// SPDX-License-Identifier: GPL-2.0-only
/****************************************************************************
 *
 * This program contains tools to manipulate the dkmgt firmware format used
 * by the TP-Link Omada switches. Much of this work is based on reverse
 * engineering the bootloader and firmware on the TP-Link ER8411v1 router.
 *
 * The firmware format consists of:
 *  | 0x00000 - 0x0103f | A header structure (struct dkmgt_fw_header).
 *  | 0x01040 - 0x1103f | 64kB upgrade partition table in JSON format.
 *  | 0x11040 - EOF     | Upgrade partition data to be written to flash.
 *
 *  Copyright (C) 2025 Naomi Kirby <dev at manawolf.ca>
 *
 ***************************************************************************/

#include <byteswap.h>
#include <ctype.h>
#include <cjson/cJSON.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "dkmgt-fwutil.h"
#include "md5.h"

#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_be32(x)	(x)
#define be32_to_cpu(x)	(x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_be32(x)	bswap_32(x)
#define be32_to_cpu(x)	bswap_32(x)
#else
#error "Unsupported endianness"
#endif

static void* map_file(const char* filename, size_t *length) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open file: %s", strerror(errno));
        return MAP_FAILED;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "Failed to get file status: %s", strerror(errno));
        close(fd);
        return MAP_FAILED;
    }
    void* firmware = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (firmware == MAP_FAILED) {
        fprintf(stderr, "Failed to map file: %s", strerror(errno));
        close(fd);
        return MAP_FAILED;
    }
    if (length) {
        *length = st.st_size;
    }
    close(fd);
    return firmware;
}

#define HEX_ENCODE_SIZE(len) ((len * 2) + 1)

static char* hexencode(const uint8_t *data, size_t len, char* hexbuf) {
    for (int i = 0; i < len; i++) {
        sprintf(&hexbuf[i*2], "%02x", data[i]);
    }
    return hexbuf;
}

#define B64_ENCODE_SIZE(len) (((len + 2) / 3) * 4 + 1)

static char* b64encode(const uint8_t* data, size_t len, char* b64buf) {
    const char dict[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char pad = '=';

    b64buf[0] = '\0';
    for (int i = 0; i < len; i += 3) {
        uint32_t val = data[i] << 16;
        int remainder = len - (i + 3);
        if (remainder >= -1) {
            val += data[i+1] << 8;
        }
        if (remainder >= 0) {
            val += data[i+2];
        }

        char tmp[5] = {pad, pad, pad, pad, '\0'};
        tmp[0] = dict[(val >> 18) & 0x3f];
        tmp[1] = dict[(val >> 12) & 0x3f];
        if (remainder >= -1) {
            tmp[2] = dict[(val >> 6) & 0x3f];
        }
        if (remainder >= 0) {
            tmp[3] = dict[(val >> 0) & 0x3f];
        }
        strcat(b64buf, tmp);
    }
    return b64buf;
}

/****************************************************************************
  DKMGT Firmware Header
 ***************************************************************************/
static void dkmgt_fw_header_parse(const void *data, size_t length, struct dkmgt_fw_header* h) {
    memcpy(h, data, sizeof(struct dkmgt_fw_header));
    for (int i = 0; i < 6; i++) {
        h->magic[i] = be32_to_cpu(h->magic[i]);
    }
    h->version = be32_to_cpu(h->version);
    h->next_header = be32_to_cpu(h->next_header);
    h->header_len = be32_to_cpu(h->header_len);
    h->total_len = be32_to_cpu(h->total_len);
}

static void dkmgt_fw_header_dump(const struct dkmgt_fw_header* h, const char* md5status, FILE *fp) {
    fprintf(fp, "DKMGT File Header:\n");
    for (int i = 0; i < 6; i++) {
        fprintf(fp, "\tmagic%d:      0x%08x\n", i, h->magic[i]);
    }
    fprintf(fp, "\tversion:     %d\n", h->version);
    fprintf(fp, "\tnext_header: 0x%08x\n", h->next_header);
    fprintf(fp, "\theader_len:  0x%08x (%d)\n", h->header_len, h->header_len);
    fprintf(fp, "\ttotal_len:   0x%08x (%d)\n", h->total_len, h->total_len);

    char hexbuf[HEX_ENCODE_SIZE(sizeof(h->md5hash))];
    fprintf(fp, "\tmd5hash:     %s (%s)\n", hexencode(h->md5hash, sizeof(h->md5hash), hexbuf), md5status);
    fprintf(fp, "\n");
}

static void dkmgt_fw_signature_dump(const struct dkmgt_fw_header* h, FILE* fp) {
    // Do nothing if the signature is all zeros.
    uint8_t zerocheck = 0;
    for (int i = 0; i < sizeof(h->signature); i++) {
        zerocheck |= h->signature[i];
    }
    if (zerocheck == 0) {
        return;
    }

    // Base64 encode the signature.
    char b64enc[B64_ENCODE_SIZE(sizeof(h->signature))];
    b64encode(h->signature, sizeof(h->signature), b64enc);

    fprintf(fp, "Firmware Signature:\n");
    for (int i = 0; i < strlen(b64enc); i += 64) {
        fprintf(fp, "\t%.64s\n", b64enc + i);
    }
    fprintf(fp, "\n");
}

/****************************************************************************
  DKMGT Partition Table
 ***************************************************************************/
static int dkmgt_ptn_table_parse(struct dkmgt_ptn_table *ptable, char *block, const uint8_t *disk, size_t length) {
    cJSON *root = cJSON_Parse(block);
    if (!root || !cJSON_IsObject(root)) {
        fprintf(stderr, "partition table JSON malformed\n");
        return -1;
    }
    cJSON* list = cJSON_GetObjectItem(root, "up-ptn-table");
    if (!list || !cJSON_IsArray(list)) {
        fprintf(stderr, "partition table JSON malformed\n");
        return -1;
    }

    memset(ptable, 0, sizeof(struct dkmgt_ptn_table));
    for (int i = 0; i < cJSON_GetArraySize(list); i++) {
        cJSON* item = cJSON_GetArrayItem(list, i);
        if (!cJSON_IsObject(item)) {
            continue;
        }

        if (ptable->count >= DKMGT_MAX_PARTITIONS) {
            fprintf(stderr, "partition table overflow\n");
            continue;
        }
        struct dkmgt_ptn_entry* entry = &ptable->partitions[ptable->count];

        cJSON* name = cJSON_GetObjectItem(item, "name");
        if (!cJSON_IsString(name)) {
            continue;
        }
        strncpy(entry->name, cJSON_GetStringValue(name), sizeof(entry->name));

        cJSON* base = cJSON_GetObjectItem(item, "base");
        if (!cJSON_IsString(base)) {
            continue;
        }
        entry->base = strtoul(cJSON_GetStringValue(base), NULL, 0);

        cJSON* size = cJSON_GetObjectItem(item, "size");
        if (!cJSON_IsString(size)) {
            continue;
        }

        // Allocate a copy of the partition data.
        entry->size = strtoul(cJSON_GetStringValue(size), NULL, 0);
        if ((entry->base > length) || (entry->base + entry->size) > length) {
            fprintf(stderr, "partition '%s' overflows\n", entry->name);
            continue;
        }
        entry->data = malloc(entry->size);
        if (!entry->data) {
            fprintf(stderr, "allocation '%s' failed: %d\n", entry->name, entry->size);
            continue;
        }
        entry->memtype = DKMGT_PTN_MEM_HEAP;
        memcpy(entry->data, disk + entry->base, entry->size);
        ptable->count++;
    }

    return 0;
}

static int dkmgt_ptn_table_encode(struct dkmgt_ptn_table *ptable, char *output, size_t bufsize) {
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        goto err;
    }
    cJSON* jstable = cJSON_AddArrayToObject(root, "up-ptn-table");
    if (!jstable) {
        goto err;
    }

    for (int i = 0; i < ptable->count; i++) {
        char intbuffer[16];
        struct dkmgt_ptn_entry *entry = &ptable->partitions[i];
        cJSON* jsentry = cJSON_CreateObject();
        if (!jsentry) {
            goto err;
        }
        if (!cJSON_AddItemToArray(jstable, jsentry)) {
            cJSON_free(jsentry);
            goto err;
        }
        if (!cJSON_AddStringToObject(jsentry, "name", entry->name)) {
            goto err;
        }

        snprintf(intbuffer, sizeof(intbuffer), "0x%08x", entry->base);
        if (!cJSON_AddStringToObject(jsentry, "base", intbuffer)) {
            goto err;
        }

        snprintf(intbuffer, sizeof(intbuffer), "0x%08x", entry->size);
        if (!cJSON_AddStringToObject(jsentry, "size", intbuffer)) {
            goto err;
        }
    }

    if (cJSON_PrintPreallocated(root, output, bufsize, 0)) {
        cJSON_free(root);
        return strlen(output);
    } else {
        fprintf(stderr, "json encoding failed\n");
        cJSON_free(root);
        return -1;
    }

err:
    fprintf(stderr, "json allocation failed\n");
    if (root) {
        cJSON_free(root);
    }
    return -1;
}

static void dkmgt_ptn_table_free(struct dkmgt_ptn_table *ptable) {
    for (int i = 0; i < ptable->count; i++) {
        struct dkmgt_ptn_entry *entry = &ptable->partitions[i];
        if (entry->memtype == DKMGT_PTN_MEM_HEAP) {
            free((void*)entry->data);
        } else if (entry->memtype == DKMGT_PTN_MEM_MMAP) {
            munmap((void*)entry->data, entry->size);
        }
    }
}

static void dkmgt_ptn_table_dump(const struct dkmgt_ptn_table* ptable, FILE *fp) {
    fprintf(fp, "Upgrade Partition Table:\n");
    fprintf(fp, "\t%10s  %10s  %10s  %s\n", "BASE", "END", "SIZE", "NAME");
    for (int i = 0; i < ptable->count; i++) {
        const struct dkmgt_ptn_entry* entry = &ptable->partitions[i];
        fprintf(fp, "\t0x%08x  0x%08x  %10d  %s\n", entry->base, entry->base + entry->size - 1, entry->size, entry->name);
    }
    fprintf(fp, "\n");
}

const void* dkmgt_ptn_parse(const struct dkmgt_ptn_entry *entry, struct dkmgt_ptn_header *hdr) {
    if (entry->size < sizeof(struct dkmgt_ptn_header)) {
        fprintf(stderr, "Partition \'%s\' header truncated\n", entry->name);
        return NULL;
    }

    memcpy(hdr, entry->data, sizeof(struct dkmgt_ptn_header));
    hdr->magic[0] = be32_to_cpu(hdr->magic[0]);
    hdr->magic[1] = be32_to_cpu(hdr->magic[1]);
    hdr->length = be32_to_cpu(hdr->length);
    hdr->checksum = be32_to_cpu(hdr->checksum);
    if ((hdr->magic[0] != DKMGT_PTN_MAGIC_0) || (hdr->magic[1] != DKMGT_PTN_MAGIC_1) ||
        (hdr->length > (entry->size - sizeof(struct dkmgt_ptn_header)))) {
        fprintf(stderr, "Partition \'%s\' has invalid header\n", entry->name);
        return NULL;
    }

    return entry->data + sizeof(struct dkmgt_ptn_header);
}

const void* dkmgt_ptn_lookup(const struct dkmgt_ptn_table* ptable, const char* name, struct dkmgt_ptn_header *hdr) {
    for (int i = 0; i < ptable->count; i++) {
        const struct dkmgt_ptn_entry* entry = &ptable->partitions[i];
        if (strncmp(name, entry->name, sizeof(entry->name)) != 0) {
            continue;
        }
        return dkmgt_ptn_parse(entry, hdr);
    }
    return NULL;
}

static int dkmgt_ptn_table_delete(struct dkmgt_ptn_table* ptable, const char* name) {
    for (int i = 0; i < ptable->count; i++) {
        struct dkmgt_ptn_entry* entry = &ptable->partitions[i];
        if (strcmp(entry->name, name) != 0) {
            continue;
        }
        if (entry->memtype == DKMGT_PTN_MEM_HEAP) {
            free(entry->data);
        } else if (entry->memtype == DKMGT_PTN_MEM_MMAP) {
            munmap(entry->data, entry->size);
        }
        memmove(entry, entry+1, sizeof(struct dkmgt_ptn_entry) * (ptable->count - i - 1));
        memset(&ptable->partitions[ptable->count-1], 0, sizeof(struct dkmgt_ptn_entry));
        ptable->count--;
        return 0;
    }

    fprintf(stderr, "partition \'%s\' not found\n", name);
    return -1;
}

static int dkmgt_ptn_table_update(struct dkmgt_ptn_table* ptable, const char* name, const char* filename) {
    struct stat st;
    if (stat(filename, &st) != 0) {
        fprintf(stderr, "Failed to read %s: %s\n", filename, strerror(errno));
        return -1;
    }

    // The updated partition data.
    size_t ptnsize;
    uint8_t *ptndata = NULL;
    uint32_t memtype = DKMGT_PTN_MEM_NONE;

    char* suffix = strrchr(filename, '.');
    if (suffix && strcmp(suffix, ".json") == 0) {
        // If this is a JSON file, wrap it with a partition header.
        ptnsize = st.st_size + sizeof(struct dkmgt_ptn_header);
        ptndata = malloc(ptnsize);
        if (!ptndata) {
            fprintf(stderr, "Failed to allocate %zu bytes\n", st.st_size + sizeof(struct dkmgt_ptn_header));
            return -1;
        }
        memtype = DKMGT_PTN_MEM_HEAP;

        struct dkmgt_ptn_header *hdr = (struct dkmgt_ptn_header *)ptndata;
        hdr->magic[0] = cpu_to_be32(DKMGT_PTN_MAGIC_0);
        hdr->magic[1] = cpu_to_be32(DKMGT_PTN_MAGIC_1);
        hdr->length = cpu_to_be32(st.st_size);
        hdr->checksum = 0;

        FILE* rfp = fopen(filename, "rb");
        if (rfp == NULL) {
            fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
            goto err;
        }
        if (fread(ptndata + sizeof(struct dkmgt_ptn_header), st.st_size, 1, rfp) <= 0) {
            fprintf(stderr, "Failed to read %s: %s\n", filename, strerror(errno));
            fclose(rfp);
            goto err;
        }
        fclose(rfp);
    } else {
        // Otherwise, append the raw file contents without a header.
        size_t length;
        ptndata = map_file(filename, &length);
        if (!ptndata) {
            fprintf(stderr, "Failed to map %s: %s\n", filename, strerror(errno));
            return -1;
        }
        ptnsize = length;
        memtype = DKMGT_PTN_MEM_MMAP;
    }

    // Check for an existing partition with the same name.
    for (int i = 0; i < ptable->count; i++) {
        struct dkmgt_ptn_entry* entry = &ptable->partitions[i];
        if (strcmp(ptable->partitions[i].name, name) != 0) {
            continue;
        }
        if (entry->memtype == DKMGT_PTN_MEM_HEAP) {
            free(entry->data);
        } else if (entry->memtype == DKMGT_PTN_MEM_MMAP) {
            munmap(entry->data, entry->size);
        }
        entry->data = ptndata;
        entry->size = ptnsize;
        entry->base = UINT32_MAX;
        entry->memtype = memtype;
        return 0;
    }

    // Otherwise, we will need to add a new partition.
    if (ptable->count < DKMGT_MAX_PARTITIONS) {
        struct dkmgt_ptn_entry* entry = &ptable->partitions[ptable->count];

        // Fill in the partition information.
        memset(entry, 0, sizeof(struct dkmgt_ptn_entry));
        strncpy(entry->name, name, sizeof(entry->name));
        entry->name[sizeof(entry->name)-1] = '\0';
        entry->data = ptndata;
        entry->size = ptnsize;
        entry->base = UINT32_MAX;
        entry->memtype = memtype;
        ptable->count++;
        return 0;
    }
    fprintf(stderr, "Partition table overflow: too many files\n");

err:
    if (memtype == DKMGT_PTN_MEM_HEAP) {
        free(ptndata);
    } else if (memtype == DKMGT_PTN_MEM_MMAP) {
        munmap(ptndata, ptnsize);
    }
    return -1;
}

/****************************************************************************
  DKMGT Firmware Information
 ***************************************************************************/
static int dkmgt_fw_info_parse(const struct dkmgt_ptn_table* ptable, struct dkmgt_fw_info *fwinfo) {
    struct dkmgt_ptn_header hdr;
    const char* data = dkmgt_ptn_lookup(ptable, "firmware-info", &hdr);
    if (!data) {
        data = dkmgt_ptn_lookup(ptable, "firmware-info.b", &hdr);
        if (!data) {
            return -1;
        }
    }
    cJSON *root = cJSON_ParseWithLength(data, hdr.length);
    if (!root) {
        fprintf(stderr, "Firmware info JSON malformed\n");
        return -1;
    }

    memset(fwinfo, 0, sizeof(struct dkmgt_fw_info));
    do {
        if (!cJSON_IsObject(root)) {
            break;
        }
        cJSON* swver = cJSON_GetObjectItem(root, "software-version");
        cJSON* fwid = cJSON_GetObjectItem(root, "firmware-id");
        if (!swver || !cJSON_IsString(swver) || !fwid || !cJSON_IsString(fwid)) {
            break;
        }
        strncpy(fwinfo->firmware_id, cJSON_GetStringValue(fwid), sizeof(fwinfo->firmware_id));

        // Parse the software version number.
        char* version = cJSON_GetStringValue(swver);
        char* end;
        fwinfo->ver_major = strtoul(version, &end, 10);
        if (*end != '.') {
            break;
        }
        version = end+1;
        fwinfo->ver_minor = strtoul(version, &end, 10);
        if (*end != '.') {
            break;
        }
        version = end+1;
        fwinfo->ver_patch = strtoul(version, &end, 10);
        if (!isspace(*end)) {
            break;
        }
        version = end+1;

        // Parse the build numver.
        while (isspace(*version) || !isdigit(*version)) version++;
        fwinfo->timestamp = strtoul(version, &end, 10);
        if (!isspace(*end)) {
            break;
        }
        version = strchr(end, '.');

        // Parse the release number.
        if (version) {
            fwinfo->release = strtoul(version+1, &end, 10);
        }
        cJSON_free(root);
        return 0;
    } while(0);

    fprintf(stderr, "Firmware info JSON malformed\n");
    cJSON_free(root);
    return -1;
}

static int dkmgt_fw_info_update(struct dkmgt_ptn_table* ptable, const struct dkmgt_fw_info *info) {
    // Encode the firmware info to JSON.
    size_t bufsize = 256;
    size_t offset = sizeof(struct dkmgt_ptn_header);
    char* buffer = malloc(bufsize);
    int len = snprintf(buffer + offset, bufsize - offset,
            "{\"software-version\": \"%u.%u.%u Build %u Rel.%u\", \"firmware-id\": \"%s\"}\n",
            info->ver_major, info->ver_minor, info->ver_patch,
            info->timestamp, info->release, info->firmware_id);

    // Build the partition header.
    struct dkmgt_ptn_header* h = (struct dkmgt_ptn_header*)buffer;
    h->magic[0] = cpu_to_be32(DKMGT_PTN_MAGIC_0);
    h->magic[1] = cpu_to_be32(DKMGT_PTN_MAGIC_1);
    h->length = cpu_to_be32(len);
    h->checksum = 0;

    // Update the partition table.
    for (int i = 0; i < ptable->count; i++) {
        struct dkmgt_ptn_entry* entry = &ptable->partitions[i];
        if ((strcmp(entry->name, "firmware-info") != 0) &&
            (strcmp(entry->name, "firmware-info.b") != 0)) {
            continue;
        }
        if (entry->memtype == DKMGT_PTN_MEM_HEAP) {
            free(entry->data);
        } else if (entry->memtype == DKMGT_PTN_MEM_MMAP) {
            munmap(entry->data, entry->size);
        }
        entry->data = buffer;
        entry->size = len + offset;
        entry->base = UINT32_MAX;
        entry->memtype = DKMGT_PTN_MEM_HEAP;
        return 0;
    }

    // Add a new partition
    if (ptable->count < DKMGT_MAX_PARTITIONS) {
        struct dkmgt_ptn_entry* entry = &ptable->partitions[ptable->count];
        strcpy(entry->name, "firmware-info");
        entry->data = buffer;
        entry->size = len + offset;
        entry->base = UINT32_MAX;
        entry->memtype = DKMGT_PTN_MEM_HEAP;
        ptable->count++;
        return 0;
    }

    fprintf(stderr, "Partition table overflow\n");
    free(buffer);
    return -1;
}

void dkmgt_fw_info_dump(const struct dkmgt_fw_info *fwinfo, FILE *fp) {
    fprintf(fp, "Firmware Info:\n");
    fprintf(fp, "\tversion:   %d.%d.%d\n", fwinfo->ver_major, fwinfo->ver_minor, fwinfo->ver_patch);
    fprintf(fp, "\ttimestamp: %u\n", fwinfo->timestamp);
    fprintf(fp, "\trelease:   %u\n", fwinfo->release);
    fprintf(fp, "\tid:        %s\n", fwinfo->firmware_id);
    fprintf(fp, "\n");
}

/****************************************************************************
  DKMGT Firmware Support List
 ***************************************************************************/
int dkmgt_support_list_parse(const struct dkmgt_ptn_table* ptable, struct dkmgt_support_list *support) {
    struct dkmgt_ptn_header hdr;
    const char* data = dkmgt_ptn_lookup(ptable, "support-list", &hdr);
    if (!data) {
        return -1;
    }

    cJSON *root = cJSON_ParseWithLength(data, hdr.length);
    if (!root) {
        fprintf(stderr, "Support list JSON malformed\n");
        return -1;
    }
    if (!root || !cJSON_IsObject(root)) {
        goto err;
    }
    cJSON* list = cJSON_GetObjectItem(root, "support-list");
    if (!list || !cJSON_IsArray(list)) {
        goto err;
    }

    memset(support, 0, sizeof(struct dkmgt_support_list));
    for (int i = 0; i < cJSON_GetArraySize(list); i++) {
        cJSON* item = cJSON_GetArrayItem(list, i);
        if (!cJSON_IsObject(item)) {
            continue;
        }

        struct dkmgt_support_entry* entry = &support->list[i];
        if (support->count >= DKMGT_MAX_SUPPORT_ENTRIES) {
            fprintf(stderr, "support list overflow\n");
            break;
        }

        cJSON* m_name = cJSON_GetObjectItem(item, "model_name");
        if (!cJSON_IsString(m_name)) {
            continue;
        }
        strncpy(entry->model_name, cJSON_GetStringValue(m_name), sizeof(entry->model_name));

        cJSON* m_version = cJSON_GetObjectItem(item, "model_version");
        if (!cJSON_IsString(m_version)) {
            continue;
        }
        strncpy(entry->model_version, cJSON_GetStringValue(m_version), sizeof(entry->model_version));

        cJSON* id = cJSON_GetObjectItem(item, "special_id");
        if (!cJSON_IsString(id)) {
            continue;
        }
        strncpy(entry->special_id, cJSON_GetStringValue(id), sizeof(entry->special_id));

        cJSON* f_version = cJSON_GetObjectItem(item, "flash_version");
        if (!cJSON_IsString(f_version)) {
            continue;
        }
        strncpy(entry->flash_version, cJSON_GetStringValue(f_version), sizeof(entry->flash_version));

        support->count++;
    }
    cJSON_free(root);
    return 0;

err:
    cJSON_free(root);
    return -1;
}

void dkmgt_support_list_dump(const struct dkmgt_support_list *support, FILE *fp) {
    fprintf(fp, "Supported Devices:\n");
    fprintf(fp, "\t%-24s  %8s  %8s  %s\n", "MODEL", "VERSION", "SPECIAL", "FLASH");
    for (int i = 0; i < support->count; i++) {
        const struct dkmgt_support_entry* entry = &support->list[i];
        fprintf(fp, "\t%-24s  %8s  %8s  %s\n", entry->model_name, entry->model_version, entry->special_id, entry->flash_version);
    }
    fprintf(fp, "\n");
}

/****************************************************************************
  DKMGT Firmware Top Level Parsing
 ***************************************************************************/
struct dkmgt_firmware {
    struct dkmgt_fw_header header;
    struct dkmgt_ptn_table ptable;
    struct dkmgt_fw_info info;
    const char* md5check;

    char ptable_block[DKMGT_PTN_BLOCK_SIZE];
};

struct dkmgt_firmware* dkmgt_firmware_new() {
    struct dkmgt_firmware* fw = calloc(sizeof(struct dkmgt_firmware), 1);
    if (!fw) {
        return NULL;
    }

    fw->header.magic[0] = DKMGT_MAGIC_0;
    fw->header.magic[1] = DKMGT_MAGIC_1;
    fw->header.magic[2] = DKMGT_MAGIC_2;
    fw->header.magic[3] = DKMGT_MAGIC_3;
    fw->header.magic[4] = DKMGT_MAGIC_4;
    fw->header.magic[5] = DKMGT_MAGIC_5;
    fw->header.version = 1;
    fw->header.header_len = sizeof(struct dkmgt_fw_header);
    fw->header.total_len = sizeof(struct dkmgt_fw_header) + DKMGT_PTN_BLOCK_SIZE;

    // Fill out the firmware information with some defaults.
    time_t now = time(0);
    struct tm utc;
    if (gmtime_r(&now, &utc)) {
        fw->info.timestamp = (utc.tm_year + 1900) * 10000;
        fw->info.timestamp += (utc.tm_mon * 100) + utc.tm_mday;
    }
    strncpy(fw->info.firmware_id, "UNKNOWN", sizeof(fw->info.firmware_id));

    return fw;
}

void dkmgt_firmware_free(struct dkmgt_firmware *fw) {
    dkmgt_ptn_table_free(&fw->ptable);
    free(fw);
}

struct dkmgt_firmware* dkmgt_firmware_parse(const void* data, size_t length) {
    if (length < sizeof(struct dkmgt_fw_header)) {
        fprintf(stderr, "Firmware header truncated\n");
        return NULL;
    }

    struct dkmgt_firmware* fw = calloc(sizeof(struct dkmgt_firmware), 1);
    dkmgt_fw_header_parse(data, length, &fw->header);
    if (length < fw->header.total_len) {
        fw->md5check = "truncated";
        fprintf(stderr, "Firmware contents truncated\n");
        dkmgt_firmware_free(fw);
        return NULL;
    } else {
        uint8_t digest[sizeof(fw->header.md5hash)];
        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx, data + fw->header.header_len, fw->header.total_len - fw->header.header_len);
        MD5_Final(digest, &ctx);
        fw->md5check = memcmp(digest, fw->header.md5hash, sizeof(digest)) ? "fail" : "okay";
    }

    // Read the upgrade partiton table and the upgrade data block.
    if (fw->header.header_len + DKMGT_PTN_BLOCK_SIZE > length) {
        fprintf(stderr, "Partition table truncated\n");
        dkmgt_firmware_free(fw);
        return NULL;
    }
    memcpy(fw->ptable_block, data + fw->header.header_len, DKMGT_PTN_BLOCK_SIZE);

    size_t disk_size = fw->header.total_len - fw->header.header_len + DKMGT_PTN_BLOCK_SIZE;
    const void* disk = data + fw->header.header_len + DKMGT_PTN_BLOCK_SIZE;
    dkmgt_ptn_table_parse(&fw->ptable, fw->ptable_block, disk, disk_size);

    if (dkmgt_fw_info_parse(&fw->ptable, &fw->info) < 0) {
        memset(&fw->info, 0, sizeof(fw->info));
    }

    return fw;
}

int dkmgt_firmware_finalize(struct dkmgt_firmware *fw) {
    // Update the firmware information partition.
    dkmgt_fw_info_update(&fw->ptable, &fw->info);

    // Recompute the partition table base addresses.
    size_t base = 0;
    for (int i = 0; i < fw->ptable.count; i++) {
        struct dkmgt_ptn_entry* entry = &fw->ptable.partitions[i];
        entry->base = base;
        base += entry->size;
    }

    // Encode the partition table into memory.
    int err = dkmgt_ptn_table_encode(&fw->ptable, fw->ptable_block, sizeof(fw->ptable_block));
    if (err < 0) {
        return err;
    }

    // Calculate the file size and checksum.
    fw->header.total_len = sizeof(struct dkmgt_fw_header) + sizeof(fw->ptable_block);
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, fw->ptable_block, sizeof(fw->ptable_block));
    for (int i = 0; i < fw->ptable.count; i++) {
        struct dkmgt_ptn_entry* entry = &fw->ptable.partitions[i];
        MD5_Update(&ctx, entry->data, entry->size);
        fw->header.total_len += entry->size;
    }
    MD5_Final(fw->header.md5hash, &ctx);
    fw->md5check = "okay";

    return 0;
}

int dkmgt_firmware_write(struct dkmgt_firmware *fw, FILE* fp) {
    // Write the file header in big-endian
    struct dkmgt_fw_header hdr;
    memcpy(&hdr, &fw->header, sizeof(struct dkmgt_fw_header));
    for (int i = 0; i < 6; i++) {
        hdr.magic[i] = cpu_to_be32(hdr.magic[i]);
    }
    hdr.version = cpu_to_be32(hdr.version);
    hdr.next_header = cpu_to_be32(hdr.next_header);
    hdr.header_len = cpu_to_be32(hdr.header_len);
    hdr.total_len = cpu_to_be32(hdr.total_len);
    hdr.unknown[0] = cpu_to_be32(hdr.unknown[0]);
    hdr.unknown[1] = cpu_to_be32(hdr.unknown[1]);
    if (fwrite(&hdr, sizeof(hdr), 1, fp) < 1) {
        fprintf(stderr, "Failed to write header: %s", strerror(errno));
        return -1;
    }

    // Write the partition table block.
    if (fwrite(fw->ptable_block, sizeof(fw->ptable_block), 1, fp) < 1) {
        fprintf(stderr, "Failed to write partition table: %s", strerror(errno));
        return -1;
    }

    // Write the partitions
    for (int i = 0; i < fw->ptable.count; i++) {
        struct dkmgt_ptn_entry* entry = &fw->ptable.partitions[i];
        if (fwrite(entry->data, entry->size, 1, fp) < 1) {
            fprintf(stderr, "Failed to write partition %s: %s", entry->name, strerror(errno));
            return -1;
        }
    }
    return 0;
}

void dkmgt_firmware_dump(const struct dkmgt_firmware *fw, FILE *fp) {
    dkmgt_fw_header_dump(&fw->header, fw->md5check, fp);
    dkmgt_fw_signature_dump(&fw->header, fp);
    dkmgt_ptn_table_dump(&fw->ptable, fp);
    dkmgt_fw_info_dump(&fw->info, fp);

    // Parse and display the support list.
    struct dkmgt_support_list support;
    if (dkmgt_support_list_parse(&fw->ptable, &support) >= 0) {
        dkmgt_support_list_dump(&support, fp);
    }
}

/****************************************************************************
  DKMGT Firwmware Util Program
 ***************************************************************************/
static void print_usage(int argc, char** argv, FILE* fp) {
    fprintf(fp, "Usage: %s [options] FIRMWARE\n", argv[0]);

    fprintf(fp, "\nOptions:\n");
    fprintf(fp, "  --print, -p          Print firmware headers\n");
    fprintf(fp, "  --extract, -x        Extract firmware contents\n");
    fprintf(fp, "  --create, -c         Create a new firmware file\n");
    fprintf(fp, "  --output, -o FILE    Write output to FILE (default: FIRMWARE)\n");
    fprintf(fp, "  --help, -h           Print this message and exit\n");

    fprintf(fp, "\nVersion options:\n");
    fprintf(fp, "  --swver, -V VERSION  Set the firmware-info software version to VERSION\n");
    fprintf(fp, "  --fwid, -I INFO      Set the firmware-info firmware-id string to INFO\n");
    fprintf(fp, "  --release, -R REV    Set the firmware-info release to REV\n");

    fprintf(fp, "\nPartition options:\n");
    fprintf(fp, "  --append, -a [NAME=]FILE  Create a partion from FILE\n");
    fprintf(fp, "  --delete, -d NAME         Delete the NAME partiton\n");
    fprintf(fp, "  --kernel, -k FILE         Create a 'kernel' partition from FILE\n");
    fprintf(fp, "  --rootfs, -r FILE         Create a 'rootfs' partition from FILE\n");

}

static char* gen_shortopts(const struct option* opts) {
    // Count the number of long options.
    int count = 0;
    while (opts[count].name) {
        count++;
    }
    char* buffer = malloc(count * 2);
    char* ptr = buffer;
    for (int i = 0; i < count; i++) {
        if (!isalpha(opts[i].val)) {
            continue;
        }
        *(ptr++) = opts[i].val;
        if (opts[i].has_arg) {
            *(ptr++) = ':';
        }
    }
    *ptr = '\0';
    return buffer;
}

// When extracting partition contents, try to guess the file extension
// by peeking at the partition contents. 
static const char* guess_ptn_file_ext(const void* data, size_t length) {
    uint32_t magic = be32_to_cpu(*(const uint32_t*)data);
    if ((magic & 0xffffff00) == 0x1f8b0800) {
        // Looks and smells like gzip.
        return ".gz";
    }

    switch (magic) {
        case 0x73717368:
        case 0x68737173:
            return ".squashfs";

        case 0xd00dfeed:{
            // Flattened device tree - but we should check if a kernel image follows.
            uint32_t fdtlen = be32_to_cpu(*(const uint32_t*)(data + 4));
            if (fdtlen >= length) {
                return ".dtb";
            }
            // There's more data here a kernel image probably follows
            return ".bin";
        }

        default:
            // If all else fails, just call it a binary file.
            return ".bin";
    }
}

int do_print(struct dkmgt_firmware* fw, const char* filename) {
    dkmgt_firmware_dump(fw, stdout);
    return EXIT_SUCCESS;
}

int do_extract(struct dkmgt_firmware* fw, const char* filename) {
    char* dirname = NULL;

    dkmgt_firmware_dump(fw, stdout);

    // Create a directory for the firmware contents.
    const char* dirsep = strrchr(filename, '/');
    dirname = strdup((dirsep) ? dirsep+1 : filename);
    char* ext = strrchr(dirname, '.');
    if (ext && strcmp(ext, ".bin") == 0) {
        *ext = '\0';
    }
    size_t dirlen = strlen(dirname);
    if (mkdir(dirname, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0) {
        if (errno != EEXIST) {
            fprintf(stderr, "Failed to create output dir: %s\n", strerror(errno));
            goto err;
        }
    }

    // Extract the firmware contents
    for (int i = 0; i < fw->ptable.count; i++) {
        struct dkmgt_ptn_entry *entry = &fw->ptable.partitions[i];

        // Use the partition name for the filename.
        char partfile[dirlen + sizeof(entry->name) + 16];
        snprintf(partfile, sizeof(partfile), "%s/%s", dirname, entry->name);

        // Strip off the ".b" suffix, if present.
        size_t len = strlen(partfile);
        if ((len > 2) && (partfile[len-1] == 'b') && (partfile[len-2] == '.')) {
            partfile[len-2] = '\0';
        }

        // If a valid partition header exists - parse it as JSON.
        struct dkmgt_ptn_header header;
        const void* data = dkmgt_ptn_parse(entry, &header);
        if (data) {
            strcat(partfile, ".json");
        }
        else {
            header.length = entry->size;
            data = entry->data;
            strcat(partfile, guess_ptn_file_ext(entry->data, header.length));
        }

        // Write the file to disk.
        FILE* wfp = fopen(partfile, "w+b");
        if (!wfp) {
            fprintf(stderr, "Unable to create %s: %s\n", partfile, strerror(errno));
            continue;
        }
        if (fwrite(data, header.length, 1, wfp) <= 0) {
            fprintf(stderr, "Unable to create %s: %s\n", partfile, strerror(errno));
        }
        fclose(wfp);
    }
    return EXIT_SUCCESS;

err:
    if (dirname) {
        free(dirname);
    }
    return EXIT_FAILURE;
}

int do_write(struct dkmgt_firmware *fw, const char* filename) {
    dkmgt_firmware_finalize(fw);
    dkmgt_firmware_dump(fw, stderr);

    // If no output file is specified, write it back
    if (strcmp(filename, "-") == 0) {
        return (dkmgt_firmware_write(fw, stdout) < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    FILE* fp = fopen(filename, "w+b");
    if (!fp) {
        fprintf(stderr, "failed to open '%s' for writing: %s\n", filename, strerror(errno));
        return EXIT_FAILURE;
    }

    int ret = dkmgt_firmware_write(fw, fp);
    fclose(fp);
    return (ret < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}

int do_update(struct dkmgt_firmware *fw, const char* partname, const char* filename) {
    // Delete the partition if no file contents were specified.
    if (!filename) {
        return dkmgt_ptn_table_delete(&fw->ptable, partname);
    }

    // If no partition name was specified, guess it from the filename.
    char autopartname[32];
    if (!partname) {
        char* dirsep = strrchr(filename, '/');
        if (dirsep) {
            strncpy(autopartname, dirsep+1, sizeof(autopartname));
        } else {
            strncpy(autopartname, filename, sizeof(autopartname));
        }
        char* ext = memchr(autopartname, '.', sizeof(autopartname));
        if (ext) {
            *ext = '\0';
        } else {
            autopartname[sizeof(autopartname)-1] = '\0';
        }
        partname = autopartname;
    }

    return dkmgt_ptn_table_update(&fw->ptable, partname, filename);
}

struct ptn_update_action {
    const char* partname;
    const char* filename;
};

int main(int argc, char** argv) {
    const struct option longopts[] = {
        {"print",    no_argument,       NULL, 'p'},
        {"extract",  no_argument,       NULL, 'x'},
        {"create",   no_argument,       NULL, 'c'},
        {"append",   required_argument, NULL, 'a'},
        {"delete",   required_argument, NULL, 'd'},
        {"kernel",   required_argument, NULL, 'k'},
        {"rootfs",   required_argument, NULL, 'r'},
        {"swver",    required_argument, NULL, 'V'},
        {"fwid",     required_argument, NULL, 'I'},
        {"release",  required_argument, NULL, 'R'},
        {"output",   required_argument, NULL, 'o'},
        {"help",     no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    const char* shortopts = gen_shortopts(longopts);

    int (*action)(struct dkmgt_firmware*, const char*) = do_print;
    const char *outfile = NULL;
    bool do_create = false;

    // Updates to be made to the partition table.
    const char* update_swver = NULL;
    const char* update_fwid = NULL;
    const char* update_rev = NULL;
    int update_count = 0;
    struct ptn_update_action updates[DKMGT_MAX_PARTITIONS];

    while (true) {
        int oindex;
        int c = getopt_long(argc, argv, shortopts, longopts, &oindex);
        if (c < 0) {
            break;
        }

        switch (c) {
            case 0:
            case 'p':
                action = do_print;
                break;

            case 'x':
                action = do_extract;
                break;

            case 'c':
                action = do_write;
                do_create = true;
                break;

            case 'a': {
                if (update_count >= DKMGT_MAX_PARTITIONS) {
                    fprintf(stderr, "Too many partition changes");
                    return EXIT_FAILURE;
                }
                char* eq = strchr(optarg, '=');
                if (eq) {
                    *eq = '\0';
                    updates[update_count].partname = optarg;
                    updates[update_count].filename = eq+1;
                } else {
                    // TODO: Guess the partiton name.
                    updates[update_count].partname = NULL;
                    updates[update_count].filename = optarg;
                }
                update_count++;
                break;
            }

            case 'd':
                if (update_count >= DKMGT_MAX_PARTITIONS) {
                    fprintf(stderr, "Too many partition changes");
                    return EXIT_FAILURE;
                }
                updates[update_count].partname = optarg;
                updates[update_count].filename = NULL;
                update_count++;
                break;

            case 'k':
                if (update_count >= DKMGT_MAX_PARTITIONS) {
                    fprintf(stderr, "Too many partition changes");
                    return EXIT_FAILURE;
                }
                updates[update_count].partname = "kernel";
                updates[update_count].filename = optarg;
                update_count++;
                break;

            case 'r':
                if (update_count >= DKMGT_MAX_PARTITIONS) {
                    fprintf(stderr, "Too many partition changes");
                    return EXIT_FAILURE;
                }
                updates[update_count].partname = "rootfs";
                updates[update_count].filename = optarg;
                update_count++;
                break;

            case 'V':
                update_swver = optarg;
                action = do_write;
                break;
            
            case 'I':
                update_fwid = optarg;
                action = do_write;
                break;

            case 'R':
                update_rev = optarg;
                action = do_write;
                break;

            case 'o':
                outfile = optarg;
                break;

            case 'h':
                print_usage(argc, argv, stdout);
                return EXIT_SUCCESS;

            default:
                print_usage(argc, argv, stderr);
                return EXIT_FAILURE;
        }
    }
    if (update_count > 0) {
        action = do_write;
    }

    // Read the firmware, or create a new one.
    if (argc <= optind) {
        fprintf(stderr, "Missing argument: FILENAME\n");
        return EXIT_FAILURE;
    }
    const char* filename = argv[optind];
    struct dkmgt_firmware* fw;
    if (do_create) {
        fw = dkmgt_firmware_new();
    } else {
        // Map the firmware into memory and begin parsing.
        size_t fwsize;
        void* fwdata = map_file(filename, &fwsize);
        if (fwdata == MAP_FAILED) {
            fprintf(stderr, "Failed to map file %s: %s\n", filename, strerror(errno));
            return EXIT_FAILURE;
        }

        fw = dkmgt_firmware_parse(fwdata, fwsize);
    }
    if (!fw) {
        return EXIT_FAILURE;
    }

    // Apply updates to the firmware contents.
    while (update_swver) {
        char* endp;
        fw->info.ver_major = strtoul(update_swver, &endp, 10);

        if (*endp == '.') {
            fw->info.ver_minor = strtoul(endp+1, &endp, 10);
        } else {
            fw->info.ver_minor = 0;
            fw->info.ver_patch = 0;
            break;
        }

        if (*endp == '.') {
            fw->info.ver_patch = strtoul(endp+1, NULL, 10);
        } else {
            fw->info.ver_patch = 0;
        }
        break;
    }
    if (update_rev) {
        // Skip leading aphabetical chars, if any.
        const char* p = update_rev;
        while (isalpha(*p)) p++;
        fw->info.release = strtoul(p, NULL, 10);
    }
    if (update_fwid) {
        strncpy(fw->info.firmware_id, update_fwid, sizeof(fw->info.firmware_id));
        fw->info.firmware_id[sizeof(fw->info.firmware_id)-1] = '\0';
    }
    for (int i = 0; i < update_count; i++) {
        // Delete the partition if no contents were provided.
        if (do_update(fw, updates[i].partname, updates[i].filename) < 0) {
            return EXIT_FAILURE;
        }
    }

    // Write the firmware file back out.
    int ret = EXIT_SUCCESS;
    if (!outfile) {
        outfile = filename;
    }
    if (action) {
        ret = action(fw, filename);
    }
    dkmgt_firmware_free(fw);
    return (ret < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
