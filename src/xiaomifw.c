// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021 Rafał Miłecki <rafal@milecki.pl>
 */

/*
 * Standard Xiaomi firmware image consists of:
 * 1. Xiaomi header
 * 2. Blobs
 * 3. RSA signature
 *
 * Each blob section consists of:
 * 1. Header
 * 2. Content
 *
 * Signature consists of:
 * 1. Header
 * 2. Content
 */

#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(__BYTE_ORDER)
#error "Unknown byte order"
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le32(x)	bswap_32(x)
#define le32_to_cpu(x)	bswap_32(x)
#define cpu_to_be32(x)	(x)
#define be32_to_cpu(x)	(x)
#define cpu_to_le16(x)	bswap_16(x)
#define le16_to_cpu(x)	bswap_16(x)
#define cpu_to_be16(x)	(x)
#define be16_to_cpu(x)	(x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le32(x)	(x)
#define le32_to_cpu(x)	(x)
#define cpu_to_be32(x)	bswap_32(x)
#define be32_to_cpu(x)	bswap_32(x)
#define cpu_to_le16(x)	(x)
#define le16_to_cpu(x)	(x)
#define cpu_to_be16(x)	bswap_16(x)
#define be16_to_cpu(x)	bswap_16(x)
#else
#error "Unsupported endianness"
#endif

#define DEVICE_ID_MIWIFI_R1CM		0x0003
#define DEVICE_ID_MIWIFI_R2D		0x0004
#define DEVICE_ID_MIWIFI_R1CL		0x0005
#define DEVICE_ID_MIWIFI_R3		0x0007
#define DEVICE_ID_MIWIFI_R3D		0x0008
#define DEVICE_ID_MIWIFI_R3G		0x000d
#define DEVICE_ID_MIWIFI_R4CM		0x0012
#define DEVICE_ID_MIWIFI_R2100		0x0016
#define DEVICE_ID_MIWIFI_RA70		0x0025

#define BLOB_ALIGNMENT			0x4

#define BLOB_TYPE_UBOOT			0x0001
#define BLOB_TYPE_FW_UIMAGE		0x0004	/* Found in r1cl, r1cm */
#define BLOB_TYPE_FW_OS2		0x0006
#define BLOB_TYPE_FW_UIMAGE2		0x0007	/* Found in r4cm */

/* Raw data */

struct xiaomi_header {
	char magic[4];
	uint32_t signature_offset;
	uint32_t crc32;
	uint16_t unused;
	uint16_t device_id;
	uint32_t blob_offsets[8];
};

struct xiaomi_blob_header {
	uint32_t magic;
	uint32_t flash_offset;
	uint32_t size;
	uint16_t type;
	uint16_t unused;
	char name[32];
};

struct xiaomi_signature_header {
	uint32_t size;
	uint32_t padding[3];
	uint8_t content[0x100];
};

/* Parsed info */

struct xiaomifw_blob_info {
	struct xiaomi_blob_header header;
	size_t offset;
	size_t size;
};

struct xiaomifw_info {
	struct xiaomi_header header;
	size_t file_size;
	struct xiaomifw_blob_info blobs[8];
	size_t signature_offset;
	uint32_t crc32;
};

static inline size_t xiaomifw_min(size_t x, size_t y) {
	return x < y ? x : y;
}

struct device_map {
	int device_id;
	const char *device_name;
};

static const struct device_map device_names[] = {
	{ DEVICE_ID_MIWIFI_R1CM, "r1cm" },
	{ DEVICE_ID_MIWIFI_R2D, "r2d" },
	{ DEVICE_ID_MIWIFI_R1CL, "r1cl" },
	{ DEVICE_ID_MIWIFI_R3, "r3" },
	{ DEVICE_ID_MIWIFI_R3D, "r3d" },
	{ DEVICE_ID_MIWIFI_R3G, "r3g" },
	{ DEVICE_ID_MIWIFI_R4CM, "r4cm" },
	{ DEVICE_ID_MIWIFI_R2100, "r2100" },
	{ DEVICE_ID_MIWIFI_RA70, "ra70" },
};

const char *xiaomifw_device_name(int device_id) {
	int i;

	for (i = 0; i < sizeof(device_names); i++) {
		if (device_names[i].device_id == device_id) {
			return device_names[i].device_name;
		}
	}

	return "unknown";
}

const int xiaomifw_device_id(const char *device_name) {
	int i;

	for (i = 0; i < sizeof(device_names); i++) {
		if (!strcmp(device_names[i].device_name, device_name)) {
			return device_names[i].device_id;
		}
	}

	return -ENOENT;
}

/**************************************************
 * CRC32
 **************************************************/

static const uint32_t crc32_tbl[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

uint32_t xiaomifw_crc32(uint32_t crc, const void *buf, size_t len) {
	const uint8_t *in = buf;

	while (len) {
		crc = crc32_tbl[(crc ^ *in) & 0xff] ^ (crc >> 8);
		in++;
		len--;
	}

	return crc;
}

/**************************************************
 * Helpers
 **************************************************/

static FILE *xiaomifw_open(const char *pathname, const char *mode) {
	struct stat st;

	if (pathname)
		return fopen(pathname, mode);

	if (isatty(fileno(stdin))) {
		fprintf(stderr, "Reading from TTY stdin is unsupported\n");
		return NULL;
	}

	if (fstat(fileno(stdin), &st)) {
		fprintf(stderr, "Failed to fstat stdin: %d\n", -errno);
		return NULL;
	}

	if (S_ISFIFO(st.st_mode)) {
		fprintf(stderr, "Reading from pipe stdin is unsupported\n");
		return NULL;
	}

	return stdin;
}

static void xiaomifw_close(FILE *fp) {
	if (fp != stdin)
		fclose(fp);
}

/**************************************************
 * Existing firmware parser
 **************************************************/

static int xiaomifw_parse(FILE *fp, struct xiaomifw_info *info) {
	struct xiaomi_header *header = &info->header;
	struct stat st;
	uint8_t buf[1024];
	size_t length;
	size_t bytes;
	int i;
	int err = 0;

	memset(info, 0, sizeof(*info));

	/* File size */

	if (fstat(fileno(fp), &st)) {
		err = -errno;
		fprintf(stderr, "Failed to fstat: %d\n", err);
		return err;
	}
	info->file_size = st.st_size;

	/* Header */

	if (fread(header, 1, sizeof(*header), fp) != sizeof(*header)) {
		fprintf(stderr, "Failed to read Xiaomi header\n");
		return -EIO;
	}

	if (strncmp(header->magic, "HDR1", 4)) {
		fprintf(stderr, "Invalid Xiaomi header magic\n");
		return -EPROTO;
	}
	info->signature_offset = le32_to_cpu(header->signature_offset);

	/* CRC32 */

	fseek(fp, 12, SEEK_SET);

	info->crc32 = 0xffffffff;
	length = info->file_size - 12;
	while (length && (bytes = fread(buf, 1, xiaomifw_min(sizeof(buf), length), fp)) > 0) {
		info->crc32 = xiaomifw_crc32(info->crc32, buf, bytes);
		length -= bytes;
	}
	if (length) {
		fprintf(stderr, "Failed to read last %zd B of data\n", length);
		return -EIO;
	}

	if (info->crc32 != le32_to_cpu(header->crc32)) {
		fprintf(stderr, "Invalid data crc32: 0x%08x instead of 0x%08x\n", info->crc32, le32_to_cpu(header->crc32));
		return -EPROTO;
	}

	/* Blobs */

	for (i = 0; i < sizeof(info->blobs); i++) {
		size_t offset = le32_to_cpu(info->header.blob_offsets[i]);
		struct xiaomifw_blob_info *file_info = &info->blobs[i];

		if (!offset) {
			break;
		}

		fseek(fp, offset, SEEK_SET);

		if (fread(&file_info->header, 1, sizeof(file_info->header), fp) != sizeof(file_info->header)) {
			fprintf(stderr, "Failed to read file Xiaomi header\n");
			return -EIO;
		}

		file_info->offset = offset;
		file_info->size = le32_to_cpu(file_info->header.size);

		offset += sizeof(file_info->header) + file_info->size;
		offset = (offset + 4) & ~(0x4 - 1);
	}

	return 0;
}

/**************************************************
 * Info
 **************************************************/

static int xiaomifw_info(int argc, char **argv) {
	struct xiaomifw_info info;
	const char *pathname = NULL;
	uint16_t device_id;
	FILE *fp;
	int i;
	int c;
	int err = 0;

	while ((c = getopt(argc, argv, "i:")) != -1) {
		switch (c) {
		case 'i':
			pathname = optarg;
			break;
		}
	}

	fp = xiaomifw_open(pathname, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open Xiaomi firmware image\n");
		err = -EACCES;
		goto out;
	}

	err = xiaomifw_parse(fp, &info);
	if (err) {
		fprintf(stderr, "Failed to parse Xiaomi firmware image\n");
		goto err_close;
	}

	device_id = le16_to_cpu(info.header.device_id);

	printf("Device ID: 0x%04x (%s)\n", device_id, xiaomifw_device_name(device_id));
	printf("CRC32: 0x%08x\n", info.crc32);
	printf("Signature offset: 0x%08zx\n", info.signature_offset);
	for (i = 0; i < sizeof(info.blobs) && info.blobs[i].offset; i++) {
		struct xiaomifw_blob_info *file_info = &info.blobs[i];

		printf("[Blob %d] offset:0x%08zx flash_offset:0x%08x size:0x%08zx type:0x%04x name:%s\n", i, file_info->offset, file_info->header.flash_offset, file_info->size, file_info->header.type, file_info->header.name);
	}

err_close:
	xiaomifw_close(fp);
out:
	return err;
}

/**************************************************
 * Create
 **************************************************/

static ssize_t xiaomifw_create_append_zeros(FILE *fp, size_t length) {
	uint8_t *buf;

	buf = malloc(length);
	if (!buf)
		return -ENOMEM;
	memset(buf, 0, length);

	if (fwrite(buf, 1, length, fp) != length) {
		fprintf(stderr, "Failed to write %zu B of zeros\n", length);
		free(buf);
		return -EIO;
	}

	free(buf);

	return length;
}

static ssize_t xiaomifw_create_append_file(FILE *fp, char *blob) {
	struct xiaomi_blob_header header = {
		.magic = le32_to_cpu(0x0000babe),
		.flash_offset = ~0,
		.type = ~0,
	};
	struct stat st;
	char *in_path = NULL;
	ssize_t length = 0;
	char *type = NULL;
	char *resptr;
	char *tok;
	char *p;
	uint8_t buf[1024];
	size_t bytes;
	FILE *in;
	int err;
	int i = 0;

	/* sscanf and strtok can't handle optional fields (e.g. "::firmware.bin:/tmp/foo.bin") */
	resptr = blob;
	do {
		p = resptr;
		if ((tok = strchr(resptr, ':'))) {
			*tok = '\0';
			resptr = tok + 1;
		} else {
			resptr = NULL;
		}

		switch (i++) {
		case 0:
			if (*p) {
				header.flash_offset = cpu_to_le32(strtoul(p, NULL, 0));
			}
			break;
		case 1:
			type = p;
			break;
		case 2:
			strncpy(header.name, p, sizeof(header.name));
			break;
		case 3:
			in_path = p;
			break;
		}
	} while (resptr);

	if (i < 4) {
		fprintf(stderr, "Failed to parse blob info\n");
		return -EPROTO;
	}

	in = fopen(in_path, "r");
	if (!in) {
		fprintf(stderr, "Failed to open %s\n", in_path);
		return -EACCES;
	}

	if (fstat(fileno(in), &st)) {
		err = -errno;
		fprintf(stderr, "Failed to fstat: %d\n", err);
		return err;
	}
	header.size = cpu_to_le32(st.st_size);

	if (*type) {
		if (!strcmp(type, "uimage")) {
			header.type = cpu_to_le32(BLOB_TYPE_FW_UIMAGE);
		} else if (!strcmp(type, "uimage2")) {
			header.type = cpu_to_le32(BLOB_TYPE_FW_UIMAGE2);
		} else {
			fprintf(stderr, "Unsupported blob type: %s\n", type);
			return -ENOENT;
		}
	}

	bytes = fwrite(&header, 1, sizeof(header), fp);
	if (bytes != sizeof(header)) {
		fprintf(stderr, "Failed to write blob header\n");
		return -EIO;
	}
	length += bytes;

	while ((bytes = fread(buf, 1, sizeof(buf), in)) > 0) {
		if (fwrite(buf, 1, bytes, fp) != bytes) {
			fprintf(stderr, "Failed to write %zu B of blob\n", bytes);
			return -EIO;
		}
		length += bytes;
	}

	fclose(in);

	if (length & (BLOB_ALIGNMENT - 1)) {
		size_t padding = BLOB_ALIGNMENT - (length % BLOB_ALIGNMENT);

		bytes = xiaomifw_create_append_zeros(fp, padding);
		if (bytes != padding) {
			fprintf(stderr, "Failed to align blob\n");
			return -EIO;
		}
		length += bytes;
	}

	return length;
}

static ssize_t xiaomifw_create_write_signature(FILE *fp) {
	struct xiaomi_signature_header header = {
	};
	size_t bytes;

	bytes = fwrite(&header, 1, sizeof(header), fp);
	if (bytes != sizeof(header)) {
		fprintf(stderr, "Failed to write blob header\n");
		return -EIO;
	}

	return bytes;
}

static int xiaomifw_create(int argc, char **argv) {
	struct xiaomi_header header = {
		.magic = { 'H', 'D', 'R', '1' },
	};
	uint32_t crc32 = 0xffffffff;
	uint8_t buf[1024];
	int blob_idx = 0;
	ssize_t length;
	ssize_t offset;
	ssize_t bytes;
	int device_id;
	FILE *fp;
	int c;
	int err = 0;

	if (argc < 3) {
		fprintf(stderr, "No Xiaomi firmware image pathname passed\n");
		err = -EINVAL;
		goto out;
	}

	optind = 3;
	while ((c = getopt(argc, argv, "m:b:")) != -1) {
		switch (c) {
		case 'm':
			device_id = xiaomifw_device_id(optarg);
			if (device_id < 0) {
				err = device_id;
				fprintf(stderr, "Failed to find device %s\n", optarg);
				goto out;
			}
			header.device_id = device_id;
			break;
		case 'b':
			break;
		}
		if (err)
			goto out;
	}

	fp = fopen(argv[2], "w+");
	if (!fp) {
		fprintf(stderr, "Failed to open %s\n", argv[2]);
		err = -EACCES;
		goto out;
	}

	offset = sizeof(header);
	fseek(fp, offset, SEEK_SET);

	optind = 3;
	while ((c = getopt(argc, argv, "m:b:")) != -1) {
		switch (c) {
		case 'm':
			break;
		case 'b':
			if (blob_idx >= sizeof(header.blob_offsets)) {
				err = -ENOENT;
				fprintf(stderr, "Too many blobs specified\n");
				goto err_close;
			}
			bytes = xiaomifw_create_append_file(fp, optarg);
			if (bytes < 0) {
				err = bytes;
				fprintf(stderr, "Failed to append blob: %d\n", err);
				goto err_close;
			}
			header.blob_offsets[blob_idx++] = cpu_to_le32(offset);
			offset += bytes;
			break;
		}
		if (err)
			goto err_close;
	}

	bytes = xiaomifw_create_write_signature(fp);
	if (bytes < 0) {
		err = bytes;
		fprintf(stderr, "Failed to write signature: %d\n", err);
		goto err_close;
	}
	header.signature_offset = cpu_to_le32(offset);
	offset += bytes;

	crc32 = xiaomifw_crc32(crc32, (uint8_t *)&header + 12, sizeof(header) - 12);
	fseek(fp, sizeof(header), SEEK_SET);
	length = offset - sizeof(header);
	while (length && (bytes = fread(buf, 1, xiaomifw_min(sizeof(buf), length), fp)) > 0) {
		crc32 = xiaomifw_crc32(crc32, buf, bytes);
		length -= bytes;
	}
	if (length) {
		err = -EIO;
		fprintf(stderr, "Failed to calculate CRC32 over the last %zd B of data\n", length);
		goto err_close;
	}

	header.crc32 = cpu_to_le32(crc32);

	rewind(fp);

	bytes = fwrite(&header, 1, sizeof(header), fp);
	if (bytes != sizeof(header)) {
		fprintf(stderr, "Failed to write header\n");
		return -EIO;
	}

err_close:
	fclose(fp);
out:
	return err;
}

/**************************************************
 * Extract
 **************************************************/

static int xiaomifw_extract(int argc, char **argv) {
	struct xiaomifw_info info;
	const char *pathname = NULL;
	const char *name = NULL;
	uint8_t buf[1024];
	size_t offset = 0;
	size_t size = 0;
	size_t bytes;
	FILE *fp;
	int i;
	int c;
	int err = 0;

	while ((c = getopt(argc, argv, "i:n:")) != -1) {
		switch (c) {
		case 'i':
			pathname = optarg;
			break;
		case 'n':
			name = optarg;
			break;
		}
	}

	if (!name) {
		err = -EINVAL;
		fprintf(stderr, "No data to extract specified\n");
		goto err_out;
	}

	fp = xiaomifw_open(pathname, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open Xiaomi firmware image\n");
		err = -EACCES;
		goto err_out;
	}

	err = xiaomifw_parse(fp, &info);
	if (err) {
		fprintf(stderr, "Failed to parse Xiaomi firmware image\n");
		goto err_close;
	}

	for (i = 0; i < sizeof(info.blobs) && info.blobs[i].offset; i++) {
		struct xiaomifw_blob_info *file_info = &info.blobs[i];

		if (!strcmp(file_info->header.name, name)) {
			offset = file_info->offset;
			size = file_info->size;
		}
	}

	if (!offset || !size) {
		err = -EINVAL;
		fprintf(stderr, "Failed to find requested data in input image\n");
		goto err_close;
	}

	fseek(fp, offset + sizeof(struct xiaomi_blob_header), SEEK_SET);
	while (size && (bytes = fread(buf, 1, xiaomifw_min(sizeof(buf), size), fp)) > 0) {
		fwrite(buf, bytes, 1, stdout);
		size -= bytes;
	}
	if (size) {
		err = -EIO;
		fprintf(stderr, "Failed to read last %zd B of data\n", size);
		goto err_close;
	}

err_close:
	xiaomifw_close(fp);
err_out:
	return err;
}

/**************************************************
 * Start
 **************************************************/

static void usage() {
	printf("Usage:\n");
	printf("\n");
	printf("Info about a Xiaomi firmware image:\n");
	printf("\txiaomifw info <options>\n");
	printf("\t-i <file>\t\t\t\t\tinput Xiaomi firmware image\n");
	printf("\n");
	printf("Creating a new Xiaomi firmware image:\n");
	printf("\txiaomifw create <file> [options]\n");
	printf("\t-m <model>\t\t\t\t\tmodel name (e.g. \"r4cm\")\n");
	printf("\t-b <flash_offset>:<type>:<name>:<path>\t\tblob to include\n");
	printf("\n");
	printf("Extracting from a Xiaomi firmware image:\n");
	printf("\txiaomifw extract <options>\n");
	printf("\t-i <file>\t\t\t\t\tinput Xiaomi firmware image\n");
	printf("\t-n <type>\t\t\t\t\tname of blob to extract (e.g. \"firmware.bin\")\n");
	printf("\n");
	printf("Examples:\n");
	printf("\txiaomifw info -i miwifi_r4cm_firmware_c6fa8_3.0.23_INT.bin\n");
	printf("\txiaomifw extract -i miwifi_r4cm_firmware_c6fa8_3.0.23_INT.bin -n firmware.bin\n");
	printf("\txiaomifw create \\\n");
	printf("\t\t-m r1cm \\\n");
	printf("\t\t-b ::xiaoqiang_version:/tmp/xiaoqiang_version \\\n");
	printf("\t\t-b 0x160000:uimage2:firmware.bin:/tmp/custom.bin\n");
}

int main(int argc, char **argv) {
	if (argc > 1) {
		optind++;
		if (!strcmp(argv[1], "info"))
			return xiaomifw_info(argc, argv);
		else if (!strcmp(argv[1], "create"))
			return xiaomifw_create(argc, argv);
		else if (!strcmp(argv[1], "extract"))
			return xiaomifw_extract(argc, argv);
	}

	usage();
	return 0;
}
