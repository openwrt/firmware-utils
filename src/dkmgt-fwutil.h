// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2025 Naomi Kirby <dev at manawolf.ca>
 */

#ifndef DKMGT_FWUTIL_H
#define DKMGT_FWUTIL_H

#include <stdint.h>

#define DKMGT_MAGIC_0       0xa5a5a5a5
#define DKMGT_MAGIC_1       0x8f72632a
#define DKMGT_MAGIC_2       0x40f8600
#define DKMGT_MAGIC_3       0x9206b51
#define DKMGT_MAGIC_4       0xd2b7636a
#define DKMGT_MAGIC_5       0x5a5a5a5a

struct dkmgt_fw_header {
    uint32_t magic[6];
    uint32_t version;
    uint32_t next_header;
    uint32_t header_len;
    uint32_t total_len;
    uint32_t unknown[2];
    uint8_t md5hash[16];
    uint8_t __padding1[240];
    uint8_t signature[112];
    uint8_t __padding2[3744];
};

#define DKMGT_PTN_MAGIC_0   0xaa55d98f
#define DKMGT_PTN_MAGIC_1   0x04e955aa

struct dkmgt_ptn_header {
    uint32_t magic[2];
    uint32_t length;
    uint32_t checksum;
};

struct dkmgt_ptn_entry {
    char name[32];
    uint32_t base;
    uint32_t size;
    void *data;
    uint32_t memtype;
};
#define DKMGT_PTN_MEM_NONE  0
#define DKMGT_PTN_MEM_HEAP  1
#define DKMGT_PTN_MEM_MMAP  2

#define DKMGT_PTN_BLOCK_SIZE (64 * 1024)
#define DKMGT_MAX_PARTITIONS 64

struct dkmgt_ptn_table {
    uint32_t disk_size;
    uint32_t count;
    struct dkmgt_ptn_entry partitions[DKMGT_MAX_PARTITIONS];
};

struct dkmgt_support_entry {
    char model_name[64];
    char model_version[16];
    char special_id[64];
    char flash_version[64];
};

#define DKMGT_MAX_SUPPORT_ENTRIES 64

struct dkmgt_support_list {
    uint32_t count;
    struct dkmgt_support_entry list[DKMGT_MAX_SUPPORT_ENTRIES];
};

struct dkmgt_fw_info {
    uint32_t ver_major;
    uint32_t ver_minor;
    uint32_t ver_patch;
    uint32_t timestamp;
    uint32_t release;
    char firmware_id[64];
};

#endif // DKMGT_FWUTIL_H
