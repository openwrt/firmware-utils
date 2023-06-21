// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 Rafał Miłecki <rafal@milecki.pl>
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
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le32(x)	(x)
#define le32_to_cpu(x)	(x)
#define cpu_to_be32(x)	bswap_32(x)
#define be32_to_cpu(x)	bswap_32(x)
#else
#error "Unsupported endianness"
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define BCMCLM_MAGIC		"CLM DATA"

/* Raw data */

struct bcmclm_header {
	char magic[8];
	uint32_t unk0;
	uint8_t unk1[2];
	char api[20];
	char compiler[10];
	uint32_t virtual_header_address;
	uint32_t lookup_table_address;
	char clm_import_ver[30];
	char manufacturer[22];
};

struct bcmclm_lookup_table {
	uint32_t offset0;
	uint32_t offset1;
	uint32_t offset2;
	uint32_t offset3;
	uint32_t offset4;
	uint32_t offset5;
	uint32_t offset6;
	uint32_t offset7;
	uint32_t offset8;
	uint32_t offset9;
	uint32_t offset10;
	uint32_t offset11;
	uint32_t offset12;
	uint32_t offset13;
	uint32_t offset14;
	uint32_t offset15;
	uint32_t offset16;
	uint32_t offset17;
	uint32_t offset18;
	uint32_t offset19;
	uint32_t offset20;
	uint32_t offset21;
	uint32_t offset22;
	uint32_t offset23;
	uint32_t offset_creation_date;
	uint32_t offset25;
	uint32_t offset26;
	uint32_t offset27;
	uint32_t offset28;
	uint32_t offset29;
	uint32_t offset30;
	uint32_t offset31;
	uint32_t offset32;
	uint32_t offset33;
	uint32_t offset34;
	uint32_t offset35;
	uint32_t offset36;
	uint32_t offset37;
	uint32_t offset38;
	uint32_t offset39;
	uint32_t offset40;
	uint32_t offset41;
	uint32_t offset42;
	uint32_t offset43;
	uint32_t offset44;
	uint32_t offset45;
	uint32_t offset46;
	uint32_t offset47;
};

/* Parsed info */

struct bcmclm_info {
	struct bcmclm_header header;
	struct bcmclm_lookup_table lookup_table;
	size_t file_size;
	size_t clm_offset;
	size_t offsets_fixup;
};

static inline size_t bcmclm_min(size_t x, size_t y)
{
	return x < y ? x : y;
}

/**************************************************
 * Helpers
 **************************************************/

static FILE *bcmclm_open(const char *pathname, const char *mode)
{
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

static void bcmclm_close(FILE *fp)
{
	if (fp != stdin)
		fclose(fp);
}

/**************************************************
 * Existing CLM parser
 **************************************************/

static int bcmclm_search(FILE *fp, struct bcmclm_info *info)
{
	uint8_t buf[1024];
	size_t offset = 0;
	size_t bytes;
	int i;

	while ((bytes = fread(buf, 1, sizeof(buf), fp)) == sizeof(buf)) {
		for (i = 0; i < bytes - 12; i += 4) {
			uint32_t unk = le32_to_cpu(*(uint32_t *)(&buf[i + 8]));

			if (!memcmp(&buf[i], BCMCLM_MAGIC, 8) && !(unk & 0xff00ffff)) {
				info->clm_offset = offset + i;

				printf("Found CLM at offset 0x%zx\n", info->clm_offset);
				printf("\n");

				return 0;
			}
		}

		offset += bytes;
	}

	return -ENOENT;
}

static int bcmclm_parse(FILE *fp, struct bcmclm_info *info)
{
	struct bcmclm_header *header = &info->header;
	struct bcmclm_lookup_table *lookup_table = &info->lookup_table;
	struct stat st;
	int err = 0;

	/* File size */

	if (fstat(fileno(fp), &st)) {
		err = -errno;
		fprintf(stderr, "Failed to fstat: %d\n", err);
		return err;
	}
	info->file_size = st.st_size;

	/* Header */

	fseek(fp, info->clm_offset, SEEK_SET);

	if (fread(header, 1, sizeof(*header), fp) != sizeof(*header)) {
		fprintf(stderr, "Failed to read CLM header\n");
		return -EIO;
	}

	if (strncmp(header->magic, BCMCLM_MAGIC, 8)) {
		fprintf(stderr, "Invalid CLM header magic\n");
		return -EPROTO;
	}

	info->offsets_fixup = info->clm_offset - le32_to_cpu(header->virtual_header_address);

	/* Lookup table */

	fseek(fp, le32_to_cpu(info->header.lookup_table_address) + info->offsets_fixup, SEEK_SET);

	if (fread(lookup_table, 1, sizeof(*lookup_table), fp) != sizeof(*lookup_table)) {
		fprintf(stderr, "Failed to read lookup table\n");
		return -EIO;
	}

	return 0;
}

/**************************************************
 * Info
 **************************************************/

static void bcmclm_print_lookup_data(FILE *fp, struct bcmclm_info *info)
{
	uint8_t buf[64];
	size_t bytes;

	if (info->lookup_table.offset_creation_date) {
		printf("\n");

		fseek(fp, le32_to_cpu(info->lookup_table.offset_creation_date) + info->offsets_fixup, SEEK_SET);

		bytes = fread(buf, 1, sizeof(buf), fp);
		if (bytes) {
			printf("Creation date: %s\n", buf);
		}
	}
}

static int bcmclm_info(int argc, char **argv)
{
	struct bcmclm_info info = {};
	const char *pathname = NULL;
	int search = 0;
	FILE *fp;
	int c;
	int err = 0;

	while ((c = getopt(argc, argv, "i:s")) != -1) {
		switch (c) {
		case 'i':
			pathname = optarg;
			break;
		case 's':
			search = 1;
			break;
		}
	}

	fp = bcmclm_open(pathname, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open CLM\n");
		err = -EACCES;
		goto out;
	}

	if (search) {
		err = bcmclm_search(fp, &info);
		if (err) {
			fprintf(stderr, "Failed to find CLM in input file\n");
			goto err_close;
		}
	}

	err = bcmclm_parse(fp, &info);
	if (err) {
		fprintf(stderr, "Failed to parse CLM\n");
		goto err_close;
	}

	printf("API: %s\n", info.header.api);
	printf("Compiler: %s\n", info.header.compiler);
	printf("clm_import_ver: %s\n", info.header.clm_import_ver);
	printf("Manufacturer: %s\n", info.header.manufacturer);
	printf("\n");
	printf("Virtual header address: 0x%08x (real: 0x%zx)\n", le32_to_cpu(info.header.virtual_header_address), le32_to_cpu(info.header.virtual_header_address) + info.offsets_fixup);
	printf("Virtual lookup table address: 0x%08x (real: 0x%zx)\n", le32_to_cpu(info.header.lookup_table_address), le32_to_cpu(info.header.lookup_table_address) + info.offsets_fixup);

	bcmclm_print_lookup_data(fp, &info);

err_close:
	bcmclm_close(fp);
out:
	return err;
}

/**************************************************
 * Start
 **************************************************/

static void usage()
{
	printf("Usage:\n");
	printf("\n");
	printf("Info about CLM:\n");
	printf("\tbcmclm info <options>\n");
	printf("\t-i <file>\t\t\t\t\tinput CLM\n");
	printf("\t-s\t\t\t\t\tsearch for CLM data in bigger file\n");
	printf("\n");
	printf("Examples:\n");
	printf("\tbcmclm info -i x.clm\n");
	printf("\tbcmclm info -s -i brcmfmac4366c-pcie.bin\n");
}

int main(int argc, char **argv)
{
	if (argc > 1) {
		optind++;
		if (!strcmp(argv[1], "info"))
			return bcmclm_info(argc, argv);
	}

	usage();

	return 0;
}
