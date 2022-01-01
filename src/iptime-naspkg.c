// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020 Sungbo Eo <mans0n@gorani.run>
 *
 * This code is based on mkdhpimg.c and mkzcfw.c
 * Copyright (C) 2010 Gabor Juhos <juhosg@openwrt.org>
 * Copyright (c) 2016 FUKAUMI Naoki <naobsd@gmail.com>
 *
 * Checksum algorithm is derived from EFM's mknas utility
 * found in GPL'ed T16000 source.
 */

#include <byteswap.h>
#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if !defined(__BYTE_ORDER)
#error "Unknown byte order"
#endif

#if (__BYTE_ORDER == __BIG_ENDIAN)
#define HOST_TO_LE32(x)	bswap_32(x)
#elif (__BYTE_ORDER == __LITTLE_ENDIAN)
#define HOST_TO_LE32(x)	(x)
#else
#error "Unsupported endianness"
#endif

#define FW_HEADER_SIZE	0x400
#define FW_VERSION	"0.0.00"
#define FW_MAGIC	"EFM_NAS_PKG"

struct fw_header {
	uint8_t model[32];
	uint8_t version[32];
	uint8_t ctime[32];
	uint32_t size;
	uint32_t checksum;
	uint32_t offset_header;
	uint32_t offset_rootfs;
	uint32_t offset_app;
	uint32_t checksum_kr;
	uint8_t magic[16];

	uint32_t size_kra;
	uint32_t checksum_kra;
	uint32_t offset_ext;
} __attribute__ ((packed));

enum board_type {
	BOARD_KIRKWOOD,
	BOARD_ARMADA380,
};

struct board_type_info {
	int bootloader_size;
	int block_size;
};

struct board_info {
	const char *model;
	enum board_type type;
};

struct board_type_info board_types[] = {
	/* BOARD_KIRKWOOD */
	{ .bootloader_size = 0x40000, .block_size = 0x0 },
	/* BOARD_ARMADA380 */
	{ .bootloader_size = 0x100000, .block_size = 0x10000 },
};

struct board_info boards[] = {
	{ .model = "nas1", .type = BOARD_KIRKWOOD },
	{ .model = "nas1dual", .type = BOARD_ARMADA380 },
	{ /* sentinel */ }
};

struct board_info *find_board(const char *model)
{
	struct board_info *ret = NULL;
	struct board_info *board;

	for (board = boards; board->model != NULL; board++) {
		if (strcmp(model, board->model) == 0) {
			ret = board;
			break;
		}
	}

	return ret;
}

/* (FW_HEADER_SIZE + size_in + padding) % block_size == 0 */
size_t calc_padding(enum board_type type, size_t size_in)
{
	int block_size, remainder;

	block_size = board_types[type].block_size;
	if (block_size == 0)
		return 0;
	remainder = (FW_HEADER_SIZE + size_in) % block_size;
	return remainder ? block_size - remainder : 0;
}

char *get_ctime(void)
{
	char *env = getenv("SOURCE_DATE_EPOCH");
	char *endptr = env;
	time_t timestamp = -1;

	if (env && *env) {
		errno = 0;
		timestamp = strtoull(env, &endptr, 10);

		if (errno || (endptr && *endptr != '\0')) {
			fprintf(stderr, "Invalid SOURCE_DATE_EPOCH\n");
			timestamp = -1;
		}
	}

	if (timestamp == -1)
		time(&timestamp);

	return asctime(gmtime(&timestamp));
}

uint32_t make_checksum(const char *model_name, uint8_t *bytes, int length)
{
	int i;
	uint32_t sum = 0;
	uint32_t magic = 0x19283745;

	for (i = 0; i < length; i++)
		sum += bytes[i];
	return ((uint32_t)strlen(model_name) * magic + ~sum) ^ sum;
}

void make_header(struct board_info *board, uint8_t *buffer, size_t img_size)
{
	struct fw_header *header = (struct fw_header *)buffer;
	char *time_created;
	uint32_t checksum;
	size_t bootloader_size, image_end_offset;

	time_created = get_ctime();
	checksum = make_checksum(board->model, buffer + FW_HEADER_SIZE, img_size);
	bootloader_size = board_types[board->type].bootloader_size;
	image_end_offset = bootloader_size + FW_HEADER_SIZE + img_size;

	strncpy((char *)header->model, board->model, sizeof(header->model)-1);
	strncpy((char *)header->version, FW_VERSION, sizeof(header->version)-1);
	strncpy((char *)header->ctime, time_created, sizeof(header->ctime)-1);
	header->size = HOST_TO_LE32(img_size);
	header->checksum = HOST_TO_LE32(checksum);
	header->offset_header = HOST_TO_LE32(bootloader_size);
	header->offset_rootfs = HOST_TO_LE32(image_end_offset);
	header->offset_app = HOST_TO_LE32(image_end_offset);
	header->checksum_kr = HOST_TO_LE32(checksum);
	strncpy((char *)header->magic, FW_MAGIC, sizeof(header->magic)-1);

	if (board->type == BOARD_ARMADA380) {
		header->size_kra = HOST_TO_LE32(img_size);
		header->checksum_kra = HOST_TO_LE32(checksum);
		header->offset_ext = HOST_TO_LE32(image_end_offset);
	}
}

int main(int argc, const char *argv[])
{
	const char *model_name, *img_in, *img_out;
	struct board_info *board;
	int file_in, file_out;
	struct stat stat_in;
	size_t size_in, size_in_padded, size_out;
	uint8_t *buffer;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <model> <input> <output>\n", argv[0]);
		return EXIT_FAILURE;
	}
	model_name = argv[1];
	img_in = argv[2];
	img_out = argv[3];

	board = find_board(model_name);
	if (board == NULL) {
		fprintf(stderr, "%s: Not supported model\n", model_name);
		return EXIT_FAILURE;
	}

	if ((file_in = open(img_in, O_RDONLY)) == -1)
		err(EXIT_FAILURE, "%s", img_in);

	if (fstat(file_in, &stat_in) == -1)
		err(EXIT_FAILURE, "%s", img_in);

	size_in = stat_in.st_size;
	size_in_padded = size_in + calc_padding(board->type, size_in);
	size_out = FW_HEADER_SIZE + size_in_padded;

	if ((buffer = malloc(size_out)) == NULL)
		err(EXIT_FAILURE, "malloc");

	read(file_in, buffer + FW_HEADER_SIZE, size_in);
	close(file_in);

	memset(buffer, 0, FW_HEADER_SIZE);

	make_header(board, buffer, size_in_padded);

	if ((file_out = creat(img_out, 0644)) == -1)
		err(EXIT_FAILURE, "%s", img_out);
	write(file_out, buffer, size_out);
	close(file_out);

	free(buffer);

	return EXIT_SUCCESS;
}
