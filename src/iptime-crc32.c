// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021 Sungbo Eo <mans0n@gorani.run>
 *
 * This code is based on mkdhpimg.c and mkzcfw.c
 * Copyright (C) 2010 Gabor Juhos <juhosg@openwrt.org>
 * Copyright (c) 2016 FUKAUMI Naoki <naobsd@gmail.com>
 *
 * Checksum algorithm is derived from add_iptime_fw_header.c
 * Copyright (C) 2020 Jaehoon You <teslamint@gmail.com>
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
#include <unistd.h>

#include "cyg_crc.h"

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

#define FW_VERSION	"00_000"

struct fw_header {
	uint8_t model[8];
	uint8_t version[8];
	uint8_t reserved[32];
	uint32_t size;
	uint32_t checksum;
} __attribute__ ((packed));

struct board_info {
	const char *model;
	size_t payload_offset;
};

struct board_info boards[] = {
	{ .model = "ax2004m", .payload_offset = 0x38 },
	{ .model = "ax8004m", .payload_offset = 0x38 },
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

uint32_t make_checksum(struct fw_header *header, uint8_t *payload, int size)
{
	cyg_uint32 checksum;

	/* get CRC of header */
	checksum = cyg_crc32_accumulate(~0L, header, sizeof(*header));

	/* get CRC of payload buffer with header CRC as initial value */
	return (uint32_t)cyg_crc32_accumulate(checksum, payload, size);
}

void make_header(struct board_info *board, uint8_t *buffer, size_t img_size)
{
	struct fw_header *header = (struct fw_header *)buffer;
	uint32_t checksum;

	strncpy((char *)header->model, board->model, sizeof(header->model)-1);
	strncpy((char *)header->version, FW_VERSION, sizeof(header->version)-1);
	header->size = HOST_TO_LE32(img_size);
	checksum = make_checksum(header, buffer + board->payload_offset, img_size);
	header->checksum = HOST_TO_LE32(checksum);
}

int main(int argc, const char *argv[])
{
	const char *model_name, *img_in, *img_out;
	struct board_info *board;
	int file_in, file_out;
	struct stat stat_in;
	size_t size_in, size_out;
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
	size_out = board->payload_offset + size_in;

	if ((buffer = malloc(size_out)) == NULL)
		err(EXIT_FAILURE, "malloc");

	read(file_in, buffer + board->payload_offset, size_in);
	close(file_in);

	memset(buffer, 0, board->payload_offset);

	make_header(board, buffer, size_in);

	if ((file_out = creat(img_out, 0644)) == -1)
		err(EXIT_FAILURE, "%s", img_out);
	write(file_out, buffer, size_out);
	close(file_out);

	free(buffer);

	return EXIT_SUCCESS;
}
