// SPDX-License-Identifier: GPL-2.0-only
/*
 * mkbossimg - wrap a firmware image in a Bintec/Teldat BOSS header
 *
 * Copyright (C) 2009-2013 Sebastien Decourriere <sebtx452@gmail.com>
 * Copyright (C) 2026 Simon Wunderlich <sw@simonwunderlich.de>
 * Based on mkbrnimg.c
 *
 * The BOSS bootmonitor found on Bintec elmeg RS-series routers expects a
 * 52-byte big-endian header in front of a gzip-compressed image. The board
 * family is identified by a magic string, which the bootmonitor reports as
 * "Identification" under "Show System Information".
 *
 * The input file is expected to carry a 52-byte placeholder header, so that
 * the payload behind the real header stays aligned to the flash sector size.
 * The placeholder is skipped; length and CRC are computed over the remainder.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

/* Image types */
#define IMG_TYPE_BOSS		0x00 /* Compressed BOSS */
#define IMG_TYPE_UBOSS		0x01 /* Uncompressed BOSS (uBoss) */
#define IMG_TYPE_LOGIC		0x02 /* Logic aka first bootloader */
#define IMG_TYPE_BOOTMON	0x03 /* Bootmonitor aka second bootloader */
#define IMG_TYPE_FIRMWARE	0x04 /* Firmware (unknown) */

#define IMG_VER		0x00000000

/*
 * In vendor images the two fields called "unknown" here hold the length and
 * CRC of an uncompressed section. For gzip images the bootmonitor accepts the
 * values below, which is what the original tool always wrote.
 */
#define UNKNOWN_1	0x00FA0524
#define UNKNOWN_2	0x00000000
#define UNKNOWN_3	0x00000000

/* Version 42, high enough that the vendor web UI accepts the upgrade */
#define FW_VERSION	0x002A0000

#define MAGIC_CHAOSENDDRAGON	"BINTEC ChaosEndDragon"
#define MAGIC_CLOSEDEYEVISUAL	"TELDAT ClosedEyeVisual"

struct boss_header {
	char magic[23];
	uint32_t fw_version;
	uint8_t image_type;
	uint32_t image_version;
	uint32_t image_length;
	uint32_t unknown1;
	uint32_t unknown2;
	uint32_t crc32;
	uint32_t unknown3;
} __attribute__((packed));

static const struct board {
	const char *name;
	const char *magic;
} boards[] = {
	/*
	 * Verified on the device itself via the bootmonitor's
	 * "Show System Information" -> "Identification:" field.
	 */
	{ "rs123", MAGIC_CLOSEDEYEVISUAL },
	{ "rs230", MAGIC_CHAOSENDDRAGON  },
	{ "rs353", MAGIC_CLOSEDEYEVISUAL },
};

static void usage(const char *mess)
{
	size_t i;

	fprintf(stderr, "Error: %s\n", mess);
	fprintf(stderr, "Usage: mkbossimg <board> <input file> <output file>\n");
	fprintf(stderr, "Supported boards:");
	for (i = 0; i < sizeof(boards) / sizeof(boards[0]); i++)
		fprintf(stderr, " %s", boards[i].name);
	fprintf(stderr, "\n");
	exit(1);
}

static ssize_t write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	size_t done = 0;

	while (done < len) {
		ssize_t n = write(fd, p + done, len - done);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		done += (size_t)n;
	}
	return (ssize_t)done;
}

int main(int argc, char **argv)
{
	const char *board_name, *in_path, *out_path;
	const char *magic = NULL;
	struct boss_header hdr;
	struct stat st;
	char *map, *payload;
	size_t payload_len;
	uint32_t crc;
	size_t i;
	int fd, outfd;

	if (argc != 4)
		usage("wrong number of arguments");

	board_name = argv[1];
	in_path = argv[2];
	out_path = argv[3];

	for (i = 0; i < sizeof(boards) / sizeof(boards[0]); i++) {
		if (strcmp(board_name, boards[i].name) == 0) {
			magic = boards[i].magic;
			break;
		}
	}
	if (!magic) {
		fprintf(stderr, "Invalid board type '%s'\n", board_name);
		usage("unknown board");
	}

	fd = open(in_path, O_RDONLY);
	if (fd < 0 || fstat(fd, &st) < 0) {
		fprintf(stderr, "Error opening '%s': %s\n", in_path, strerror(errno));
		exit(1);
	}
	if ((size_t)st.st_size <= sizeof(hdr)) {
		fprintf(stderr, "Input '%s' is too small (%ju bytes)\n",
			in_path, (uintmax_t)st.st_size);
		exit(1);
	}

	map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "Error mapping '%s': %s\n", in_path, strerror(errno));
		exit(1);
	}
	close(fd);

	/* Skip the placeholder header that pads the payload to a sector */
	payload = map + sizeof(hdr);
	payload_len = (size_t)st.st_size - sizeof(hdr);

	if (!((unsigned char)payload[0] == 0x1F && (unsigned char)payload[1] == 0x8B)) {
		fprintf(stderr, "Invalid image type: expected gzip magic, got %02X %02X\n",
			(unsigned char)payload[0], (unsigned char)payload[1]);
		exit(1);
	}

	memset(&hdr, 0, sizeof(hdr));
	strncpy(hdr.magic, magic, sizeof(hdr.magic) - 1);
	hdr.fw_version = htonl(FW_VERSION);
	hdr.image_type = IMG_TYPE_BOSS;
	hdr.image_version = htonl(IMG_VER);
	hdr.unknown1 = htonl(UNKNOWN_1);
	hdr.unknown2 = htonl(UNKNOWN_2);
	hdr.unknown3 = htonl(UNKNOWN_3);

	crc = crc32(0, (const unsigned char *)payload, payload_len);
	hdr.image_length = htonl((uint32_t)payload_len);
	hdr.crc32 = htonl(crc);

	fprintf(stderr, "Board '%s' magic '%s', crc32 %08x, length %08zx\n",
		board_name, magic, crc, payload_len);

	outfd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (outfd < 0) {
		fprintf(stderr, "Error opening '%s' for writing: %s\n",
			out_path, strerror(errno));
		exit(1);
	}
	if (write_all(outfd, &hdr, sizeof(hdr)) < 0 ||
	    write_all(outfd, payload, payload_len) < 0) {
		fprintf(stderr, "Error writing '%s': %s\n", out_path, strerror(errno));
		exit(1);
	}
	close(outfd);
	munmap(map, (size_t)st.st_size);

	return EXIT_SUCCESS;
}
