// SPDX-License-Identifier: GPL-2.0-only
/*
 * mkh3cqca - wrap a FIT image into the upgrade header used by the web
 * interface of H3C Magic routers based on Qualcomm SoCs (QSDK firmware),
 * e.g. the Magic NX30, RT3000, RC3000 and RW3000.
 *
 * Layout (all words big endian unless noted):
 *   0x00  "H3C_+k", zero padded
 *   0x3c  length of everything from 0x40 to the end (little endian)
 *   0x40  inner header length (0x60)
 *   0x44  length of everything from 0x40 to the end
 *   0x48  checksum: the 32-bit words from 0x40 to the end add up to
 *         0xffffffff
 *   0x4c  timestamp
 *   0x50  payload length
 *   0x54  0
 *   0x58  0xaa 0xff 0xff 0xff 0xff 0x01 0xff ...
 *   0x63  firmware version, e.g. "NX30V100R012"; the product name at
 *         its start must match the device
 *   0x87  0x01
 *   0x88  internal version, e.g. "D019"
 *   0xa0  payload (FIT image), padded to 4 bytes
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define HDR_LEN		0xa0
#define INNER_OFF	0x40
#define VERSION_OFF	0x63
#define VERSION_MAX	(0x87 - VERSION_OFF)
#define INTVER_OFF	0x88
#define INTVER_MAX	(HDR_LEN - INTVER_OFF)

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

static void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = v;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}

static uint32_t get_be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -i <fit> -o <output> -v <version> [-d <internal version>] [-t <timestamp>]\n"
		"  -v  firmware version, starting with the product name (e.g. NX30V100R012)\n"
		"  -d  internal version (e.g. D019), default empty\n"
		"  -t  timestamp, default SOURCE_DATE_EPOCH or the current time\n",
		prog);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	const char *in = NULL, *out = NULL, *version = NULL, *intver = "";
	const char *epoch = getenv("SOURCE_DATE_EPOCH");
	uint32_t timestamp = epoch ? strtoul(epoch, NULL, 0) : time(NULL);
	uint32_t payload_len, inner_len, sum = 0;
	size_t fit_len, total, i;
	uint8_t *buf;
	FILE *f;
	long size;
	int c;

	while ((c = getopt(argc, argv, "i:o:v:d:t:h")) != -1) {
		switch (c) {
		case 'i': in = optarg; break;
		case 'o': out = optarg; break;
		case 'v': version = optarg; break;
		case 'd': intver = optarg; break;
		case 't': timestamp = strtoul(optarg, NULL, 0); break;
		default: usage(argv[0]);
		}
	}
	if (!in || !out || !version)
		usage(argv[0]);
	if (strlen(version) >= VERSION_MAX || strlen(intver) >= INTVER_MAX) {
		fprintf(stderr, "version string too long\n");
		return EXIT_FAILURE;
	}

	f = fopen(in, "rb");
	if (!f || fseek(f, 0, SEEK_END) || (size = ftell(f)) < 0) {
		fprintf(stderr, "cannot read %s: %s\n", in, strerror(errno));
		return EXIT_FAILURE;
	}
	fit_len = size;
	payload_len = (fit_len + 3) & ~3;
	total = HDR_LEN + payload_len;
	buf = calloc(1, total);
	if (!buf) {
		fprintf(stderr, "out of memory\n");
		return EXIT_FAILURE;
	}
	rewind(f);
	if (fread(buf + HDR_LEN, 1, fit_len, f) != fit_len) {
		fprintf(stderr, "cannot read %s\n", in);
		return EXIT_FAILURE;
	}
	fclose(f);

	inner_len = total - INNER_OFF;
	memcpy(buf, "H3C_+k", 6);
	put_le32(buf + 0x3c, inner_len);
	put_be32(buf + 0x40, HDR_LEN - INNER_OFF);
	put_be32(buf + 0x44, inner_len);
	put_be32(buf + 0x4c, timestamp);
	put_be32(buf + 0x50, payload_len);
	memset(buf + 0x58, 0xff, HDR_LEN - 0x58);
	buf[0x58] = 0xaa;
	buf[0x5d] = 0x01;
	memcpy(buf + VERSION_OFF, version, strlen(version) + 1);
	buf[0x87] = 0x01;
	memcpy(buf + INTVER_OFF, intver, strlen(intver) + 1);

	for (i = INNER_OFF; i < total; i += 4)
		sum += get_be32(buf + i);
	put_be32(buf + 0x48, 0xffffffff - sum);

	f = fopen(out, "wb");
	if (!f || fwrite(buf, 1, total, f) != total || fclose(f)) {
		fprintf(stderr, "cannot write %s: %s\n", out, strerror(errno));
		return EXIT_FAILURE;
	}
	free(buf);
	return EXIT_SUCCESS;
}
