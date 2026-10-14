// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jbootimage - build a jboot (AMIT "ZXL6") record-format migration image
 *              for the Zyxel LTE3301-M209/Q222.
 *
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The jboot record header is the same 80-byte AUH structure the D-Link
 * mkdlinkfw tool already builds (see mkdlinkfw-lib.h), so the checksum and
 * the field layout are shared from there. Two things are specific to the
 * Zyxel variant and are added here:
 *
 *   - the header scramble the Zyxel recovery loader expects (mkdlinkfw
 *     leaves the D-Link "derange" field at 0, i.e. unscrambled);
 *   - the migration layout: a raw U-Boot record targeting flash offset 0
 *     plus raw kernel/rootfs records at the firmware offset, with the
 *     U-Boot record written last so an aborted upload leaves the device
 *     recoverable. mkdlinkfw only produces the D-Link factory layout
 *     (kernel wrapped in STAG/SCH2 into the firmware partition).
 *
 * The record stream is: [80-byte record][data] ... . Each record carries
 * erase_start/length and data_offset/length; the loader writes the data to
 * data_offset + flash_base. Build with family member (FMID) 0xffff so the
 * loader skips its device-FMID match and accepts the migration image.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "mkdlinkfw-lib.h"

/* referenced by the ERR/ERRS macros in mkdlinkfw-lib.h */
char *progname;

#define REC_SIZE	AUH_SIZE		/* 80 == 0x50 */
#define SCRAMBLE_SEED	0x1234
#define FLASH_BASE_NONE	0			/* offsets are flash-relative here */

/* record section types (field +0x46) */
#define SEC_TYPE_KERNEL	0x04
#define SEC_TYPE_ROOTFS	0x08

static inline void put_le16(uint8_t *p, uint16_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
}

static inline void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

static inline uint32_t get_le32(const uint8_t *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * The loader's keystream generator ("aba0"): three LCG steps per output
 * word, output assembled from the high halves. Advances *state.
 */
static uint32_t prng(uint32_t *state)
{
	uint32_t x, y, z, a, b, c;

	x = (*state * 0x41c64e6dU + 0x3039U);
	y = (x * 0x41c64e6dU + 0x3039U);
	z = (y * 0x41c64e6dU + 0x3039U);
	*state = z;

	a = (x >> 16) & 0x7ff;
	b = (y >> 16) & 0x3ff;
	c = (z >> 16) & 0x3ff;

	return c | ((b ^ (a << 10)) << 10);
}

/*
 * Scramble an 80-byte plaintext record into out[] the way the loader's
 * descrambler (adf8/ac90) consumes it: a free seed goes into bytes 6..7,
 * the descramble marker 0x81 into byte 4, bytes 0x0d/0x1b carry the wanted
 * plaintext of bytes 4/5, then the 18 words from offset 8 are XORed with a
 * CBC-like keystream, and finally the seed is placed byte-swapped at
 * 0x4e..0x4f (the descrambler swaps it back into 6..7).
 */
static void scramble(const uint8_t *plain, uint8_t *out)
{
	uint32_t state = SCRAMBLE_SEED;
	uint32_t k;
	int i;

	memcpy(out, plain, REC_SIZE);

	out[4] = 0x81;
	out[0xd] = plain[4];
	out[0x1b] = plain[5];
	out[6] = (SCRAMBLE_SEED >> 8) & 0xff;
	out[7] = SCRAMBLE_SEED & 0xff;
	out[0x4e] = plain[6];
	out[0x4f] = plain[7];

	k = prng(&state);
	for (i = 0; i < 18; i++) {
		uint8_t *p = out + 8 + i * 4;
		uint32_t w = get_le32(p);	/* plaintext */
		uint32_t cw = k ^ w;		/* ciphertext */

		put_le32(p, cw);
		k = prng(&state) ^ cw;		/* chain with the ciphertext */
	}
}

/*
 * 16-bit end-around-carry sum over the whole record must equal 0xffff.
 * jboot_checksum() from the shared lib implements exactly that fold; for an
 * 80-byte (even) record there is no odd-byte tail, so the result matches a
 * plain 40-word sum.
 */
static uint16_t rec_csum(const uint8_t *rec)
{
	return jboot_checksum(0, (uint16_t *)rec, REC_SIZE);
}

static int build_record(uint8_t *out, uint32_t erase_start, uint32_t erase_length,
			uint32_t data_offset, uint32_t data_length,
			uint8_t type, uint8_t flags, uint16_t fm)
{
	uint8_t p[REC_SIZE];
	uint32_t cand;

	memset(p, 0, sizeof(p));
	memcpy(p, "ZXL6", 4);
	p[4] = 0x45;			/* final plaintext byte 4 (via scramble) */
	p[0x1a] = 0x01;			/* PV */
	put_le32(p + 0x20, erase_start);
	put_le32(p + 0x24, erase_length);
	put_le32(p + 0x28, data_offset);
	put_le32(p + 0x2c, data_length);
	put_le16(p + 0x40, AUH_HDR_ID);	/* 0x4842 */
	p[0x42] = AUH_HDR_VER;		/* 0x02 */
	p[0x46] = type;
	p[0x47] = flags;
	put_le16(p + 0x4c, fm);
	/* seed, byte-swapped, where the descrambler leaves it */
	p[0x4e] = (SCRAMBLE_SEED >> 8) & 0xff;
	p[0x4f] = SCRAMBLE_SEED & 0xff;

	/*
	 * Make the whole-record sum come out to 0xffff by searching a filler
	 * word at offset 0x0e. The loader zeroes 0x0d/0x1b in the final
	 * plaintext, so this cannot be solved linearly; a 64K scan is
	 * negligible.
	 */
	for (cand = 0; cand < 0x10000; cand++) {
		put_le16(p + 0x0e, cand);
		if (rec_csum(p) == 0xffff)
			break;
	}
	if (cand == 0x10000) {
		ERR("no valid record checksum found");
		return -1;
	}

	scramble(p, out);
	return 0;
}

static uint8_t *read_file(const char *name, uint32_t *len)
{
	struct file_info fi = { .file_name = (char *)name };
	uint8_t *buf;

	if (get_file_stat(&fi))
		return NULL;
	buf = malloc(fi.file_size);
	if (!buf) {
		ERR("out of memory for %s", name);
		return NULL;
	}
	if (read_to_buf(&fi, (char *)buf)) {
		free(buf);
		return NULL;
	}
	*len = fi.file_size;
	return buf;
}

static void usage(int status)
{
	fprintf(stderr,
		"Usage: %s -u <u-boot> -c <kernel+rootfs> -s <kernel-size> "
		"-f <fmid> -O <fw-offset> -o <out>\n"
		"\n"
		"  -u <file>   raw bootloader image, written to flash offset 0\n"
		"  -c <file>   concatenated kernel+rootfs for the firmware area\n"
		"  -s <size>   split offset inside -c between kernel and rootfs\n"
		"  -f <fmid>   family member id (use 0xffff for a migration image)\n"
		"  -O <off>    firmware flash offset the kernel/rootfs go to\n"
		"  -o <file>   output image\n",
		progname);
	exit(status);
}

int main(int argc, char *argv[])
{
	const char *uboot = NULL, *combo = NULL, *out = NULL;
	long ksize = -1, fw_off = -1, fm = -1;
	uint8_t *ub_d, *combo_d, rec[REC_SIZE];
	uint32_t ub_len, combo_len;
	FILE *fp;
	int c;

	progname = argv[0];

	while ((c = getopt(argc, argv, "u:c:s:f:O:o:h")) != -1) {
		switch (c) {
		case 'u': uboot = optarg; break;
		case 'c': combo = optarg; break;
		case 's': ksize = strtol(optarg, NULL, 0); break;
		case 'f': fm = strtol(optarg, NULL, 0); break;
		case 'O': fw_off = strtol(optarg, NULL, 0); break;
		case 'o': out = optarg; break;
		case 'h': usage(EXIT_SUCCESS); break;
		default: usage(EXIT_FAILURE);
		}
	}

	if (!uboot || !combo || !out || ksize < 0 || fw_off < 0 || fm < 0)
		usage(EXIT_FAILURE);

	ub_d = read_file(uboot, &ub_len);
	combo_d = read_file(combo, &combo_len);
	if (!ub_d || !combo_d)
		return EXIT_FAILURE;
	if ((uint32_t)ksize > combo_len) {
		ERR("kernel size 0x%lx exceeds -c file size 0x%x", ksize, combo_len);
		return EXIT_FAILURE;
	}

	fp = fopen(out, "wb");
	if (!fp) {
		ERRS("cannot open %s", out);
		return EXIT_FAILURE;
	}

	/*
	 * Order matters: the U-Boot record (flash offset 0) comes last so an
	 * aborted upload never touches the bootloader sector.
	 */
	/* record 1: kernel -> fw_off */
	if (build_record(rec, fw_off, ksize, fw_off, ksize,
			 SEC_TYPE_KERNEL, 0, fm))
		return EXIT_FAILURE;
	fwrite(rec, 1, REC_SIZE, fp);
	fwrite(combo_d, 1, ksize, fp);

	/* record 2: rootfs (and any inter-section padding) -> right behind it */
	if (build_record(rec, fw_off + ksize, combo_len - ksize,
			 fw_off + ksize, combo_len - ksize,
			 SEC_TYPE_ROOTFS, 0, fm))
		return EXIT_FAILURE;
	fwrite(rec, 1, REC_SIZE, fp);
	fwrite(combo_d + ksize, 1, combo_len - ksize, fp);

	/* record 3: U-Boot -> flash offset 0 */
	if (build_record(rec, 0, ub_len, 0, ub_len, SEC_TYPE_KERNEL, 0, fm))
		return EXIT_FAILURE;
	fwrite(rec, 1, REC_SIZE, fp);
	fwrite(ub_d, 1, ub_len, fp);

	if (fclose(fp)) {
		ERRS("error writing %s", out);
		return EXIT_FAILURE;
	}

	DBG("%s: u-boot %u, kernel %ld, rootfs %u, fw-offset 0x%lx",
	    out, ub_len, ksize, combo_len - (uint32_t)ksize, fw_off);
	free(ub_d);
	free(combo_d);
	return EXIT_SUCCESS;
}
