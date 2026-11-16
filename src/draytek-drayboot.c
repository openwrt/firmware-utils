// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * draytek-drayboot - build images for the DrayTek "DrayBoot" bootloader
 *
 * Copyright (C) 2026 Gregory Dymarek
 *
 * DrayBoot (DrayTek Vigor 2860 and relatives) accepts a firmware image over
 * TFTP and writes it verbatim to its NAND firmware slot. The image format is:
 *
 *   0x000  be32  total image length, including the trailing checksum
 *   0x008  "rDkmfaaryTedecz" signature
 *   0x100  payload; DrayBoot copies a fixed 512 KiB from here to RAM and
 *          jumps to it
 *   end-4  be32  one's complement of the 32-bit sum of all preceding
 *          big-endian words
 *
 * The payload here is a chainloaded U-Boot. Optionally, a kernel and a root
 * filesystem are appended so that a single upload installs the whole system:
 * the U-Boot region is padded to --uboot-region bytes so that the kernel
 * starts on its own NAND partition, and the kernel is padded to
 * --kernel-size bytes so that the rootfs starts on the next partition.
 */

#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HDR_LEN		0x100
#define SIG_OFF		0x08
#define SIG		"rDkmfaaryTedecz"
#define PAYLOAD_MAX	0x80000		/* DrayBoot copies a fixed 512 KiB */
#define IMAGE_MAX	0x2000000	/* DrayBoot firmware slot size */

static const char *progname;

static void usage(int status)
{
	fprintf(stderr,
		"Usage: %s -u <u-boot> -o <output> [options]\n"
		"\n"
		"Options:\n"
		"  -u <file>   U-Boot binary (payload, at most 512 KiB)\n"
		"  -k <file>   kernel image; builds a combined installer image\n"
		"  -r <file>   root filesystem appended after the kernel (needs -k)\n"
		"  -U <size>   U-Boot region size in combined images (default 0x100000)\n"
		"  -K <size>   kernel partition size in combined images (default 0x400000)\n"
		"  -o <file>   output image\n"
		"  -h          show this help\n",
		progname);
	exit(status);
}

static uint8_t *read_file(const char *name, size_t *len)
{
	uint8_t *buf;
	FILE *f;
	long n;

	f = fopen(name, "rb");
	if (!f) {
		fprintf(stderr, "%s: cannot open %s: %s\n", progname, name, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (fseek(f, 0, SEEK_END) || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
		fprintf(stderr, "%s: cannot size %s\n", progname, name);
		exit(EXIT_FAILURE);
	}
	buf = malloc(n ? n : 1);
	if (!buf || fread(buf, 1, n, f) != (size_t)n) {
		fprintf(stderr, "%s: cannot read %s\n", progname, name);
		exit(EXIT_FAILURE);
	}
	fclose(f);
	*len = n;
	return buf;
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

static uint32_t get_be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

static unsigned long parse_size(const char *s)
{
	char *end;
	unsigned long v = strtoul(s, &end, 0);

	if (!*s || *end) {
		fprintf(stderr, "%s: invalid size '%s'\n", progname, s);
		exit(EXIT_FAILURE);
	}
	return v;
}

int main(int argc, char **argv)
{
	const char *uboot_name = NULL, *kernel_name = NULL;
	const char *rootfs_name = NULL, *out_name = NULL;
	size_t uboot_region = 0x100000, kernel_size = 0x400000;
	size_t uboot_len, kernel_len = 0, rootfs_len = 0, len, total, i;
	uint8_t *uboot, *kernel = NULL, *rootfs = NULL, *img;
	uint32_t sum = 0;
	FILE *f;
	int c;

	progname = argv[0];

	while ((c = getopt(argc, argv, "u:k:r:U:K:o:h")) != -1) {
		switch (c) {
		case 'u': uboot_name = optarg; break;
		case 'k': kernel_name = optarg; break;
		case 'r': rootfs_name = optarg; break;
		case 'U': uboot_region = parse_size(optarg); break;
		case 'K': kernel_size = parse_size(optarg); break;
		case 'o': out_name = optarg; break;
		case 'h': usage(EXIT_SUCCESS); break;
		default: usage(EXIT_FAILURE);
		}
	}

	if (!uboot_name || !out_name || optind != argc)
		usage(EXIT_FAILURE);
	if (rootfs_name && !kernel_name) {
		fprintf(stderr, "%s: -r requires -k\n", progname);
		return EXIT_FAILURE;
	}

	uboot = read_file(uboot_name, &uboot_len);
	if (uboot_len > PAYLOAD_MAX) {
		fprintf(stderr, "%s: U-Boot is 0x%zx bytes, limit is 0x%x\n",
			progname, uboot_len, PAYLOAD_MAX);
		return EXIT_FAILURE;
	}

	if (kernel_name) {
		if (uboot_region < HDR_LEN + PAYLOAD_MAX + 4 || uboot_region % 4) {
			fprintf(stderr, "%s: invalid U-Boot region size 0x%zx\n",
				progname, uboot_region);
			return EXIT_FAILURE;
		}
		kernel = read_file(kernel_name, &kernel_len);
		if (kernel_len > kernel_size) {
			fprintf(stderr, "%s: kernel is 0x%zx bytes, partition is 0x%zx\n",
				progname, kernel_len, kernel_size);
			return EXIT_FAILURE;
		}
		if (rootfs_name)
			rootfs = read_file(rootfs_name, &rootfs_len);
		len = uboot_region + kernel_size + rootfs_len;
	} else {
		len = HDR_LEN + uboot_len;
	}

	/* pad to a whole word, then append the checksum word */
	len = (len + 3) & ~(size_t)3;
	total = len + 4;
	if (total > IMAGE_MAX) {
		fprintf(stderr, "%s: image is 0x%zx bytes, limit is 0x%x\n",
			progname, total, IMAGE_MAX);
		return EXIT_FAILURE;
	}

	img = calloc(1, total);
	if (!img) {
		fprintf(stderr, "%s: out of memory\n", progname);
		return EXIT_FAILURE;
	}

	memcpy(img + SIG_OFF, SIG, strlen(SIG));
	memcpy(img + HDR_LEN, uboot, uboot_len);
	if (kernel)
		memcpy(img + uboot_region, kernel, kernel_len);
	if (rootfs)
		memcpy(img + uboot_region + kernel_size, rootfs, rootfs_len);

	put_be32(img, total);
	for (i = 0; i < len; i += 4)
		sum += get_be32(img + i);
	put_be32(img + len, ~sum);

	f = fopen(out_name, "wb");
	if (!f || fwrite(img, 1, total, f) != total || fclose(f)) {
		fprintf(stderr, "%s: cannot write %s\n", progname, out_name);
		return EXIT_FAILURE;
	}

	free(img);
	free(uboot);
	free(kernel);
	free(rootfs);
	return EXIT_SUCCESS;
}
