/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * mksunxiandroid - wrap a loader, an arm64 kernel and a DTB into an Android
 * boot image (version 3) that an Allwinner 32-bit vendor U-Boot boots.
 */
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARM64_HDR_SIZE		64
#define ARM64_MAGIC		0x644d5241
#define ARM64_FLAGS		0x0a
#define ARM64_CODE0_B_LOADER	0x14000010

#define BOOT_MAGIC		"ANDROID!"
#define BOOT_MAGIC_SIZE		8
#define BOOT_HDR_V3_SIZE	1580
#define BOOT_HDR_VERSION	3
#define BOOT_PAGE_SIZE		4096

static void put_le32(uint8_t *buf, uint32_t val)
{
	buf[0] = val & 0xff;
	buf[1] = (val >> 8) & 0xff;
	buf[2] = (val >> 16) & 0xff;
	buf[3] = val >> 24;
}

static void put_le64(uint8_t *buf, uint64_t val)
{
	put_le32(buf, val & 0xffffffff);
	put_le32(buf + 4, val >> 32);
}

static uint8_t *file_read(const char *path, size_t *len)
{
	uint8_t *buf;
	long size;
	FILE *f;

	f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) || (size = ftell(f)) < 0) {
		fprintf(stderr, "cannot size %s: %s\n", path, strerror(errno));
		fclose(f);
		return NULL;
	}
	rewind(f);
	buf = malloc(size);
	if (!buf) {
		fprintf(stderr, "out of memory for %s\n", path);
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, size, f) != (size_t)size) {
		fprintf(stderr, "cannot read %s: %s\n", path, strerror(errno));
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*len = size;
	return buf;
}

static size_t round_up(size_t val, size_t align)
{
	return (val + align - 1) & ~(align - 1);
}

static int blob_write(FILE *f, const uint8_t *data, size_t len, size_t pad)
{
	static const uint8_t zero[BOOT_PAGE_SIZE];
	size_t rem;
	size_t n;

	if (len && fwrite(data, 1, len, f) != len)
		return -1;
	for (rem = pad - len; rem; rem -= n) {
		n = rem < sizeof(zero) ? rem : sizeof(zero);
		if (fwrite(zero, 1, n, f) != n)
			return -1;
	}
	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s -l loader -k kernel -d dtb -o out\n"
		"  -l  position-independent relocation loader (flat binary)\n"
		"  -k  arm64 kernel Image\n"
		"  -d  device tree blob\n"
		"  -o  output Android boot image\n", argv0);
}

int main(int argc, char **argv)
{
	const char *loader_path, *kernel_path, *dtb_path, *out_path;
	size_t loader_len, kernel_len, dtb_len, ksz, dsz, blob_len;
	uint8_t *loader, *kernel, *dtb;
	uint8_t stub[ARM64_HDR_SIZE];
	uint8_t hdr[BOOT_PAGE_SIZE];
	uint8_t szhdr[16];
	int ret = 1;
	FILE *out;
	int c;

	loader_path = kernel_path = dtb_path = out_path = NULL;
	loader = kernel = dtb = NULL;
	out = NULL;

	while ((c = getopt(argc, argv, "l:k:d:o:")) != -1) {
		switch (c) {
		case 'l': loader_path = optarg; break;
		case 'k': kernel_path = optarg; break;
		case 'd': dtb_path = optarg; break;
		case 'o': out_path = optarg; break;
		default: usage(argv[0]); return 1;
		}
	}
	if (!loader_path || !kernel_path || !dtb_path || !out_path) {
		usage(argv[0]);
		return 1;
	}

	loader = file_read(loader_path, &loader_len);
	kernel = file_read(kernel_path, &kernel_len);
	dtb = file_read(dtb_path, &dtb_len);
	if (!loader || !kernel || !dtb)
		goto out;

	if (loader_len & 0xf) {
		fprintf(stderr, "loader is not 16-byte aligned (%zu bytes)\n",
			loader_len);
		goto out;
	}

	ksz = round_up(kernel_len, 16);
	dsz = round_up(dtb_len, 16);
	blob_len = ARM64_HDR_SIZE + loader_len + sizeof(szhdr) + ksz + dsz;

	memset(stub, 0, sizeof(stub));
	put_le32(stub + 0x00, ARM64_CODE0_B_LOADER);
	put_le64(stub + 0x10, blob_len);
	put_le64(stub + 0x18, ARM64_FLAGS);
	put_le32(stub + 0x38, ARM64_MAGIC);

	put_le64(szhdr + 0, ksz);
	put_le64(szhdr + 8, dsz);

	memset(hdr, 0, sizeof(hdr));
	memcpy(hdr, BOOT_MAGIC, BOOT_MAGIC_SIZE);
	put_le32(hdr + 8, blob_len);
	put_le32(hdr + 20, BOOT_HDR_V3_SIZE);
	put_le32(hdr + 40, BOOT_HDR_VERSION);

	out = fopen(out_path, "wb");
	if (!out) {
		fprintf(stderr, "cannot create %s: %s\n", out_path,
			strerror(errno));
		goto out;
	}
	if (fwrite(hdr, 1, sizeof(hdr), out) != sizeof(hdr) ||
	    blob_write(out, stub, sizeof(stub), sizeof(stub)) ||
	    blob_write(out, loader, loader_len, loader_len) ||
	    blob_write(out, szhdr, sizeof(szhdr), sizeof(szhdr)) ||
	    blob_write(out, kernel, kernel_len, ksz) ||
	    blob_write(out, dtb, dtb_len, dsz) ||
	    blob_write(out, NULL, 0,
		       round_up(blob_len, BOOT_PAGE_SIZE) - blob_len)) {
		fprintf(stderr, "cannot write %s: %s\n", out_path,
			strerror(errno));
		goto out;
	}
	ret = 0;
out:
	if (out)
		fclose(out);
	free(loader);
	free(kernel);
	free(dtb);
	return ret;
}
