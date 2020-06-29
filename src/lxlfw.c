// SPDX-License-Identifier: GPL-2.0-or-later OR MIT
/*
 * Luxul's firmware container format
 *
 * Copyright 2020 Legrand AV Inc.
 */

#define _GNU_SOURCE

#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <libgen.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le32(x)	bswap_32(x)
#define cpu_to_le16(x)	bswap_16(x)
#define le32_to_cpu(x)	bswap_32(x)
#define le16_to_cpu(x)	bswap_16(x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le32(x)	(x)
#define cpu_to_le16(x)	(x)
#define le32_to_cpu(x)	(x)
#define le16_to_cpu(x)	(x)
#endif

#define min(a, b)				\
	({					\
		__typeof__ (a) _a = (a);	\
		__typeof__ (b) _b = (b);	\
		_a < _b ? _a : _b;		\
	})

#define max(a, b)				\
	({					\
		__typeof__ (a) _a = (a);	\
		__typeof__ (b) _b = (b);	\
		_a > _b ? _a : _b;		\
	})

#define MAX_SUPPORTED_VERSION			3

#define LXL_FLAGS_VENDOR_LUXUL			0x00000001

#define LXL_BLOB_CERTIFICATE			0x0001
#define LXL_BLOB_SIGNATURE			0x0002

struct lxl_hdr {
	char		magic[4];	/* "LXL#" */
	uint32_t	version;
	uint32_t	hdr_len;
	uint8_t		v0_end[0];
	/* Version: 1+ */
	uint32_t	flags;
	char		board[16];
	uint8_t		v1_end[0];
	/* Version: 2+ */
	uint8_t		release[4];
	uint8_t		v2_end[0];
	/* Version: 3+ */
	uint32_t	blobs_offset;
	uint32_t	blobs_len;
	uint8_t		v3_end[0];
} __attribute__((packed));

struct lxl_blob {
	char		magic[2];	/* "D#" */
	uint16_t	type;
	uint32_t	len;
	uint8_t		data[0];
} __attribute__((packed));

/**************************************************
 * Helpers
 **************************************************/

static uint32_t lxlfw_hdr_len(uint32_t version)
{
	switch (version) {
	case 0:
		return offsetof(struct lxl_hdr, v0_end);
	case 1:
		return offsetof(struct lxl_hdr, v1_end);
	case 2:
		return offsetof(struct lxl_hdr, v2_end);
	case 3:
		return offsetof(struct lxl_hdr, v3_end);
	default:
		fprintf(stderr, "Unsupported version %d\n", version);
		return 0;
	}
}

/**
 * lxlfw_open - open Luxul firmware file and validate it
 *
 * @pathname: Luxul firmware file
 * @hdr: struct to read to
 */
static FILE *lxlfw_open(const char *pathname, struct lxl_hdr *hdr)
{
	size_t v0_len = lxlfw_hdr_len(0);
	size_t min_hdr_len;
	uint32_t version;
	uint32_t hdr_len;
	size_t bytes;
	FILE *lxl;

	lxl = fopen(pathname, "r");
	if (!lxl) {
		fprintf(stderr, "Could not open \"%s\" file\n", pathname);
		goto err_out;
	}

	bytes = fread(hdr, 1, v0_len, lxl);
	if (bytes != v0_len) {
		fprintf(stderr, "Input file too small to use Luxul format\n");
		goto err_close;
	}

	if (memcmp(hdr->magic, "LXL#", 4)) {
		fprintf(stderr, "File <file> does not use Luxul's format\n");
		goto err_close;
	}

	version = le32_to_cpu(hdr->version);

	min_hdr_len = lxlfw_hdr_len(min(version, MAX_SUPPORTED_VERSION));

	bytes = fread(((uint8_t *)hdr) + v0_len, 1, min_hdr_len - v0_len, lxl);
	if (bytes != min_hdr_len - v0_len) {
		fprintf(stderr, "Input file too small for header version %d\n", version);
		goto err_close;
	}

	hdr_len = le32_to_cpu(hdr->hdr_len);

	if (hdr_len < min_hdr_len) {
		fprintf(stderr, "Header length mismatch: 0x%x (expected: 0x%zx)\n", hdr_len, min_hdr_len);
		goto err_close;
	}

	if (version >= 3 && hdr->blobs_offset && hdr->blobs_len) {
		uint32_t blobs_end = le32_to_cpu(hdr->blobs_offset) + le32_to_cpu(hdr->blobs_len);

		if (blobs_end > hdr_len) {
			fprintf(stderr, "Blobs section ends beyond header end: 0x%x (max: 0x%x)\n", blobs_end, hdr_len);
			goto err_close;
		}
	}

	return lxl;

err_close:
	fclose(lxl);
err_out:
	return NULL;
}

/**
 * lxlfw_copy_data - read data from one stream and write to another
 *
 * @from: input stream
 * @to: output stream
 * @size: amount of bytes to copy (0 to copy all data)
 */
static ssize_t lxlfw_copy_data(FILE *from, FILE *to, size_t size)
{
	int copy_all = size == 0;
	char buf[512];
	size_t ret = 0;

	while (copy_all || size) {
		size_t to_read = copy_all ? sizeof(buf) : min(size, sizeof(buf));
		size_t bytes;

		bytes = fread(buf, 1, to_read, from);
		if (bytes == 0 && copy_all) {
			break;
		} else if (bytes <= 0) {
			fprintf(stderr, "Failed to read data\n");
			return -EIO;
		}

		if (fwrite(buf, 1, bytes, to) != bytes) {
			fprintf(stderr, "Failed to write data\n");
			return -EIO;
		}

		if (!copy_all)
			size -= bytes;
		ret += bytes;
	}

	return ret;
}

/**
 * lxlfw_write_blob - read data from external file and write blob to stream
 *
 * @lxl: stream to write to
 * @type: blob type
 * @pathname: external file pathname to read blob data from
 */
static ssize_t lxlfw_write_blob(FILE *lxl, uint16_t type, const char *pathname)
{
	struct lxl_blob blob = {
		.magic = { 'D', '#' },
		.type = cpu_to_le16(type),
	};
	char buf[512];
	size_t blob_data_len;
	size_t bytes;
	FILE *data;

	data = fopen(pathname, "r");
	if (!data) {
		fprintf(stderr, "Could not open input file %s\n", pathname);
		return -EIO;
	}

	blob_data_len = 0;
	fseek(lxl, sizeof(blob), SEEK_CUR);
	while ((bytes = fread(buf, 1, sizeof(buf), data)) > 0) {
		if (fwrite(buf, 1, bytes, lxl) != bytes) {
			fprintf(stderr, "Could not copy %zu bytes from input file\n", bytes);
			fclose(data);
			return -EIO;
		}
		blob_data_len += bytes;
	}

	fclose(data);

	blob.len = cpu_to_le32(blob_data_len);

	fseek(lxl, -(blob_data_len + sizeof(blob)), SEEK_CUR);
	bytes = fwrite(&blob, 1, sizeof(blob), lxl);
	if (bytes != sizeof(blob)) {
		fprintf(stderr, "Could not write Luxul's header\n");
		return -EIO;
	}

	fseek(lxl, blob_data_len, SEEK_CUR);

	return blob_data_len + sizeof(blob);
}

/**************************************************
 * Info
 **************************************************/

static int lxlfw_info(int argc, char **argv) {
	struct lxl_hdr hdr;
	uint32_t version;
	char board[17];
	int err = 0;
	FILE *lxl;
	int flags;

	if (argc < 3) {
		fprintf(stderr, "Missing <file> argument\n");
		err = -EINVAL;
		goto out;
	}

	lxl = lxlfw_open(argv[2], &hdr);
	if (!lxl) {
		fprintf(stderr, "Could not open \"%s\" Luxul firmware\n", argv[2]);
		err = -ENOENT;
		goto out;
	}

	version = le32_to_cpu(hdr.version);

	printf("Format version:\t%d\n", version);
	printf("Header length:\t%d\n", le32_to_cpu(hdr.hdr_len));
	if (version >= 1) {
		printf("Flags:\t\t");
		flags = le32_to_cpu(hdr.flags);
		if (flags & LXL_FLAGS_VENDOR_LUXUL)
			printf("VENDOR_LUXUL ");
		printf("\n");
		memcpy(board, hdr.board, sizeof(hdr.board));
		board[16] = '\0';
		printf("Board:\t\t%s\n", board);
	}
	if (version >= 2) {
		printf("Release:\t");
		if (hdr.release[0] || hdr.release[1] || hdr.release[2] || hdr.release[3]) {
			printf("%hu.%hu.%hu", hdr.release[0], hdr.release[1], hdr.release[2]);
			if (hdr.release[3])
				printf(".%hu", hdr.release[3]);
		}
		printf("\n");
	}
	if (version >= 3) {
		printf("Blobs offset:\t%d\n", le32_to_cpu(hdr.blobs_offset));
		printf("Blobs length:\t%d\n", le32_to_cpu(hdr.blobs_len));
	}

	if (version >= 3 && hdr.blobs_offset) {
		size_t offset;

		fseek(lxl, le32_to_cpu(hdr.blobs_offset), SEEK_SET);
		for (offset = 0; offset < le32_to_cpu(hdr.blobs_len); ) {
			struct lxl_blob blob;
			size_t bytes;
			size_t len;

			bytes = fread(&blob, 1, sizeof(blob), lxl);
			if (bytes != sizeof(blob)) {
				fprintf(stderr, "Failed to read blob section\n");
				err = -ENXIO;
				goto err_close;
			}

			len = le32_to_cpu(blob.len);

			printf("\n");
			printf("Blob\n");
			printf("Magic:\t\t%s\n", blob.magic);
			printf("Type:\t\t0x%04x\n", le16_to_cpu(blob.type));
			printf("Length:\t\t%zu\n", len);

			offset += sizeof(blob) + len;
			fseek(lxl, len, SEEK_CUR);
		}

		if (offset != le32_to_cpu(hdr.blobs_len)) {
			printf("\n");
			fprintf(stderr, "Blobs size (0x%zx) doesn't match declared length (0x%x)\n", offset, le32_to_cpu(hdr.blobs_len));
		}
	}

err_close:
	fclose(lxl);
out:
	return err;
}

/**************************************************
 * Extract
 **************************************************/

static int lxlfw_extract(int argc, char **argv) {
	struct lxl_hdr hdr;
	char *out_path = NULL;
	ssize_t bytes;
	int err = 0;
	FILE *lxl;
	FILE *out;
	int c;

	if (argc < 3) {
		fprintf(stderr, "Missing <file> argument\n");
		err = -EINVAL;
		goto out;
	}

	optind = 3;
	while ((c = getopt(argc, argv, "O:")) != -1) {
		switch (c) {
		case 'O':
			out_path = optarg;
			break;
		}
	}

	if (!out_path) {
		fprintf(stderr, "Missing output file path\n");
		err = -EINVAL;
		goto out;
	}

	lxl = lxlfw_open(argv[2], &hdr);
	if (!lxl) {
		fprintf(stderr, "Failed to open \"%s\" Luxul firmware\n", argv[2]);
		err = -ENOENT;
		goto out;
	}

	fseek(lxl, le32_to_cpu(hdr.hdr_len), SEEK_SET);

	if (!strcmp(out_path, "-")) {
		out = stdout;
	} else {
		out = fopen(out_path, "w+");
		if (!out) {
			fprintf(stderr, "Failed to open \"%s\" file\n", out_path);
			err = -EIO;
			goto err_close_lxl;
		}
	}

	bytes = lxlfw_copy_data(lxl, out, 0);
	if (bytes < 0) {
		fprintf(stderr, "Failed to copy image: %zd\n", bytes);
		err = -EIO;
		goto err_close_lxl;
	}

	if (out != stdout) {
		fclose(out);
	}

err_close_lxl:
	fclose(lxl);
out:
	return err;
}

/**************************************************
 * Blobs
 **************************************************/

/**
 * lxlfw_blob_save - save blob data to external file
 *
 * @lxl: Luxul firmware FILE with position seeked to blob data
 * @len: blob data length
 * @path: external file pathname to write
 */
static int lxlfw_blob_save(FILE *lxl, size_t len, const char *path) {
	char buf[256];
	size_t bytes;
	FILE *out;
	int err = 0;

	out = fopen(path, "w+");
	if (!out) {
		fprintf(stderr, "Could not open \"%s\" file\n", path);
		err = -EIO;
		goto err_out;
	}

	while (len && (bytes = fread(buf, 1, min(len, sizeof(buf)), lxl)) > 0) {
		if (fwrite(buf, 1, bytes, out) != bytes) {
			fprintf(stderr, "Could not copy %zu bytes from input file\n", bytes);
			err = -EIO;
			goto err_close_out;
		}
		len -= bytes;
	}

	if (len) {
		fprintf(stderr, "Could not copy all signature\n");
		err = -EIO;
		goto err_close_out;
	}

err_close_out:
	fclose(out);
err_out:
	return err;
}

static int lxlfw_blobs(int argc, char **argv) {
	char *certificate_path = NULL;
	char *signature_path = NULL;
	struct lxl_hdr hdr;
	uint32_t version;
	size_t offset;
	size_t bytes;
	int err = 0;
	FILE *lxl;
	int c;

	if (argc < 3) {
		fprintf(stderr, "Missing <file> argument\n");
		err = -EINVAL;
		goto out;
	}

	optind = 3;
	while ((c = getopt(argc, argv, "c:s:")) != -1) {
		switch (c) {
		case 'c':
			certificate_path = optarg;
			break;
		case 's':
			signature_path = optarg;
			break;
		}
	}

	if (!certificate_path && !signature_path) {
		fprintf(stderr, "Missing info on blobs to extract\n");
		err = -EINVAL;
		goto out;
	}

	lxl = lxlfw_open(argv[2], &hdr);
	if (!lxl) {
		fprintf(stderr, "Failed to open \"%s\" Luxul firmware\n", argv[2]);
		err = -ENOENT;
		goto out;
	}

	version = le32_to_cpu(hdr.version);

	if (version < 3 || !hdr.blobs_offset) {
		fprintf(stderr, "File <file> doesn't contain any blobs\n");
		err = -ENOENT;
		goto err_close;
	}

	fseek(lxl, le32_to_cpu(hdr.blobs_offset), SEEK_SET);
	for (offset = 0; offset < le32_to_cpu(hdr.blobs_len); ) {
		struct lxl_blob blob;
		uint16_t type;
		size_t len;

		bytes = fread(&blob, 1, sizeof(blob), lxl);
		if (bytes != sizeof(blob)) {
			fprintf(stderr, "Failed to read blob section\n");
			err = -ENXIO;
			goto err_close;
		}
		offset += bytes;

		if (memcmp(blob.magic, "D#", 2)) {
			fprintf(stderr, "Failed to parse blob section\n");
			err = -ENXIO;
			goto err_close;
		}

		type = le16_to_cpu(blob.type);
		len = le32_to_cpu(blob.len);

		if (type == LXL_BLOB_CERTIFICATE && certificate_path) {
			err = lxlfw_blob_save(lxl, len, certificate_path);
			certificate_path = NULL;
		} else if (type == LXL_BLOB_SIGNATURE && signature_path) {
			err = lxlfw_blob_save(lxl, len, signature_path);
			signature_path = NULL;
		} else {
			fseek(lxl, len, SEEK_CUR);
		}
		if (err) {
			fprintf(stderr, "Failed to save blob section\n");
			goto err_close;
		}
		offset += len;
	}

	if (certificate_path) {
		fprintf(stderr, "Failed to find certificate blob\n");
		err = -ENOENT;
	}
	if (signature_path) {
		fprintf(stderr, "Failed to find signature blob\n");
		err = -ENOENT;
	}

err_close:
	fclose(lxl);
out:
	return err;
}

/**************************************************
 * Create
 **************************************************/

static int lxlfw_create(int argc, char **argv) {
	struct lxl_hdr hdr = {
		.magic = { 'L', 'X', 'L', '#' },
	};
	char *certificate_path = NULL;
	char *signature_path = NULL;
	char *in_path = NULL;
	uint32_t version = 0;
	uint32_t hdr_raw_len;	/* Header length without blobs */
	uint32_t hdr_len;	/* Header length with blobs */
	uint32_t blobs_len;
	ssize_t bytes;
	int err = 0;
	FILE *lxl;
	FILE *in;
	int c;

	if (argc < 3) {
		fprintf(stderr, "Missing <file> argument\n");
		err = -EINVAL;
		goto out;
	}

	optind = 3;
	while ((c = getopt(argc, argv, "i:lb:r:")) != -1) {
		switch (c) {
		case 'i':
			in_path = optarg;
			break;
		case 'l':
			hdr.flags |= cpu_to_le32(LXL_FLAGS_VENDOR_LUXUL);
			version = max(version, 1);
			break;
		case 'b':
			memcpy(hdr.board, optarg, strlen(optarg) > 16 ? 16 : strlen(optarg));
			version = max(version, 1);
			break;
		case 'r':
			if (sscanf(optarg, "%hhu.%hhu.%hhu.%hhu", &hdr.release[0], &hdr.release[1], &hdr.release[2], &hdr.release[3]) < 1) {
				fprintf(stderr, "Failed to parse release number \"%s\"\n", optarg);
				err = -EINVAL;
				goto out;
			}
			version = max(version, 2);
			break;
		case 'c':
			certificate_path = optarg;
			version = max(version, 3);
			break;
		case 's':
			signature_path = optarg;
			version = max(version, 3);
			break;
		}
	}

	hdr_raw_len = lxlfw_hdr_len(version);
	hdr_len = hdr_raw_len;

	if (!in_path) {
		fprintf(stderr, "Missing input file argument\n");
		err = -EINVAL;
		goto out;
	}

	in = fopen(in_path, "r");
	if (!in) {
		fprintf(stderr, "Could not open input file %s\n", in_path);
		err = -EIO;
		goto out;
	}

	lxl = fopen(argv[2], "w+");
	if (!lxl) {
		fprintf(stderr, "Could not open \"%s\" file\n", argv[2]);
		err = -EIO;
		goto err_close_in;
	}

	/* Write blobs */

	blobs_len = 0;

	fseek(lxl, hdr_raw_len, SEEK_SET);
	if (certificate_path) {
		bytes = lxlfw_write_blob(lxl, LXL_BLOB_CERTIFICATE, certificate_path);
		if (bytes <= 0) {
			fprintf(stderr, "Failed to write certificate\n");
			goto err_close_lxl;
		}
		blobs_len += bytes;
	}
	if (signature_path) {
		bytes = lxlfw_write_blob(lxl, LXL_BLOB_SIGNATURE, signature_path);
		if (bytes <= 0) {
			fprintf(stderr, "Failed to write signature\n");
			goto err_close_lxl;
		}
		blobs_len += bytes;
	}

	if (blobs_len) {
		hdr.blobs_offset = cpu_to_le32(hdr_raw_len);
		hdr.blobs_len = cpu_to_le32(blobs_len);
		hdr_len += blobs_len;
	}

	/* Write header */

	hdr.version = cpu_to_le32(version);
	hdr.hdr_len = cpu_to_le32(hdr_len);

	fseek(lxl, 0, SEEK_SET);
	bytes = fwrite(&hdr, 1, hdr_raw_len, lxl);
	if (bytes != hdr_raw_len) {
		fprintf(stderr, "Could not write Luxul's header\n");
		err = -EIO;
		goto err_close_lxl;
	}

	/* Write input data */

	fseek(lxl, 0, SEEK_END);
	bytes = lxlfw_copy_data(in, lxl, 0);
	if (bytes < 0) {
		fprintf(stderr, "Could not copy %zu bytes from input file\n", bytes);
		err = -EIO;
		goto err_close_lxl;
	}

err_close_lxl:
	fclose(lxl);
err_close_in:
	fclose(in);
out:
	return err;
}

/**************************************************
 * Insert
 **************************************************/

static int lxlfw_insert(int argc, char **argv) {
	struct lxl_hdr hdr = { };
	char *certificate_path = NULL;
	char *signature_path = NULL;
	char *tmp_path = NULL;
	uint32_t version = 0;
	uint32_t hdr_raw_len;	/* Header length without blobs */
	uint32_t hdr_len;	/* Header length with blobs */
	uint32_t blobs_len;
	ssize_t bytes;
	char *path;
	FILE *lxl;
	FILE *tmp;
	int fd;
	int c;
	int err = 0;

	if (argc < 3) {
		fprintf(stderr, "Missing <file> argument\n");
		err = -EINVAL;
		goto out;
	}

	optind = 3;
	while ((c = getopt(argc, argv, "c:s:")) != -1) {
		switch (c) {
		case 'c':
			certificate_path = optarg;
			break;
		case 's':
			signature_path = optarg;
			break;
		}
	}

	if (!certificate_path && !signature_path) {
		fprintf(stderr, "Missing info on blobs to insert\n");
		err = -EINVAL;
		goto out;
	}

	lxl = lxlfw_open(argv[2], &hdr);
	if (!lxl) {
		fprintf(stderr, "Failed to open \"%s\" Luxul firmware\n", argv[2]);
		err = -ENOENT;
		goto out;
	}

	version = le32_to_cpu(hdr.version);
	if (version > MAX_SUPPORTED_VERSION) {
		fprintf(stderr, "Unsupported <file> version %d\n", version);
		err = -EIO;
		goto err_close_lxl;
	}

	version = max(version, 3);

	hdr_raw_len = lxlfw_hdr_len(version);
	hdr_len = hdr_raw_len;

	/* Temporary file */

	path = strdup(argv[2]);
	if (!path) {
		err = -ENOMEM;
		goto err_close_lxl;
	}
	asprintf(&tmp_path, "%s/lxlfwXXXXXX", dirname(path));
	free(path);
	if (!tmp_path) {
		err = -ENOMEM;
		goto err_close_lxl;
	}

	fd = mkstemp(tmp_path);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to open temporary file\n");
		goto err_free_path;
	}
	tmp = fdopen(fd, "w+");

	/* Blobs */

	fseek(tmp, hdr_raw_len, SEEK_SET);
	blobs_len = 0;

	/* Copy old blobs */

	if (hdr.blobs_offset) {
		size_t offset;

		fseek(lxl, le32_to_cpu(hdr.blobs_offset), SEEK_SET);
		for (offset = 0; offset < le32_to_cpu(hdr.blobs_len); ) {
			struct lxl_blob blob;
			uint16_t type;
			size_t len;

			bytes = fread(&blob, 1, sizeof(blob), lxl);
			if (bytes != sizeof(blob)) {
				fprintf(stderr, "Failed to read blob section\n");
				err = -ENXIO;
				goto err_close_tmp;
			}

			type = le16_to_cpu(blob.type);
			len = le32_to_cpu(blob.len);

			/* Don't copy blobs that have to be replaced */
			if ((type == LXL_BLOB_CERTIFICATE && certificate_path) ||
			    (type == LXL_BLOB_SIGNATURE && signature_path)) {
				fseek(lxl, len, SEEK_CUR);
			} else {
				fseek(lxl, -sizeof(blob), SEEK_CUR);
				bytes = lxlfw_copy_data(lxl, tmp, sizeof(blob) + len);
				if (bytes != sizeof(blob) + len) {
					fprintf(stderr, "Failed to copy original blob\n");
					err = -EIO;
					goto err_close_tmp;
				}
				blobs_len += sizeof(blob) + len;
			}

			offset += sizeof(blob) + len;
		}
	}

	/* Write new blobs */

	if (certificate_path) {
		bytes = lxlfw_write_blob(tmp, LXL_BLOB_CERTIFICATE, certificate_path);
		if (bytes <= 0) {
			fprintf(stderr, "Failed to write certificate\n");
			goto err_close_tmp;
		}
		blobs_len += bytes;
	}
	if (signature_path) {
		bytes = lxlfw_write_blob(tmp, LXL_BLOB_SIGNATURE, signature_path);
		if (bytes <= 0) {
			fprintf(stderr, "Failed to write signature\n");
			goto err_close_tmp;
		}
		blobs_len += bytes;
	}

	hdr.blobs_offset = cpu_to_le32(hdr_raw_len);
	hdr.blobs_len = cpu_to_le32(blobs_len);
	hdr_len += blobs_len;

	/* Write header */

	hdr.version = cpu_to_le32(version);
	hdr.hdr_len = cpu_to_le32(hdr_len);

	fseek(tmp, 0, SEEK_SET);
	bytes = fwrite(&hdr, 1, hdr_raw_len, tmp);
	if (bytes != hdr_raw_len) {
		fprintf(stderr, "Could not write Luxul's header\n");
		err = -EIO;
		goto err_close_tmp;
	}

	/* Write original data */

	fseek(tmp, 0, SEEK_END);
	bytes = lxlfw_copy_data(lxl, tmp, 0);
	if (bytes < 0) {
		fprintf(stderr, "Failed to copy original file\n");
		err = -EIO;
		goto err_close_tmp;
	}

	fclose(tmp);

	fclose(lxl);

	/* Replace original file */

	if (rename(tmp_path, argv[2])) {
		err = -errno;
		fprintf(stderr, "Failed to rename %s: %d\n", tmp_path, err);
		unlink(tmp_path);
		goto out;
	}

	return 0;

err_close_tmp:
	fclose(tmp);
err_free_path:
	free(tmp_path);
err_close_lxl:
	fclose(lxl);
out:
	return err;
}

/**************************************************
 * Start
 **************************************************/

static void usage() {
	printf("Usage:\n");
	printf("\n");
	printf("Get info about Luxul firmware:\n");
	printf("\tlxlfw info <file>\n");
	printf("\n");
	printf("Extract image from Luxul firmware:\n");
	printf("\tlxlfw extract <file> [options]\n");
	printf("\t-O file\t\t\t\toutput file (- for stdout)\n");
	printf("\n");
	printf("Extract blobs from Luxul firmware:\n");
	printf("\tlxlfw blobs <file> [options]\n");
	printf("\t-c file\t\t\t\tcertificate output file\n");
	printf("\t-s file\t\t\t\tsignature output file\n");
	printf("\n");
	printf("Create new Luxul firmware:\n");
	printf("\tlxlfw create <file> [options]\n");
	printf("\t-i file\t\t\t\tinput file for Luxul's firmware container\n");
	printf("\t-l\t\t\t\tmark firmware as created by Luxul company (DON'T USE)\n");
	printf("\t-b board\t\t\tboard (device) name\n");
	printf("\t-r release\t\t\trelease number (e.g. 5.1.0, 7.1.0.2)\n");
	printf("\t-c file\t\t\t\tcertificate file\n");
	printf("\t-s file\t\t\t\tsignature file\n");
	printf("\n");
	printf("Insert blob to Luxul firmware:\n");
	printf("\tlxlfw insert <file> [options]\n");
	printf("\t-c file\t\t\t\tcertificate file\n");
	printf("\t-s file\t\t\t\tsignature file\n");

}

int main(int argc, char **argv) {
	if (argc > 1) {
		if (!strcmp(argv[1], "info"))
			return lxlfw_info(argc, argv);
		else if (!strcmp(argv[1], "extract"))
			return lxlfw_extract(argc, argv);
		else if (!strcmp(argv[1], "blobs"))
			return lxlfw_blobs(argc, argv);
		else if (!strcmp(argv[1], "create"))
			return lxlfw_create(argc, argv);
		else if (!strcmp(argv[1], "insert"))
			return lxlfw_insert(argc, argv);
	}

	usage();
	return 0;
}
