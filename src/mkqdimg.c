// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Coia Prant <coiaprant@gmail.com>
 *
 * The golang version can be found at:
 * <https://gitlab.com/CoiaPrant/mkqdimg>
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <libgen.h>
#include <getopt.h>
#include <errno.h>
#include <endian.h>

#include "sha1.h"

#define HDR_PADDING_BYTE	0x00
#define PADDING_BYTE		0xff

#define MAX_LENGTH		16647168
#define BOARD_ID_LENGTH		8
#define VERSION_LENGTH		8
#define UBOOT_LENGTH		196608

#define HDR_LENGTH		0x00000400
#define HDR_OFF_BOARD_ID	0
#define HDR_OFF_VERSION		8
#define HDR_OFF_UBOOT		16
#define HDR_OFF_FIRMWARE	32
#define HDR_OFF_MAGIC		48
#define HDR_OFF_CHECKSUM	52
#define HDR_OFF_UBOOT_LEN	72
#define HDR_OFF_FIRMWARE_LEN	76
#define HDR_MAGIC		538248722

/*
 * Globals
 */
static char *progname;

/*
 * Message macros
 */
#define ERR(fmt, ...) do { \
	fflush(0); \
	fprintf(stderr, "[%s] *** error: " fmt "\n", \
			progname, ## __VA_ARGS__); \
} while (0)

#define ERRS(fmt, ...) do { \
	int save = errno; \
	fflush(0); \
	fprintf(stderr, "[%s] *** error: " fmt "\n", \
			progname, ## __VA_ARGS__, strerror(save)); \
} while (0)

static void usage(int status)
{
	FILE *stream = (status != EXIT_SUCCESS) ? stderr : stdout;

	fprintf(stream, "Usage: %s [OPTIONS...]\n", progname);
	fprintf(stream,
"\n"
"Options:\n"
"  -B <board>      create image for the board specified with <board>\n"
"  -V <version>    version string\n"
"  -u <file>       read uboot image from the file <file>\n"
"  -f <file>       read firmware image from the file <file>\n"
"  -o <file>       write output to the file <file>\n"
"  -h              show this screen\n"
	);

	exit(status);
}

void writele(unsigned char *buf, size_t offset, uint32_t value)
{
	value = htole32(value);
	memcpy(buf + offset, &value, sizeof(uint32_t));
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	long ulen, flen, buflen = HDR_LENGTH, fspace;
	unsigned char *buf;
	char *board_id = NULL, *version = NULL, *ufname = NULL, *ffname = NULL, *ofname = NULL;
	FILE *out, *uboot = NULL, *firmware = NULL;

	progname = basename(argv[0]);

	while (1) {
		int c;

		c = getopt(argc, argv, "B:V:u:f:o:h");
		if (c == -1)
			break;

		switch (c) {
		case 'B':
			board_id = optarg;
			break;
		case 'V':
			version = optarg;
			break;
		case 'u':
			ufname = optarg;
			break;
		case 'f':
			ffname = optarg;
			break;
		case 'o':
			ofname = optarg;
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		default:
			usage(EXIT_FAILURE);
			break;
		}
	}

	if (board_id == NULL) {
		ERR("no board specified");
		goto err;
	}

	if (strlen(board_id) > BOARD_ID_LENGTH) {
		ERR("board_id \"%s\" is too long - max length: 8\n",
		    board_id);
		goto err;
	}

	if (version != NULL && strlen(version) > VERSION_LENGTH) {
		ERR("version \"%s\" is too long - max length: 8\n",
		    version);
		goto err;
	}

	if (ofname == NULL) {
		ERR("no output file specified");
		goto err;
	}

	if (ufname != NULL) {
		uboot = fopen(ufname, "r");
		if (uboot == NULL) {
			ERRS("could not open \"%s\" for reading: %s", ufname);
			goto err;
		}

		/* Get uboot length */
		fseek(uboot, 0, SEEK_END);
		ulen = ftell(uboot);
		rewind(uboot);

		if (ulen > UBOOT_LENGTH) {
			fclose(uboot);
			ERR("file \"%s\" is too big - max size: 0x%08d\n",
		  	  ufname, UBOOT_LENGTH);
			goto err;
		}

		buflen += UBOOT_LENGTH;
	}

	if (ffname != NULL) {
		firmware = fopen(ffname, "r");
		if (firmware == NULL) {
			ERRS("could not open \"%s\" for reading: %s", ffname);
			goto err;
		}

		/* Get firmware length */
		fseek(firmware, 0, SEEK_END);
		flen = ftell(firmware);
		rewind(firmware);

		fspace = MAX_LENGTH - buflen;
		if (flen > fspace) {
			ERR("file \"%s\" is too big - max size: 0x%08ld\n",
		  	  ffname, fspace);
			goto err_close;
		}

		buflen += flen;
	}

	/* Allocate and initialize buffer for final image */
	buf = malloc(buflen);
	if (buf == NULL) {
		ERRS("no memory for buffer: %s\n");
		goto err_close;
	}
	memset(buf, HDR_PADDING_BYTE, HDR_LENGTH);
	memset(buf + HDR_LENGTH, PADDING_BYTE, buflen - HDR_LENGTH);

	/* Write board id */
	memcpy(buf + HDR_OFF_BOARD_ID, board_id, strlen(board_id));

	/* Write version */
	if (version != NULL) {
		memcpy(buf + HDR_OFF_VERSION, version, strlen(version));
	}

	if (uboot != NULL) {
		/* Write UBOOT ID */
		memcpy(buf + HDR_OFF_UBOOT, "UBOOT", 5);

		/* Load U-Boot */
		fread(buf + HDR_LENGTH, ulen, 1, uboot);

		/* Write U-Boot Length */
		writele(buf, HDR_OFF_UBOOT_LEN, UBOOT_LENGTH);
	}

	if (firmware != NULL) {
		/* Write FIRMWARE ID */
		memcpy(buf + HDR_OFF_FIRMWARE, "FIRMWARE", 8);

		/* Load Firmware */
		if (uboot != NULL) {
			fread(buf + HDR_LENGTH + UBOOT_LENGTH, flen, 1, firmware);
		} else {
			fread(buf + HDR_LENGTH, flen, 1, firmware);
		}

		/* Write Firmware Length */
		writele(buf, HDR_OFF_FIRMWARE_LEN, flen);
	}

	/* Write magic */
	writele(buf, HDR_OFF_MAGIC, HDR_MAGIC);

	/* Write checksum and static hash */
	sha1_csum(buf + HDR_LENGTH, buflen - HDR_LENGTH, buf + HDR_OFF_CHECKSUM);

	/* Save finished image */
	out = fopen(ofname, "w");
	if (out == NULL) {
		ERRS("could not open \"%s\" for writing: %s", ofname);
		goto err_free;
	}
	fwrite(buf, buflen, 1, out);

	ret = EXIT_SUCCESS;

	fclose(out);

err_free:
	free(buf);

err_close:
	if (uboot != NULL) {
		fclose(uboot);
	}

	if (firmware != NULL) {
		fclose(firmware);
	}

err:
	return ret;
}
