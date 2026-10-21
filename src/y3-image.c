// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Assemble an OpenWrt image for the legacy Inteno/Genexis Y3 updater.
 *
 * Version 8 consists of a 1024-byte, NUL-padded text header, payloads and
 * a 32-byte lowercase ASCII MD5 of everything before the checksum.
 * Offsets are absolute file offsets; sizes and offsets are decimal.
 *
 * This utility wraps an already assembled UBI image (see ubinize). It
 * deliberately emits no CFE ROM or rescue payload. The singlepureubi CFE
 * updater replaces the UBI area while keeping the existing loader code.
 * That updater can still rewrite NVRAM in the loader partition: cfe 0
 * does NOT guarantee that the entire loader partition remains untouched.
 *
 * On XG6846B, the UBI image must retain the original cferam.000 in the
 * kernel_0 boot bundle, alongside vmlinux.lz and 96846.dtb. The metadata
 * volumes and boot bundle use Broadcom formats, not ordinary filesystems.
 * Kernel wrapping, boot metadata and UBI geometry belong to the board's
 * image recipe. This tool neither reformats nor edits the supplied UBI.
 */

#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "md5.h"

#define Y3_HEADER_SIZE		1024
/* The legacy CFE tag scanner stops short of the end of the header. */
#define Y3_HEADER_TEXT_MAX	1004
#define Y3_MD5_SIZE		32
#define Y3_DEFAULT_MAX_SIZE	0x03a20000
#define UBI_EC_HEADER_SIZE	64

struct y3_options {
	const char *input;
	const char *output;
	const char *chip;
	const char *model;
	const char *arch;
	const char *release;
	const char *customer;
	const char *revision;
	uint32_t max_size;
};

static void usage(FILE *stream, const char *prog)
{
	fprintf(stream,
		"Usage: %s -i <ubi> -o <y3> -c <chip> -m <model> -a <arch> [options]\n"
		"\n"
		"  -i <file>    Prepared UBI image containing kernel and rootfs\n"
		"  -o <file>    Output Y3 image\n"
		"  -c <id>      Chip ID as printed by CFE, e.g. 6846 or 63138\n"
		"  -m <string>  Model identifier(s), e.g. PANTHER\n"
		"  -a <string>  Architecture identifier(s), e.g. 'all arm_xscale'\n"
		"  -r <string>  Release (default: OpenWrt)\n"
		"  -u <string>  Customer identifier (default: OpenWrt)\n"
		"  -g <string>  Source revision (default: unknown)\n"
		"  -s <bytes>   Maximum total size, decimal or 0x-prefixed\n"
		"              (default: 0x03a20000, the XG6846B CFE limit)\n"
		"  -h           Show this help\n"
		"\n"
		"Creates version 8 singlepureubi/bpartit32 images with no CFE ROM\n"
		"or rescue payload. The UBI boot bundle must retain CFE RAM where\n"
		"required. CFE may still update NVRAM. See docs/y3-image.md.\n",
		prog);
}

static int valid_text(const char *name, const char *value)
{
	const unsigned char *p = (const unsigned char *)value;

	if (value && *value) {
		for (; *p; p++) {
			if (*p < ' ' || *p > '~')
				break;
		}
		if (!*p)
			return 1;
	}
	fprintf(stderr, "%s must be nonempty printable ASCII without newlines\n",
		name);
	return 0;
}

static int parse_size(const char *str, uint32_t *size)
{
	char *end;
	uintmax_t value;

	errno = 0;
	value = strtoumax(str, &end, !strncmp(str, "0x", 2) ? 16 : 10);
	if (*str < '0' || *str > '9' || *end || errno ||
	    value < Y3_HEADER_SIZE + UBI_EC_HEADER_SIZE + Y3_MD5_SIZE ||
	    value > INT32_MAX) {
		fprintf(stderr, "Invalid maximum image size: %s\n", str);
		return -1;
	}
	*size = value;
	return 0;
}

static int make_header(char *header, const struct y3_options *opts,
		       uint32_t ubi_size)
{
	uint32_t md5_offset = Y3_HEADER_SIZE + ubi_size;
	int len;

	memset(header, 0, Y3_HEADER_SIZE);
	len = snprintf(header, Y3_HEADER_SIZE,
		"IntenoIopY\n"
		"version 8\n"
		"integrity MD5SUM\n"
		"git %s\n"
		"chip %s\n"
		"arch %s\n"
		"model %s\n"
		"release %s\n"
		"customer %s\n"
		"cfeofs %u\ncfe 0\n"
		"rescueofs %u\nrescue 0\n"
		"vmlinuxofs %u\nvmlinux 0\n"
		"ubifsofs %u\nubifs 0\n"
		"ubiofs %u\nubi %" PRIu32 "\n"
		"pkginfoofs %" PRIu32 "\npkginfo 0\n"
		"scrofs %" PRIu32 "\nscr 0\n"
		"flags singlepureubi bpartit32\n"
		"sigofs %" PRIu32 "\nsig 0\n"
		"md5ofs %" PRIu32 "\nmd5 32\n"
		"size %" PRIu32 "\n",
		opts->revision, opts->chip, opts->arch, opts->model,
		opts->release, opts->customer,
		Y3_HEADER_SIZE, Y3_HEADER_SIZE, Y3_HEADER_SIZE,
		Y3_HEADER_SIZE, Y3_HEADER_SIZE, ubi_size,
		md5_offset, md5_offset, md5_offset, md5_offset,
		md5_offset + Y3_MD5_SIZE);
	if (len < 0 || len > Y3_HEADER_TEXT_MAX) {
		fprintf(stderr, "Metadata does not fit in the Y3 header\n");
		return -1;
	}
	return 0;
}

static int write_image(const struct y3_options *opts)
{
	unsigned char buf[65536], digest[16];
	char header[Y3_HEADER_SIZE], hex[Y3_MD5_SIZE + 1];
	struct stat input_stat, output_stat;
	FILE *input = NULL, *output = NULL;
	char *temporary = NULL;
	uint32_t remaining;
	MD5_CTX md5;
	mode_t mask;
	size_t count;
	int fd, i, ret = -1;

	input = fopen(opts->input, "rb");
	if (!input) {
		fprintf(stderr, "%s: %s\n", opts->input, strerror(errno));
		goto out;
	}
	if (fstat(fileno(input), &input_stat) ||
	    !S_ISREG(input_stat.st_mode)) {
		fprintf(stderr, "%s: input must be a regular file\n", opts->input);
		goto out;
	}
	if (input_stat.st_size < UBI_EC_HEADER_SIZE ||
	    (uintmax_t)input_stat.st_size >
	    opts->max_size - Y3_HEADER_SIZE - Y3_MD5_SIZE) {
		fprintf(stderr, "%s: invalid UBI size or image exceeds %" PRIu32
			" bytes\n", opts->input, opts->max_size);
		goto out;
	}
	if (!stat(opts->output, &output_stat) &&
	    input_stat.st_dev == output_stat.st_dev &&
	    input_stat.st_ino == output_stat.st_ino) {
		fprintf(stderr, "Input and output refer to the same file\n");
		goto out;
	}
	if (fread(buf, 1, UBI_EC_HEADER_SIZE, input) != UBI_EC_HEADER_SIZE ||
	    memcmp(buf, "UBI#", 4) || buf[4] != 1) {
		fprintf(stderr, "%s: expected a UBI version 1 image\n", opts->input);
		goto out;
	}
	if (fseek(input, 0, SEEK_SET)) {
		fprintf(stderr, "%s: cannot rewind input\n", opts->input);
		goto out;
	}
	remaining = input_stat.st_size;
	if (make_header(header, opts, remaining))
		goto out;

	/* Publish only a complete image; preserve any old output on failure. */
	temporary = malloc(strlen(opts->output) + sizeof(".XXXXXX"));
	if (!temporary) {
		fprintf(stderr, "Out of memory\n");
		goto out;
	}
	sprintf(temporary, "%s.XXXXXX", opts->output);
	fd = mkstemp(temporary);
	if (fd < 0) {
		fprintf(stderr, "%s: %s\n", opts->output, strerror(errno));
		free(temporary);
		temporary = NULL;
		goto out;
	}
	mask = umask(0);
	umask(mask);
	if (fchmod(fd, 0666 & ~mask)) {
		close(fd);
		goto write_error;
	}
	output = fdopen(fd, "wb");
	if (!output) {
		close(fd);
		goto write_error;
	}
	MD5_Init(&md5);
	MD5_Update(&md5, header, sizeof(header));
	if (fwrite(header, 1, sizeof(header), output) != sizeof(header))
		goto write_error;
	while (remaining) {
		count = remaining < sizeof(buf) ? remaining : sizeof(buf);
		if (fread(buf, 1, count, input) != count) {
			fprintf(stderr, "%s: short read or read error\n", opts->input);
			goto out;
		}
		MD5_Update(&md5, buf, count);
		if (fwrite(buf, 1, count, output) != count)
			goto write_error;
		remaining -= count;
	}
	if (fgetc(input) != EOF || ferror(input)) {
		fprintf(stderr, "%s: input changed size or read failed\n", opts->input);
		goto out;
	}
	MD5_Final(digest, &md5);
	for (i = 0; i < 16; i++)
		snprintf(hex + 2 * i, 3, "%02x", digest[i]);
	if (fwrite(hex, 1, Y3_MD5_SIZE, output) != Y3_MD5_SIZE)
		goto write_error;
	if (fclose(output)) {
		output = NULL;
		goto write_error;
	}
	output = NULL;
	if (rename(temporary, opts->output))
		goto write_error;
	ret = 0;
	goto out;

write_error:
	fprintf(stderr, "%s: output failed: %s\n", opts->output, strerror(errno));
out:
	if (input)
		fclose(input);
	if (output)
		fclose(output);
	if (temporary) {
		if (ret)
			unlink(temporary);
		free(temporary);
	}
	return ret;
}

int main(int argc, char **argv)
{
	struct y3_options opts = {
		.release = "OpenWrt",
		.customer = "OpenWrt",
		.revision = "unknown",
		.max_size = Y3_DEFAULT_MAX_SIZE,
	};
	int opt;

	while ((opt = getopt(argc, argv, "i:o:c:m:a:r:u:g:s:h")) != -1) {
		switch (opt) {
		case 'i':
			opts.input = optarg;
			break;
		case 'o':
			opts.output = optarg;
			break;
		case 'c':
			opts.chip = optarg;
			break;
		case 'm':
			opts.model = optarg;
			break;
		case 'a':
			opts.arch = optarg;
			break;
		case 'r':
			opts.release = optarg;
			break;
		case 'u':
			opts.customer = optarg;
			break;
		case 'g':
			opts.revision = optarg;
			break;
		case 's':
			if (parse_size(optarg, &opts.max_size))
				return EXIT_FAILURE;
			break;
		case 'h':
			usage(stdout, argv[0]);
			return EXIT_SUCCESS;
		default:
			usage(stderr, argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (!opts.input || !opts.output || !opts.chip || !opts.model ||
	    !opts.arch || optind != argc) {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}
	/* CFE parses the chip ID as hexadecimal, accepting digits 0..9 only. */
	if (!*opts.chip || strlen(opts.chip) > 8 ||
	    strspn(opts.chip, "0123456789") != strlen(opts.chip)) {
		fprintf(stderr, "Chip ID must contain one to eight digits\n");
		return EXIT_FAILURE;
	}
	if (!valid_text("model", opts.model) || !valid_text("arch", opts.arch) ||
	    !valid_text("release", opts.release) ||
	    !valid_text("customer", opts.customer) ||
	    !valid_text("revision", opts.revision))
		return EXIT_FAILURE;

	return write_image(&opts) ? EXIT_FAILURE : EXIT_SUCCESS;
}
