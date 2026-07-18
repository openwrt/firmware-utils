// SPDX-License-Identifier: GPL-2.0-only
/*
 * uimage_padhdr.c : add zero paddings after the tail of uimage header
 *
 * Copyright (C) 2019 NOGUCHI Hiroshi <drvlabo@gmail.com>
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <zlib.h>


/* from u-boot/include/image.h */
#define IH_MAGIC	0x27051956	/* Image Magic Number		*/
#define IH_NMLEN		32	/* Image Name Length		*/

/*
 * Legacy format image header,
 * all data in network byte order (aka natural aka bigendian).
 */
typedef struct image_header {
	uint32_t	ih_magic;	/* Image Header Magic Number	*/
	uint32_t	ih_hcrc;	/* Image Header CRC Checksum	*/
	uint32_t	ih_time;	/* Image Creation Timestamp	*/
	uint32_t	ih_size;	/* Image Data Size		*/
	uint32_t	ih_load;	/* Data	 Load  Address		*/
	uint32_t	ih_ep;		/* Entry Point Address		*/
	uint32_t	ih_dcrc;	/* Image Data CRC Checksum	*/
	uint8_t		ih_os;		/* Operating System		*/
	uint8_t		ih_arch;	/* CPU architecture		*/
	uint8_t		ih_type;	/* Image Type			*/
	uint8_t		ih_comp;	/* Compression Type		*/
	uint8_t		ih_name[IH_NMLEN];	/* Image Name		*/
} image_header_t;


/* default padding size */
#define	IH_PAD_BYTES		(32)

/* maximum number of -x / -s patch entries */
#define MAX_PATCHES		64

typedef struct {
	size_t		offset;	/* byte offset within the padding area */
	uint8_t		*data;
	size_t		len;
} patch_entry_t;

static patch_entry_t patches[MAX_PATCHES];
static int num_patches = 0;

static void free_patches(void)
{
	int i;

	for (i = 0; i < num_patches; i++) {
		free(patches[i].data);
		patches[i].data = NULL;
	}
	num_patches = 0;
}

/*
 * Helper to add a validated patch entry.
 * Takes ownership of `data` on success.
 */
static int add_patch(size_t offset, uint8_t *data, size_t len)
{
	if (num_patches >= MAX_PATCHES) {
		fprintf(stderr, "Too many patch entries (max %d)\n", MAX_PATCHES);
		free(data);
		return -1;
	}

	patches[num_patches].offset = offset;
	patches[num_patches].data   = data;
	patches[num_patches].len    = len;
	num_patches++;
	return 0;
}

/*
 * Parse offset from argument prefix.
 * Returns pointer to the start of the payload data, or NULL on error.
 */
static const char *
parse_offset(const char *arg, const char *opt_name, size_t *offset_out)
{
	const char *colon;
	long offset;
	char *endptr;

	colon = strchr(arg, ':');
	if (!colon) {
		fprintf(stderr, "Invalid %s argument (expected offset:value): %s\n", opt_name, arg);
		return NULL;
	}

	errno = 0;
	offset = strtol(arg, &endptr, 0);
	if (errno || endptr == arg || endptr != colon || offset < 0) {
		fprintf(stderr, "Invalid offset in %s argument: %s\n", opt_name, arg);
		return NULL;
	}

	*offset_out = (size_t)offset;
	return colon + 1;
}

static int hex_to_nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/*
 * Parse "offset:hexstring" and add patch.
 */
static int
add_hex_patch(const char *arg)
{
	const char *hexstr;
	size_t offset;
	size_t hexlen;
	uint8_t *data;
	size_t i;

	hexstr = parse_offset(arg, "-x", &offset);
	if (!hexstr)
		return -1;

	hexlen = strlen(hexstr);
	if (hexlen == 0 || hexlen % 2 != 0) {
		fprintf(stderr, "Hex string must have even number of digits: %s\n", hexstr);
		return -1;
	}

	data = malloc(hexlen / 2);
	if (!data) {
		fprintf(stderr, "Memory allocation failed\n");
		return -1;
	}

	for (i = 0; i < hexlen / 2; i++) {
		int high = hex_to_nibble(hexstr[2 * i]);
		int low = hex_to_nibble(hexstr[2 * i + 1]);

		if (high < 0 || low < 0) {
			fprintf(stderr, "Invalid hex byte at position %zu: %.2s\n",
				i, hexstr + 2 * i);
			free(data);
			return -1;
		}
		data[i] = (uint8_t)((high << 4) | low);
	}

	return add_patch(offset, data, hexlen / 2);
}

/*
 * Parse "offset:string" and add patch.
 */
static int
add_str_patch(const char *arg)
{
	const char *str;
	size_t offset;
	size_t slen;
	uint8_t *data;

	str = parse_offset(arg, "-s", &offset);
	if (!str)
		return -1;

	slen = strlen(str);
	if (slen == 0) {
		fprintf(stderr, "Empty string in -s argument: %s\n", arg);
		return -1;
	}

	data = malloc(slen);
	if (!data) {
		fprintf(stderr, "Memory allocation failed\n");
		return -1;
	}
	memcpy(data, str, slen);

	return add_patch(offset, data, slen);
}

static void usage(char *prog)
{
	fprintf(stderr,
		"%s -i <input_uimage_file> -o <output_file> [-l <padding bytes>]\n"
		"   [-x offset:hexstring] [-s offset:string]\n"
		"\n"
		"  -l <bytes>         Total padding size appended after the uImage header\n"
		"                     (default: %d bytes, zero-filled)\n"
		"  -x offset:hexstr   Write hex bytes at <offset> within the padding\n"
		"                     (can be repeated; hex digits must be even count)\n"
		"  -s offset:string   Write ASCII string at <offset> within the padding\n"
		"                     (can be repeated; string is NOT NUL-terminated)\n"
		"\n"
		"Offsets are relative to the start of the padding area.\n"
		"Patches are validated so they do not exceed the padding size.\n",
		prog, IH_PAD_BYTES);
}

int main(int argc, char *argv[])
{
	struct stat statbuf;
	u_int8_t *filebuf = NULL;
	int ifd = -1;
	int ofd = -1;
	ssize_t rsz;
	u_int32_t crc_recalc;
	image_header_t *imgh;
	int opt;
	char *infname = NULL;
	char *outfname = NULL;
	int padsz = IH_PAD_BYTES;
	int ltmp;
	int i;
	int ret = 1;

	while ((opt = getopt(argc, argv, "i:o:l:x:s:")) != -1) {
		switch (opt) {
		case 'i':
			infname = optarg;
			break;
		case 'o':
			outfname = optarg;
			break;
		case 'l':
			ltmp = strtol(optarg, NULL, 0);
			if (ltmp > 0)
				padsz = ltmp;
			break;
		case 'x':
			if (add_hex_patch(optarg) < 0)
				goto out;
			break;
		case 's':
			if (add_str_patch(optarg) < 0)
				goto out;
			break;
		default:
			break;
		}
	}

	if (!infname || !outfname) {
		usage(argv[0]);
		goto out;
	}

	/* Validate all patches fit inside the padding area (with overflow protection) */
	for (i = 0; i < num_patches; i++) {
		if (patches[i].offset > (size_t)padsz ||
		    patches[i].len > (size_t)padsz - patches[i].offset) {
			fprintf(stderr,
				"Patch %d (offset=%zu len=%zu) overflows "
				"padding size %d\n",
				i,
				patches[i].offset,
				patches[i].len,
				padsz);
			goto out;
		}
	}

	ifd = open(infname, O_RDONLY);
	if (ifd < 0) {
		fprintf(stderr,
			"could not open input file. (errno = %d)\n", errno);
		goto out;
	}

	ofd = open(outfname, O_WRONLY | O_CREAT, 0644);
	if (ofd < 0) {
		fprintf(stderr,
			"could not open output file. (errno = %d)\n", errno);
		goto out;
	}

	if (fstat(ifd, &statbuf) < 0) {
		fprintf(stderr,
			"could not fstat input file. (errno = %d)\n", errno);
		goto out;
	}

	filebuf = malloc(statbuf.st_size + padsz);
	if (!filebuf) {
		fprintf(stderr, "buffer allocation failed\n");
		goto out;
	}

	rsz = read(ifd, filebuf, sizeof(*imgh));
	if (rsz != sizeof(*imgh)) {
		fprintf(stderr,
			"could not read input file (errno = %d).\n", errno);
		goto out;
	}

	memset(&(filebuf[sizeof(*imgh)]), 0, padsz);

	/* Apply patches into the padding area (before checksum) */
	for (i = 0; i < num_patches; i++) {
		memcpy(&filebuf[sizeof(*imgh) + patches[i].offset],
		       patches[i].data,
		       patches[i].len);
	}

	rsz = read(ifd, &(filebuf[sizeof(*imgh) + padsz]),
				statbuf.st_size - sizeof(*imgh));
	if (rsz != (int32_t)(statbuf.st_size - sizeof(*imgh))) {
		fprintf(stderr,
			"could not read input file (errno = %d).\n", errno);
		goto out;
	}

	imgh = (image_header_t *)filebuf;

	imgh->ih_hcrc = 0;
	crc_recalc = crc32(0, filebuf, sizeof(*imgh) + padsz);
	imgh->ih_hcrc = htonl(crc_recalc);

	rsz = write(ofd, filebuf, statbuf.st_size + padsz);
	if (rsz != (int32_t)statbuf.st_size + padsz) {
		fprintf(stderr,
			"could not write output file (errnor = %d).\n", errno);
		goto out;
	}

	ret = 0;

out:
	if (ifd >= 0)
		close(ifd);
	if (ofd >= 0)
		close(ofd);
	free_patches();
	free(filebuf);

	return ret;
}
