// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 INAGAKI Hiroshi <musashino.open@gmail.com>
 */

#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FWHDR_LEN		0x20
#define BLKHDR_LEN		0x18

#define BLKHDR_FLAGS_GZIP	0x80000000
#define BLKHDR_FLAGS_EXEC	0x00000002
#define BLKHDR_FLAGS_SYS	0x00000001
#define BLKHDR_DEF_LOADADDR	0x80040000
#define BLKHDR_DEF_ENTRYP	BLKHDR_DEF_LOADADDR

#define FILETYPE_LEN		0x20

#define PADBLK_LEN		0x4
#define DATABLK_CNT_MAX		2

struct header
{
	uint32_t flags;
	uint32_t totlen;
	uint32_t hdrlen;
	uint32_t cksum;
	uint32_t loadaddr;
	uint32_t entryp;
} __attribute__ ((packed));

static char *progname;
FILE *outbin;
int nblk = 0;

static void usage(void)
{
	printf("Usage: %s <output> [OPTIONS...]\n", progname);
	printf("\n"
	       "Options:\n"
	       "  -t <type>       set firmware type to <type>\n"
	       "  -f <flags>      set data flags to <flags>\n"
	       "  -a <loadaddr>   set data load address to <loadaddr>\n"
	       "  -e <entry>      set data entry point to <entry>\n"
	       "  -d <file>       read input data from file <file> (max. %dx)\n",
	       DATABLK_CNT_MAX);
}

static int strtou32(char *arg, uint32_t *val)
{
	char *endptr = NULL;

	errno = 0;
	*val = strtoul(arg, &endptr, 0);
	return (errno || (endptr && *endptr)) ? -EINVAL : 0;
}

static int write_data(const char *buf, size_t length, uint32_t *cksum)
{
	size_t padlen = 0;
	size_t pos;

	if (length % PADBLK_LEN)
		padlen = PADBLK_LEN - length % PADBLK_LEN;

	if (fwrite(buf, 1, length, outbin) != length) {
		fprintf(stderr, "Couldn't write %zu bytes\n", length);
		return -EACCES;
	}

	if (cksum)
		for (pos = 0; pos < length; pos += 2) {
			if (length - pos == 1)
				*cksum += le16toh(buf[pos]);
			else
				*cksum += le16toh(*(uint16_t *)(buf + pos));
		}

	if (padlen) {
		int i;
		for (i = 0; i < padlen; i++)
			fputc(0x0, outbin);
	}

	return padlen;
}

static int write_blockheader(uint32_t flags,
			     uint32_t loadaddr, uint32_t entryp,
			     size_t datalen, int padlen, uint32_t cksum)
{
	struct header hdr;
	uint16_t *cur = (uint16_t *)&hdr;
	char buf[0x20];

	flags <<= 16;
	flags |= (~flags & 0xffff0000) >> 16;

	hdr.flags = htobe32(flags);
	hdr.totlen = htobe32(BLKHDR_LEN + datalen);
	hdr.hdrlen = htobe32(BLKHDR_LEN);
	hdr.cksum = 0;
	hdr.loadaddr = htobe32(loadaddr);
	hdr.entryp = htobe32(entryp);

	for (cur += 2; cur - (uint16_t *)&hdr < BLKHDR_LEN / 2; cur++) {
		cksum += htole16(*cur);
		/*
		 * workaround of unknown bug if built with gcc 9.4.0
		 * (Ubuntu 9.4.0-1ubuntu1~20.04.2) and cmake
		 */
		snprintf(buf, sizeof(buf), "%u", cksum);
	}

	cksum = 0xffff ^ cksum % 0xffff;
	hdr.cksum = htole32(cksum);

	if (datalen)
		fseek(outbin, -(BLKHDR_LEN + datalen + padlen), SEEK_CUR);
	if (fwrite(&hdr, 1, BLKHDR_LEN, outbin) != BLKHDR_LEN) {
		fprintf(stderr, "Couldn't write %d bytes\n", BLKHDR_LEN);
		return -EACCES;
	}
	if (datalen)
		fseek(outbin, datalen + padlen, SEEK_CUR);

	nblk++;
	printf("%d:\t0x%04x,\t0x%08zx,\t0x%08x,\t0x%08x,\t0x%08x\n",
	       nblk, flags >> 16, BLKHDR_LEN + datalen, loadaddr, entryp, cksum);
	return 0;
}

static int append_datablock_from_file(uint32_t flags,
			 uint32_t loadaddr, uint32_t entryp,
			 const char *datapath)
{
	FILE *databin;
	size_t readlen, length = 0;
	uint32_t cksum = 0;
	char buf[0x10000];
	int ret = 0;

	fseek(outbin, BLKHDR_LEN, SEEK_CUR);

	databin = fopen(datapath, "r");
	if (!databin) {
		fprintf(stderr, "couldn't open %s\n", datapath);
		return -EACCES;
	}

	while ((readlen = fread(buf, 1, sizeof(buf), databin)) > 0) {
		ret = write_data(buf, readlen, &cksum);
		if (ret < 0)
			goto exit;
		length += readlen;
	}

	ret = write_blockheader(flags, loadaddr, entryp, length, ret, cksum);

exit:
	fclose(databin);
	return ret;
}

static int append_datablock_from_buf(uint32_t flags,
				     uint32_t loadaddr, uint32_t entryp,
				     const char *buf, size_t buflen)
{
	uint32_t cksum = 0;
	int ret;

	fseek(outbin, BLKHDR_LEN, SEEK_CUR);

	ret = write_data(buf, buflen, &cksum);

	return write_blockheader(flags, loadaddr, entryp, buflen, ret, cksum);
}

int main(int argc, char **argv)
{
	uint32_t flags = BLKHDR_FLAGS_EXEC;
	uint32_t loadaddr = BLKHDR_DEF_LOADADDR;
	uint32_t entryp = BLKHDR_DEF_ENTRYP;
	char buf[0x40], ftype[FILETYPE_LEN];
	int ret, c, ftlen = 0;

	progname = basename(argv[0]);

	if (argc >= 2 &&
	    (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
		usage();
		return 0;
	}

	if (argc < 2) {
		fprintf(stderr, "no output file specified\n");
		usage();
		return -EINVAL;
	}

	outbin = fopen(argv[1], "w+");
	if (!outbin) {
		fprintf(stderr, "Couldn't open %s\n", argv[1]);
		return -EACCES;
	}

	/* add firmware header */
	sprintf(buf, "USB ATERMWL3050");
	memset(buf + 0x10, 0xff, 0x10);
	ret = write_data(buf, FWHDR_LEN, NULL);
	if (ret < 0)
		goto exit;

	printf("\tFlags\tTotal Len.\tLoad Addr\tEntry Point\tChecksum\n");

	/* add version/copyright block */
	ret = sprintf(buf, "VERSION: 9.99.99\nOEM1 VERSION: 9.9.99\n");
	ret = append_datablock_from_buf(0x0, 0x0, 0x0, buf, ret);
	if (ret)
		goto exit;

	/* set type and parse/write user-defined data blocks */
	while((c = getopt(argc, argv, "f:a:e:d:t:")) != -1) {
		switch (c) {
		case 'f':
			if (strtou32(optarg, &flags)) {
				fprintf(stderr, "invalid flags value specified\n");
				ret = -EINVAL;
				goto exit;
			}
			break;
		case 'a':
			if (strtou32(optarg, &loadaddr)) {
				fprintf(stderr, "invalid load address specified\n");
				ret = -EINVAL;
				goto exit;
			}
			break;
		case 'e':
			if (strtou32(optarg, &entryp)) {
				fprintf(stderr, "invalid entry point specified\n");
				ret = -EINVAL;
				goto exit;
			}
			break;
		case 'd':
			if (nblk - 1 >= DATABLK_CNT_MAX) {
				fprintf(stderr,
					"data block count exceeds maximum count (%d), skipping...\n",
					DATABLK_CNT_MAX);
				continue;
			}
			ret = append_datablock_from_file(flags, loadaddr, entryp, optarg);
			if (ret)
				goto exit;

			flags = BLKHDR_FLAGS_EXEC;
			loadaddr = BLKHDR_DEF_LOADADDR;
			entryp = BLKHDR_DEF_ENTRYP;
			break;
		case 't':
			ftlen = snprintf(buf, sizeof(buf), "Binary Type%s File END \r\n", optarg);
			if (ftlen > FILETYPE_LEN) {
				fprintf(stderr, "specified type is too long\n");
				ret = -EINVAL;
				goto exit;
			}
			memset(ftype, 0xff, FILETYPE_LEN);
			strncpy(ftype + (FILETYPE_LEN - ftlen), buf, ftlen);
			break;
		case '?':
		default:
			ret = -EINVAL;
			goto exit;
		}
	}

	if (!ftlen) {
		fprintf(stderr, "no file type specified\n");
		ret = -EINVAL;
		goto exit;
	}

	/* append end block */
	ret = write_blockheader(BLKHDR_FLAGS_SYS, 0, 0, 0, 0, 0);
	if (ret)
		goto exit;

	/* append file type */
	ret = write_data(ftype, FILETYPE_LEN, NULL);

exit:
	fclose(outbin);
	if (ret == -EINVAL)
		usage();
	return ret < 0 ? ret : 0;
}
