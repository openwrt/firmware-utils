// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2025-2026 Andreas Boehler <dev@aboehler.at>
 *  Based on reverse-engineering by Jan Hoffmann (obfuscation)
 *
 * Create images for the XikeStor SKS7300 series
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <zlib.h>

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#  define HOST_TO_LE16(x)	(x)
#  define HOST_TO_LE32(x)	(x)
#  define LE16_TO_HOST(x)	(x)
#  define LE32_TO_HOST(x)	(x)
#  define HOST_TO_BE16(x)	bswap_16(x)
#  define HOST_TO_BE32(x)	bswap_32(x)
#  define BE16_TO_HOST(x)	bswap_16(x)
#  define BE32_TO_HOST(x)	bswap_32(x)
#else
#  define HOST_TO_BE16(x)	(x)
#  define HOST_TO_BE32(x)	(x)
#  define BE16_TO_HOST(x)	(x)
#  define BE32_TO_HOST(x)	(x)
#  define HOST_TO_LE16(x)	bswap_16(x)
#  define HOST_TO_LE32(x)	bswap_32(x)
#  define LE16_TO_HOST(x)	bswap_16(x)
#  define LE32_TO_HOST(x)	bswap_32(x)
#endif

#define ALIGN(x,y)	(((x)+((y)-1)) & ~((y)-1))

/*
 * Message macros
 */
#define ERR(fmt, ...) do { \
	fflush(0); \
	fprintf(stderr, "[%s] *** error: " fmt "\n", \
			progname, ## __VA_ARGS__ ); \
} while (0)


#define MAX_ARG_COUNT	32
#define MAX_ARG_LEN	1024

struct sks7300_hdr {
	uint32_t image_magic;     // Image Magic 0xfe071301
	uint32_t hdr_crc;         // Header CRC
	uint32_t image_size;      // Image Size (Bytes)
	uint32_t timestamp;       // Image Timestamp (Unix Timestamp)
	uint32_t image00_offset;  // Image 00 Offset
	uint32_t image00_size;    // Image 00 size
	uint8_t image00_type;     // Image 00 Type; 0x52 = Kernel Image, 0x5B = Unknown Image, 0x53 = RAMDisk
	uint8_t image00_comp;     // Image 00 Compression; 0x67 = LZMA, 0x00 = uncompressed
	uint16_t unknown1;        // Unknown1
	uint32_t image01_offset;  // Image 01 Offset
	uint32_t image01_size;    // Image 01 size
	uint32_t unknown2;        // Unknown2
	uint32_t image02_offset;  // Image 02 Offset
	uint32_t image02_size;    // Image 02 size
	uint32_t unknown3;        // Unknown3
	uint8_t padding[60];      // unknown padding, probably for another 4 images
	char image_name[64];      // Image Name
	uint32_t image_id;        // Image ID 0xfe009300
	uint32_t unknown4;        // Unknown4
	uint32_t load_addr;       // Kernel Load Address
	uint32_t entry_point;     // Kernel Entry Point
	uint32_t payload_crc;     // CRC32 of entire payload
	uint8_t image_os;         // Image OS Type; 0x0f = Linux
	uint8_t image_arch;       // Image Arch; 0x37 = MIPS
	uint8_t unknown5[4];      // Unknown5
	uint8_t stk_header[6];    // STK Header 0xaa552288bb66
	uint8_t unknown6[84];     // Unknown6
	uint32_t image_id2;       // Image ID 0xfe009300
	uint8_t unknown7[20];     // Unknown7
	char version_string[396]; // Version string; probably shorter, the rest is padding
} __attribute__((packed));

char *ofname = NULL;
char *ifname = NULL;
char *image_name = NULL;
char *image_version = NULL;

void *input_file = NULL;
char *progname;
uint32_t load_addr = 0x80100000;
uint32_t entry_point = 0x80100000;

/*
 * Helper routines
 */
void
usage(int status)
{
	FILE *stream = (status != EXIT_SUCCESS) ? stderr : stdout;

	fprintf(stream, "Usage: %s [OPTIONS...]\n", progname);
	fprintf(stream, "\nOptions:\n");
	fprintf(stream,
"  -i <file>\n"
"                  input file, e.g. OpenWrt firmware image\n"
"  -o <file>\n"
"                  write output to the file <file>\n"
"  -n <name>\n"
"                  image name (e.g. OpenWrt)\n"
"  -v <version>\n"
"                  version (e.g. 25.12.0)\n"
"  -h              show this screen\n"
	);

	exit(status);
}

static void
*map_input(const char *name, size_t *len)
{
	struct stat stat;
	void *mapped;
	int fd;

	fd = open(name, O_RDONLY);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &stat) < 0) {
		close(fd);
		return NULL;
	}
	*len = stat.st_size;
	mapped = mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (close(fd) < 0) {
		(void) munmap(mapped, stat.st_size);
		return NULL;
	}
	return mapped;
}

int
parse_arg(char *arg, char *buf, char *argv[])
{
	int res = 0;
	size_t argl;
	char *tok;
	char **ap = &buf;
	int i;

	memset(argv, 0, MAX_ARG_COUNT * sizeof(void *));

	if ((arg == NULL)) {
		/* no arguments */
		return 0;
	}

	argl = strlen(arg);
	if (argl == 0) {
		/* no arguments */
		return 0;
	}

	if (argl >= MAX_ARG_LEN) {
		/* argument is too long */
		argl = MAX_ARG_LEN-1;
	}

	memcpy(buf, arg, argl);
	buf[argl] = '\0';

	for (i = 0; i < MAX_ARG_COUNT; i++) {
		tok = strsep(ap, ":");
		if (tok == NULL) {
			break;
		}
		argv[i] = tok;
		res++;
	}

	return res;
}

int
required_arg(char c, char *arg)
{
	if (arg == NULL || *arg != '-')
		return 0;

	ERR("option -%c requires an argument\n", c);
	return -1;
}

int
parse_opt_name(char ch, char *arg, char **dest)
{

	if (*dest != NULL) {
		ERR("only one input/output file allowed");
		return -1;
	}

	if (required_arg(ch, arg))
		return -1;

	*dest = arg;

	return 0;
}

uint8_t*
obfuscate_file(uint8_t *input_file, size_t len) {
	uint8_t *out_file = malloc(len+3); // The new header adds 3 bytes to the total size
	uint8_t lc;
	uint8_t lp;
	uint8_t pb;
	uint8_t ds1;
	uint8_t ds2;
	uint8_t ds3;
	uint8_t ds4;
	int pos;
	int index;

	struct hdr {
		uint8_t props;
		uint32_t dicsize;
		uint64_t size;
	} __attribute__((packed));

	struct newhdr {
		uint16_t magic;    // Magic Number
		uint16_t special;  // Special Numbers for obfuscation
		uint8_t pb;        // LZMA pb
		uint8_t lp;        // LZMA lp
		uint8_t lc;        // LZMA lc
		uint8_t pad;       // Padding
		uint8_t ds2;       // Data size byte 2
		uint8_t ds3;       // Data size byte 3
		uint8_t ds4;       // Data size byte 4
		uint8_t ds1;       // Data size byte 1
		uint32_t size;     // Size
	} __attribute__((packed));

	struct hdr old_hdr;
	struct newhdr new_hdr;

	if(out_file == NULL)
		return out_file;

	memcpy(&old_hdr, input_file, sizeof(old_hdr));
	lc = old_hdr.props % 9;
	lp = ((old_hdr.props - lc) / 9) % 5;
	pb = (((old_hdr.props - lc) / 9) - lp) / 5;
	lc ^= 0xb9;
	lp ^= 0x5e;
	pb ^= 0x37;

	ds1 = old_hdr.dicsize >> 24;
	ds2 = old_hdr.dicsize >> 16;
	ds3 = old_hdr.dicsize >> 8;
	ds4 = old_hdr.dicsize;

	memset(&new_hdr, 0, sizeof(new_hdr));
	new_hdr.magic = HOST_TO_BE16(0x5e71);
	/* We set special 1 and special 2 to 1 so that the algorithm does not require any magic values */
	new_hdr.special = 0x0101;
	new_hdr.pb = pb;
	new_hdr.lp = lp;
	new_hdr.lc = lc;
	new_hdr.ds1 = ds1;
	new_hdr.ds2 = ds2;
	new_hdr.ds3 = ds3;
	new_hdr.ds4 = ds4;
	/* This narrows the uint64_t to uint32_t; a file bigger than the 32 bits limit
	   wouldn't be accepted anyway */
	new_hdr.size = HOST_TO_BE32(old_hdr.size); 

	memcpy(out_file, &new_hdr, sizeof(new_hdr));
	memcpy(&out_file[sizeof(new_hdr)], &input_file[sizeof(old_hdr)], len - sizeof(old_hdr));

	pos = sizeof(new_hdr);
	while(pos < (len - sizeof(old_hdr))) {
		for(int i=0; i<8; i++) {
			index = pos + i;
			if(index >= (len + sizeof(old_hdr)))
				break;

			out_file[index] = i ^ out_file[index];
		}
		pos += 0x4000;
	}

	return out_file;
}

int
is_empty_arg(char *arg)
{
	int ret = 1;
	if (arg != NULL) {
		if (*arg) ret = 0;
	};
	return ret;
}

int main(int argc, char *argv[]) {
	size_t file_len = 0;
	size_t out_len = 0;
	int optinvalid = 0;   /* flag for invalid option */
	int res = EXIT_FAILURE;
	int c;
	uint8_t *obfuscated_file = NULL;

	struct sks7300_hdr sks_hdr;

	FILE *outfile;

	progname=basename(argv[0]);

	opterr = 0;  /* could not print standard getopt error messages */
	while ( 1 ) {
		optinvalid = 0;

		c = getopt(argc, argv, "i:o:n:v:h");
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			optinvalid = parse_opt_name(c,optarg,&ifname);
			break;
		case 'o':
			optinvalid = parse_opt_name(c,optarg,&ofname);
			break;
		case 'n':
			optinvalid = parse_opt_name(c,optarg,&image_name);
			break;
		case 'v':
			optinvalid = parse_opt_name(c,optarg,&image_version);
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		default:
			optinvalid = 1;
			break;
		}
		if (optinvalid != 0 ) {
			ERR("invalid option: -%c", optopt);
			goto out;
		}
	}

	if(!ifname) {
		ERR("input file is mandatory");
		goto out;
	}

	if(!ofname) {
		ERR("output file is mandatory");
		goto out;
	}

	if(!image_name) {
		ERR("image name is mandatory");
		goto out;
	}

	if(!image_version) {
		ERR("image version is mandatory");
		goto out;
	}

	input_file = map_input(ifname, &file_len);
	if(!input_file) {
		ERR("input file not found.");
		goto out;
	}

	obfuscated_file = obfuscate_file(input_file, file_len);
	out_len = file_len + 3; // The obfuscation adds 3 bytes to the total length

	memset(&sks_hdr, 0, sizeof(sks_hdr));
	sks_hdr.image_magic = HOST_TO_BE32(0xfe071301);
	sks_hdr.image_id = HOST_TO_BE32(0xfe009300);
	sks_hdr.load_addr = HOST_TO_BE32(load_addr);
	sks_hdr.entry_point = HOST_TO_BE32(entry_point);
	sks_hdr.stk_header[0] = 0xaa;
	sks_hdr.stk_header[1] = 0x55;
	sks_hdr.stk_header[2] = 0x22;
	sks_hdr.stk_header[3] = 0x88;
	sks_hdr.stk_header[4] = 0xbb;
	sks_hdr.stk_header[5] = 0x66;
	sks_hdr.image_id2 = HOST_TO_BE32(0xfe009300);
	strcpy(sks_hdr.image_name, image_name);
	strcpy(sks_hdr.version_string, image_version);
	sks_hdr.image00_type = 0x52; // Linux Kernel
	sks_hdr.image00_comp = 0x67; // LZMA compressed
	sks_hdr.image_os = 0x0f; // Linux
	sks_hdr.image_arch = 0x37; // MIPS

/*
	// The below values are set in the OEM upgrade file, but their meaning
	// is unknown
	sks_hdr.unknown4 = HOST_TO_BE32(0x01);
	sks_hdr.unknown5[2] = 0x8c;
	sks_hdr.unknown5[3] = 0x08;

	sks_hdr.unknown6[3] = 0x01;
	sks_hdr.unknown6[7] = 0x84;
	sks_hdr.unknown6[8] = 0x01;
	sks_hdr.unknown6[10] = 0x01;
	sks_hdr.unknown6[11] = 0x07;
	sks_hdr.unknown6[15] = 0x74;
	sks_hdr.unknown6[83] = 0x74;

	sks_hdr.unknown7[3] = 0x02;
	sks_hdr.unknown7[7] = 0x16;
*/
	uint32_t crc = crc32(0, obfuscated_file, out_len);
	sks_hdr.payload_crc = HOST_TO_BE32(crc);
	sks_hdr.image00_size = HOST_TO_BE32(out_len);
	sks_hdr.image_size = HOST_TO_BE32(out_len);
	crc = crc32(0, (unsigned char *)&sks_hdr, sizeof(sks_hdr));
	sks_hdr.hdr_crc = HOST_TO_BE32(crc);

	outfile = fopen(ofname, "w");
	fwrite(&sks_hdr, sizeof(sks_hdr), 1, outfile);
	fwrite(obfuscated_file, out_len, 1, outfile);
	fflush(outfile);
	fclose(outfile);

	res = EXIT_SUCCESS;

out:
	if (res != EXIT_SUCCESS) {
		unlink(ofname);
	}
	if(input_file)
		munmap(input_file, file_len);
	return res;
}
