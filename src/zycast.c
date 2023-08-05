// SPDX-License-Identifier: GPL-2.0-only
/*
 * zycast - push images via multicast to a ZyXEL bootloader
 *
 * Many ZyXEL devices supports image manipulation using a multicast
 * based protocol.  The protocol is not documented publicly, and
 * both the bootloader embedded part and the official clients are
 * closed source.
 *
 * This client is based on the following description of the protocol.
 * which is reverse engineered from bootloader binaries. It is likely
 * to be both incomplete and inaccurate, as it only covers the
 * observed implementation on a limited set of devices.  No client
 * implementation or network packets were available for the protocol
 * reverse engineering.
 *
 * Protocol description:
 *
 * UDP to multicast destination address 225.0.0.0 port 5631. Source
 * address and port is arbitrary.
 *
 *  Payload is split in packets prepended with a 30 byte header:
 *
 *   4 byte signature: 'z', 'y', 'x', 0x0 [1]
 *   16 bit checksum [2][3]
 *   32 bit packet id [2][4]
 *   32 bit packet length [2][5]
 *   32 bit file length [2][6]
 *   32 bit image bitmap [2][7]
 *   2 byte ascii country code [8]
 *   8 bit  flags [9]
 *   5 byte reserved [10]
 *
 * [1] the terminating null is not actually checked by the observed
 *     implementations, but is assumed to be safest in case the
 *     signature is treated as a string
 *
 * [2] all integers are in network byte order, i.e. big endian
 *
 * [3] checksum = sum >> 16 + sum, where sum is the sum of all
 *     payload bytes
 *
 * [4] starts at 0 and is incremented by 1 for each packet.  Used both
 *     to ensure sequential, loss free, unidirectional transport, and to
 *     allow the transfer to start at any point.  The sequence must be
 *     repeated until the transfer is complete
 *
 * [5] Testing indicates that some implementations expect 1024 byte
 *     packets.  Smaller size results in a corrupt download, and larger
 *     size causes the download to hang - waiting for packet ids which
 *     does not exist.
 *
 * [6] the length of each file in case of a multi file transfer.
 *
 * [7] the lower 8 bits is a bitmap of all image types included in the
 *     transfer.  Bits 8 - 16 contains the image type for this packet.
 *     The purpose of the upper 16 bits is unknown.
 *
 *     The known image types are
 *
 *       0x01 - "bootbase" (often "Bootloader" partition)
 *       0x02 - "rom"      (often "data" partition)
 *       0x04 - "ras"      (often "Kernel" partition)
 *       0x08 - "romd"     (often "rom-d" partition)
 *       0x10 - "backup"   (often "Kernel2" partition)
 *
 *     The supported set of images vary among implementations.
 *     The protocol may support other image types.
 *
 *     WARNING: The flash offset of each supported image type is hard
 *      coded in the bootloader server implementation.  There is no
 *      relation to the bootloader configuration, and no way to verify
 *      that those values are correct without decompiling that
 *      implementations. Device specific bugs are likely, and may
 *      result in a brick.
 *
 * [8] two upper case ascii characters, like 'D','E'. The purpose
 *     is unknown, but ZyXEL devices are often configured with this
 *     as one of their device specific variables

 * [9] bitmap controlling actions taken after a complete transfer:
 *
 *       0x01 - set DebugFlag
 *       0x02 - erase "rom"
 *       0x04 - erase "rom-d"
 *
 *     Other, unknown, values may exist in the protocol.  Device
 *     support may vary.
 *
 * [10] these bytes are not used by the observed implementations.
 *      The purpose is therefore unknown. There is a risk
 *      they are interpreted by other devices, resulting in
 *      unexpected and potentially harmful behaviour.
 *
 * Copyright (C) 2024 Bjørn Mork <bjorn@mork.no>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* defaulting to 10 ms interpacket delay */
static int pktdelay = 10000;
static int sockfd = -1;
static bool exiting;

/* All integers are stored in network order (big endian) */
struct zycast_t {
	uint32_t magic;
	uint16_t chksum;
	uint32_t pid;
	uint32_t plen;
	uint32_t flen;
	uint16_t unusedbits;
	unsigned char type;
	unsigned char images;
	char cc[2];
	unsigned char flags;
	char reserved[5];
} __attribute__ ((packed));

#define HDRSIZE (sizeof(struct zycast_t))
#define DEST_ADDR "225.0.0.0"
#define DEST_PORT 5631
#define CHUNK 1024
#define MAGIC 0x7a797800  /* "zyx" */

#define BIT(nr) (1 << (nr))

enum imagetype {
	BOOTBASE = 0,
	ROM,
	RAS,
	ROMD,
	BACKUP,
	_MAX_IMAGETYPE
};

#define FLAG_SET_DEBUG  BIT(0)
#define FLAG_ERASE_ROM  BIT(1)
#define FLAG_ERASE_ROMD BIT(2)

static void errexit(const char *msg)
{
	fprintf(stderr, "ERR: %s: %s\n", msg, errno ? strerror(errno) : "unknown");
	exit(EXIT_FAILURE);
}

static void *map_input(const char *name, size_t *len)
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

static uint16_t chksum(uint8_t *p, size_t len)
{
	int i;
	uint32_t sum = 0;

	for (i = 0; i < len; i++)
		sum += *p++;
	return (uint16_t)((sum >> 16) + sum);
}

static int pushimage(void *file, struct zycast_t *phdr)
{
	uint32_t count = 0;
	uint32_t len = ntohl(phdr->flen);
	uint32_t plen = CHUNK;

	while (!exiting && len > 0) {
		if (len < CHUNK)
			plen = len;
		phdr->plen = htonl(plen);
		phdr->pid = htonl(count++);
		phdr->chksum = htons(chksum(file, plen));
		if (send(sockfd, phdr, HDRSIZE, MSG_MORE | MSG_DONTROUTE) < 0)
			errexit("send(phdr)");
		if (send(sockfd, file, plen, MSG_DONTROUTE) < 0)
			errexit("send(payload)");
		file += plen;
		len -= plen;

		/* No need to kill the network. The target can't
		 * process packets as fast as we send them anyway.
		 */
		usleep(pktdelay);
	}
	return 0;
}

static void sig_handler(int signo)
{
	if (signo == SIGINT)
		exiting = true;
}

static void usage(const char *name)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, " %s [options]\n", name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-i interface            outgoing interface for multicast packets\n");
	fprintf(stderr, "\t-t delay                interpacket delay in milliseconds\n");
	fprintf(stderr, "\t-f rasimage             primary firmware image\n");
	fprintf(stderr, "\t-b backupimage          secondary firmware image (if supported)\n");
	fprintf(stderr, "\t-d rom                  data for the \"rom\" or \"data\" partition\n");
	fprintf(stderr, "\t-r romd                 data for the \"rom-d\" partition\n");
#ifdef DO_BOOTBASE
	fprintf(stderr, "\t-u bootloader           flash new bootloader\n");
	fprintf(stderr, "\nWARNING: bootloader upgrades are dangerous.  DON'T DO IT!\n");
#endif
	fprintf(stderr, "\nNOTE: some bootloaders will flash a rasimage to both primary and\n");
	fprintf(stderr, "secondary firmware partitions\n");
	fprintf(stderr, "\nExample:\n");
	fprintf(stderr, " %s -i eth1 -t 20 -f openwrt-initramfs.bin\n\n", name);
	if (sockfd >= 0)
		close(sockfd);
	exit(EXIT_FAILURE);
}

#define ADD_IMAGE(nr) \
	do { \
		hdr.images |= BIT(nr); \
		file[nr] = map_input(optarg, &len[nr]); \
		if (!file[nr]) \
			errexit(optarg); \
	} while (0)

int main(int argc, char **argv)
{
	void *file[_MAX_IMAGETYPE] = {};
	size_t len[_MAX_IMAGETYPE] = {};
	struct zycast_t hdr = {
		.magic = htonl(MAGIC),
		.cc    = {'F', 'F' },
		.flags = FLAG_SET_DEBUG,
	};
	const struct sockaddr_in dest = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr(DEST_ADDR),
		.sin_port = htons(DEST_PORT),
	};
	int i, c;

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		errexit("signal()");
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		errexit("socket()");
	if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) < 0)
		errexit("connect()");

	while ((c = getopt(argc, argv, "i:t:f:b:d:r:u:")) != -1) {
		switch (c) {
		case 'i':
			if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,  optarg, strlen(optarg)) < 0)
				errexit(optarg);
			break;
		case 't':
			i = strtoul(optarg, NULL, 0);
			if (i < 1)
				i = 1;
			pktdelay = i * 1000;
			break;
		case 'f':
			ADD_IMAGE(RAS);
			break;
		case 'b':
			ADD_IMAGE(BACKUP);
			break;
		case 'd':
			ADD_IMAGE(ROM);
			break;
		case 'r':
			ADD_IMAGE(ROMD);
			break;
		case 'u':
#ifdef DO_BOOTBASE
			ADD_IMAGE(BOOTBASE);
			break;
#endif
		default:
			usage(argv[0]);
		}
	}

	if (!hdr.images)
		usage(argv[0]);

	fprintf(stderr, "Press Ctrl+C to stop before rebooting target after upgrade\n");
	while (!exiting) {
		for (i = 0; i < _MAX_IMAGETYPE; i++) {
			if (hdr.images & BIT(i)) {
				hdr.type = BIT(i);
				hdr.flen = htonl(len[i]);
				pushimage(file[i], &hdr);
			}
		}
	};

	fprintf(stderr, "\nClosing all files\n");
	if (sockfd >= 0)
		close(sockfd);
	for (i = 0; i < _MAX_IMAGETYPE; i++)
		if (hdr.images & BIT(i))
			munmap(file[i], len[i]);

	return EXIT_SUCCESS;
}
