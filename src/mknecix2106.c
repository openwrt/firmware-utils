/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Build a Bootstrap-compatible IX2106 RAM RAP or two-record NOR image.
 * The format constants below are protocol fields, not copied firmware data.
 */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

#define SHIM_SIZE_MAX 0x10000u
#define SHIM_ADDRESS 0x00020000u
#define KERNEL_ADDRESS 0x02000000u
#define KERNEL_LIMIT 0x01000000u
#define NOR_SIZE 27000832u
#define ERASE_SIZE 0x00020000u
#define RECORD_HEADER_SIZE 0xc6u
#define KERNEL_REGION_SIZE 0x00800000u
#define ROOTFS_RECORD_OFFSET 0x00800000u
#define ROOTFS_OFFSET 0x00820000u
#define ROOTFS_SIZE (NOR_SIZE - ROOTFS_OFFSET)
#define NOR_FS_DEVICE_OFFSET 0x00400000u
#define NAME_SIZE 0x50u
#define ROOTFS_NAME "openwrt-rootfs"
#define KERNEL_NAME "ix2106-openwrt.ldc"
#define ERASED_BYTE 0xffu

struct buffer {
	uint8_t *data;
	size_t size;
};

static void put_be32(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)(value >> 24);
	p[1] = (uint8_t)(value >> 16);
	p[2] = (uint8_t)(value >> 8);
	p[3] = (uint8_t)value;
}

static uint32_t get_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
	       (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t get_le64(const uint8_t *p)
{
	return (uint64_t)get_le32(p) | (uint64_t)get_le32(p + 4) << 32;
}

static uint32_t align_up(uint32_t value, uint32_t alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
		"Usage: %s --mode ram|factory --shim FILE --kernel FILE "
		"[--rootfs FILE] --output FILE\n"
		"  ram:     shim (1..65536 bytes) and raw kernel; writes a RAP image\n"
		"  factory: same RAP wrapped in the NOR FS layout; --rootfs required\n",
		program);
}

static int read_file(const char *path, struct buffer *buffer)
{
	FILE *file;
	long length;

	file = fopen(path, "rb");
	if (!file) {
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		return -1;
	}
	if (fseek(file, 0, SEEK_END) || (length = ftell(file)) < 0 ||
	    fseek(file, 0, SEEK_SET)) {
		fprintf(stderr, "%s: cannot determine input size\n", path);
		fclose(file);
		return -1;
	}
	buffer->size = (size_t)length;
	buffer->data = malloc(buffer->size ? buffer->size : 1);
	if (!buffer->data) {
		fprintf(stderr, "%s: out of memory\n", path);
		fclose(file);
		return -1;
	}
	if (buffer->size && fread(buffer->data, 1, buffer->size, file) != buffer->size) {
		fprintf(stderr, "%s: short read\n", path);
		free(buffer->data);
		buffer->data = NULL;
		fclose(file);
		return -1;
	}
	if (fclose(file)) {
		fprintf(stderr, "%s: close failed\n", path);
		free(buffer->data);
		buffer->data = NULL;
		return -1;
	}
	return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t size)
{
	FILE *file = fopen(path, "wb");
	if (!file) {
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		return -1;
	}
	size_t written = fwrite(data, 1, size, file);
	int close_error = fclose(file);
	if (written != size || close_error) {
		fprintf(stderr, "%s: write failed\n", path);
		return -1;
	}
	return 0;
}

static uint32_t crc32_msb(const uint8_t *data, size_t size)
{
	uint32_t crc = 0;
	size_t i;
	unsigned bit;

	for (i = 0; i < size; i++) {
		crc ^= (uint32_t)data[i] << 24;
		for (bit = 0; bit < 8; bit++)
			crc = (crc & 0x80000000u) ?
				((crc << 1) ^ 0x04c11db7u) : crc << 1;
	}
	return crc;
}

static int append(uint8_t *out, size_t capacity, size_t *position,
		   const void *data, size_t size)
{
	if (size > capacity - *position)
		return -1;
	memcpy(out + *position, data, size);
	*position += size;
	return 0;
}

static int append_u32(uint8_t *out, size_t capacity, size_t *position,
		      uint32_t value)
{
	uint8_t encoded[4];
	put_be32(encoded, value);
	return append(out, capacity, position, encoded, sizeof(encoded));
}

static int append_record(uint8_t *out, size_t capacity, size_t *position,
			 const struct buffer *payload, uint32_t address)
{
	static const uint8_t record_magic[] = { 0x02, 0x8c };
	size_t p = 0;
	uint8_t flags;

	if (!payload->size || payload->size > UINT32_MAX || address & 3)
		return -1;
	if (append(out, capacity, position, record_magic, sizeof(record_magic)) ||
	    append_u32(out, capacity, position, (uint32_t)payload->size) ||
	    append_u32(out, capacity, position, address))
		return -1;
	while (payload->size - p >= 8) {
		flags = 0xff;
		if (append(out, capacity, position, &flags, 1) ||
		    append(out, capacity, position, payload->data + p, 8))
			return -1;
		p += 8;
	}
	flags = (uint8_t)((1u << (payload->size - p)) - 1u);
	if (append(out, capacity, position, &flags, 1) ||
	    append(out, capacity, position, payload->data + p, payload->size - p))
		return -1;
	/* zero-source back-reference terminates each literal-only LZSS stream */
	{
		static const uint8_t end_marker[] = { 0, 0 };
		return append(out, capacity, position, end_marker, sizeof(end_marker));
	}
}

static int record_size_bound(size_t size, size_t *bound)
{
	size_t flags = size / 8 + 1;

	if (size > SIZE_MAX - flags - 13)
		return -1;
	*bound = size + flags + 13;
	return 0;
}

static int make_rap(const struct buffer *shim, const struct buffer *kernel,
		    struct buffer *rap)
{
	static const uint8_t prefix[] = {
		0x03, 0x00, 0x00, 0x00, 0x00, 0x25,
		0xac, 0xce, 0xac, 0xce, 0x88, 0x88, 0x88, 0x88,
		0x01, 0x00, 0x00, 0x00, 0x15,
		'O', 'p', 'e', 'n', 'W', 'r', 't', ' ', 'I', 'X', '2', '1', '0', '6',
		' ', 'R', 'A', 'M', ' ', 'i', 'm', 'a', 'g', 'e'
	};
	uint8_t end_record[10] = { 0x02, 0x8c };
	size_t capacity, shim_bound, kernel_bound, p = 0, crc_start;

	if (!shim->size || shim->size > SHIM_SIZE_MAX ||
	    !kernel->size || kernel->size > KERNEL_LIMIT) {
		fprintf(stderr, "shim must be 1..65536 bytes and kernel must fit in 16 MiB\n");
		return -1;
	}
	if (kernel->size >= 4 &&
	    (!memcmp(kernel->data, "\x7f" "ELF", 4) ||
	     !memcmp(kernel->data, "\x27\x05\x19\x56", 4))) {
		fprintf(stderr, "kernel must be a raw wrapper binary, not ELF/uImage\n");
		return -1;
	}
	if (record_size_bound(shim->size, &shim_bound) ||
	    record_size_bound(kernel->size, &kernel_bound)) {
		fprintf(stderr, "input size overflow\n");
		return -1;
	}
	capacity = sizeof(prefix);
	if (shim_bound > SIZE_MAX - capacity ||
	    kernel_bound > SIZE_MAX - capacity - shim_bound ||
	    sizeof(end_record) + sizeof(uint32_t) >
		SIZE_MAX - capacity - shim_bound - kernel_bound) {
		fprintf(stderr, "input size overflow\n");
		return -1;
	}
	capacity += shim_bound + kernel_bound + sizeof(end_record) +
		sizeof(uint32_t);
	rap->data = malloc(capacity);
	if (!rap->data) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	rap->size = 0;
	if (append(rap->data, capacity, &p, prefix, sizeof(prefix)))
		goto overflow;
	crc_start = p;
	if (append_record(rap->data, capacity, &p, shim, SHIM_ADDRESS) ||
	    append_record(rap->data, capacity, &p, kernel, KERNEL_ADDRESS))
		goto overflow;
	put_be32(end_record + 2, 0);
	put_be32(end_record + 6, SHIM_ADDRESS);
	if (append(rap->data, capacity, &p, end_record, sizeof(end_record)))
		goto overflow;
	if (append_u32(rap->data, capacity, &p,
		       crc32_msb(rap->data + crc_start, p - crc_start)))
		goto overflow;
	rap->size = p;
	return 0;
overflow:
	fprintf(stderr, "RAP output size overflow\n");
	free(rap->data);
	rap->data = NULL;
	return -1;
}

static int name_field(uint8_t *header, const char *name)
{
	size_t length = strlen(name);
	if (!length || length >= NAME_SIZE)
		return -1;
	memcpy(header + 8, name, length);
	return 0;
}

static int put_fs_record(uint8_t *image, size_t image_size, size_t offset,
			 const char *name, const uint8_t *payload,
			 size_t payload_size)
{
	uint8_t digest[16];
	MD5_CTX md5;
	if (payload_size > UINT32_MAX || offset > image_size ||
	    RECORD_HEADER_SIZE > image_size - offset ||
	    payload_size > image_size - offset - RECORD_HEADER_SIZE)
		return -1;
	put_be32(image + offset, (uint32_t)payload_size);
	image[offset + 4] = 0x18;
	image[offset + 5] = 0x02;
	image[offset + 6] = 0xff;
	image[offset + 7] = 0xff;
	memset(image + offset + 8, 0, NAME_SIZE);
	if (name_field(image + offset, name))
		return -1;
	memset(image + offset + 0x58, 0xff, 8);
	MD5_Init(&md5);
	MD5_Update(&md5, payload, (unsigned long)payload_size);
	MD5_Final(digest, &md5);
	memcpy(image + offset + 0x60, digest, sizeof(digest));
	memcpy(image + offset + RECORD_HEADER_SIZE, payload, payload_size);
	return 0;
}

static int make_factory(const struct buffer *rap, const struct buffer *rootfs,
			 struct buffer *image)
{
	uint64_t bytes_used;
	uint32_t rootfs_data_offset;
	size_t rootfs_payload_offset, rootfs_payload_size;
	uint8_t *rootfs_payload;
	MD5_CTX md5;
	uint8_t digest[16];

	if (rootfs->size < 48 || memcmp(rootfs->data, "hsqs", 4)) {
		fprintf(stderr, "rootfs must be a complete little-endian SquashFS image\n");
		return -1;
	}
	bytes_used = get_le64(rootfs->data + 40);
	if (!bytes_used || bytes_used != rootfs->size || rootfs->size > ROOTFS_SIZE) {
		fprintf(stderr, "invalid SquashFS bytes_used or rootfs size\n");
		return -1;
	}
	rootfs_data_offset = ROOTFS_OFFSET + align_up((uint32_t)bytes_used, ERASE_SIZE);
	if (rootfs_data_offset > NOR_SIZE ||
	    NOR_SIZE - rootfs_data_offset < ERASE_SIZE) {
		fprintf(stderr, "less than one erase sector remains for rootfs_data\n");
		return -1;
	}
	image->data = malloc(NOR_SIZE);
	if (!image->data) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	image->size = NOR_SIZE;
	memset(image->data, ERASED_BYTE, image->size);
	if (rap->size > KERNEL_REGION_SIZE - RECORD_HEADER_SIZE ||
	    put_fs_record(image->data, image->size, 0, KERNEL_NAME,
			  rap->data, rap->size)) {
		fprintf(stderr, "kernel RAP does not fit in the 8 MiB record region\n");
		goto fail;
	}
	rootfs_payload_offset = ROOTFS_RECORD_OFFSET + RECORD_HEADER_SIZE;
	rootfs_payload_size = NOR_SIZE - rootfs_payload_offset;
	memcpy(image->data + ROOTFS_OFFSET, rootfs->data, rootfs->size);
	image->data[rootfs_data_offset + 0] = 0xde;
	image->data[rootfs_data_offset + 1] = 0xad;
	image->data[rootfs_data_offset + 2] = 0xc0;
	image->data[rootfs_data_offset + 3] = 0xde;
	rootfs_payload = image->data + rootfs_payload_offset;
	MD5_Init(&md5);
	MD5_Update(&md5, rootfs_payload, (unsigned long)rootfs_payload_size);
	MD5_Final(digest, &md5);
	put_be32(image->data + ROOTFS_RECORD_OFFSET, (uint32_t)rootfs_payload_size);
	image->data[ROOTFS_RECORD_OFFSET + 4] = 0x18;
	image->data[ROOTFS_RECORD_OFFSET + 5] = 0x02;
	image->data[ROOTFS_RECORD_OFFSET + 6] = 0xff;
	image->data[ROOTFS_RECORD_OFFSET + 7] = 0xff;
	memset(image->data + ROOTFS_RECORD_OFFSET + 8, 0, NAME_SIZE);
	if (name_field(image->data + ROOTFS_RECORD_OFFSET, ROOTFS_NAME))
		goto fail;
	memset(image->data + ROOTFS_RECORD_OFFSET + 0x58, 0xff, 8);
	memcpy(image->data + ROOTFS_RECORD_OFFSET + 0x60, digest, sizeof(digest));
	return 0;
fail:
	free(image->data);
	image->data = NULL;
	image->size = 0;
	return -1;
}

int main(int argc, char **argv)
{
	const char *mode = NULL, *shim_path = NULL, *kernel_path = NULL;
	const char *rootfs_path = NULL, *output_path = NULL;
	struct buffer shim = { 0 }, kernel = { 0 }, rootfs = { 0 };
	struct buffer rap = { 0 }, output = { 0 };
	int i, result = EXIT_FAILURE;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
		else if (!strcmp(argv[i], "--shim") && i + 1 < argc) shim_path = argv[++i];
		else if (!strcmp(argv[i], "--kernel") && i + 1 < argc) kernel_path = argv[++i];
		else if (!strcmp(argv[i], "--rootfs") && i + 1 < argc) rootfs_path = argv[++i];
		else if (!strcmp(argv[i], "--output") && i + 1 < argc) output_path = argv[++i];
		else {
			usage(stderr, argv[0]);
			goto done;
		}
	}
	if (!mode || !shim_path || !kernel_path || !output_path ||
	    (strcmp(mode, "ram") && strcmp(mode, "factory")) ||
	    (!strcmp(mode, "ram") && rootfs_path) ||
	    (!strcmp(mode, "factory") && !rootfs_path)) {
		usage(stderr, argv[0]);
		goto done;
	}
	if (read_file(shim_path, &shim) || read_file(kernel_path, &kernel))
		goto done;
	if (!strcmp(mode, "factory") && read_file(rootfs_path, &rootfs))
		goto done;
	if (make_rap(&shim, &kernel, &rap))
		goto done;
	if (!strcmp(mode, "factory") && make_factory(&rap, &rootfs, &output))
		goto done;
	if (!strcmp(mode, "ram")) {
		output = rap;
		rap.data = NULL;
		rap.size = 0;
	}
	if (write_file(output_path, output.data, output.size))
		goto done;
	printf("mode=%s size=%zu output=%s\n", mode, output.size, output_path);
	if (!strcmp(mode, "factory"))
		printf("kernel_record=0x00000000 rootfs_record=0x00800000 "
		       "rootfs_offset=0x00820000 rootfs_data_offset=0x%08x "
		       "rootfs_data_size=0x%08x\n",
		       ROOTFS_OFFSET + align_up((uint32_t)get_le64(rootfs.data + 40), ERASE_SIZE),
		       NOR_SIZE - (ROOTFS_OFFSET +
		       align_up((uint32_t)get_le64(rootfs.data + 40), ERASE_SIZE)));
	result = EXIT_SUCCESS;
done:
	free(shim.data);
	free(kernel.data);
	free(rootfs.data);
	free(rap.data);
	free(output.data);
	return result;
}
