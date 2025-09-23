// SPDX-License-Identifier: GPL-3.0-only
/*
 * NPK Kernel Packer - C implementation
 *
 * This tool creates MikroTik NPK packages containing kernel images.
 * It's a C reimplementation of the Python poc_pack_kernel.py tool
 * written by John Thomson <git@johnthomson.fastmail.com.au>
 * which is based on npkpy https://github.com/botlabsDev/npkpy
 * provided by @botlabsDev under GPL-3.0.
 *
 * created within minutes using Claude Sonnet 4 instructed by
 * Daniel Golle <daniel@makrotopia.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>
#include <arpa/inet.h>
#include <err.h>
#include <fcntl.h>

/* Ensure we have the file type constants */
#ifndef S_IFDIR
#define S_IFDIR 0040000 /* Directory */
#endif
#ifndef S_IFREG
#define S_IFREG 0100000 /* Regular file */
#endif

/* NPK format constants */
#define NPK_MAGIC_BYTES 0xBAD0F11E
#define NPK_NULL_BLOCK 22
#define NPK_SQUASH_FS_IMAGE 21
#define NPK_ZLIB_COMPRESSED_DATA 4

/* Container alignment */
#define SQUASHFS_ALIGNMENT 0x1000

/* File mode constants (from stat.h) */
#define FILE_MODE_EXEC (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define FILE_MODE_REG (FILE_MODE_EXEC & ~(S_IXUSR | S_IXGRP | S_IXOTH))

static char *progname;

#pragma pack(push, 1)

/* NPK file header */
typedef struct {
	uint32_t magic;		/* Magic bytes: 0x1EF1D0BA */
	uint32_t payload_len;	/* Length of all containers */
} npk_header_t;

/* Container header */
typedef struct {
	uint16_t cnt_id;	/* Container type ID */
	uint32_t payload_len;	/* Container payload length */
} container_header_t;

/* Zlib compressed object header */
typedef struct {
	uint16_t obj_mode;	/* File mode (stat.h format) */
	uint16_t zeroes1[3];	/* Padding */
	uint32_t timestamps[3];	/* create, access, modify timestamps */
	uint32_t zeroes2;	/* More padding */
	uint32_t payload_len;	/* Payload length */
	uint16_t name_len;	/* Name length */
	/* Followed by name and payload */
} zlib_obj_header_t;

#pragma pack(pop)

/* Structure to hold container data */
typedef struct {
	uint16_t cnt_id;
	uint32_t payload_len;
	uint8_t *payload;
} container_t;

/* Structure to hold zlib object data */
typedef struct {
	uint16_t obj_mode;
	uint32_t timestamps[3];
	char *name;
	uint8_t *payload;
	uint32_t payload_len;
} zlib_object_t;

/*
 * Calculate the size needed for a container including header
 */
static size_t container_full_size(const container_t *cnt)
{
	return sizeof(container_header_t) + cnt->payload_len;
}

/*
 * Write a container to a buffer
 */
static size_t write_container(uint8_t *buffer, const container_t *cnt)
{
	container_header_t *header = (container_header_t *)buffer;
	header->cnt_id = cnt->cnt_id;
	header->payload_len = cnt->payload_len;

	if (cnt->payload && cnt->payload_len > 0) {
		memcpy(buffer + sizeof(container_header_t), cnt->payload, cnt->payload_len);
	}

	return container_full_size(cnt);
}

/*
 * Create a null block container for alignment
 */
static container_t create_null_block(size_t alignment_size)
{
	container_t cnt = { 0 };
	size_t header_size, padding;

	cnt.cnt_id = NPK_NULL_BLOCK;

	/* Calculate padding needed to align next container to boundary */
	header_size = sizeof(npk_header_t) + sizeof(container_header_t);
	padding = alignment_size - (header_size + sizeof(container_header_t)) % alignment_size;
	if (padding == alignment_size)
		padding = 0;

	cnt.payload_len = padding;
	if (padding > 0) {
		if ((cnt.payload = calloc(1, padding)) == NULL)
			err(EXIT_FAILURE, "calloc");
	}

	return cnt;
}

/*
 * Create a SquashFS container with dummy payload
 */
static container_t create_squashfs_container(void)
{
	container_t cnt = { 0 };
	cnt.cnt_id = NPK_SQUASH_FS_IMAGE;
	cnt.payload_len = SQUASHFS_ALIGNMENT;

	if ((cnt.payload = calloc(1, cnt.payload_len)) == NULL)
		err(EXIT_FAILURE, "calloc");

	return cnt;
}

/*
 * Serialize a zlib object to binary format
 */
static uint8_t *serialize_zlib_object(const zlib_object_t *obj, size_t *out_size)
{
	size_t name_len = strlen(obj->name);
	size_t total_size = sizeof(zlib_obj_header_t) + name_len + obj->payload_len;
	uint8_t *buffer;
	zlib_obj_header_t *header;

	if ((buffer = malloc(total_size)) == NULL)
		err(EXIT_FAILURE, "malloc");

	header = (zlib_obj_header_t *)buffer;
	header->obj_mode = obj->obj_mode;
	memset(header->zeroes1, 0, sizeof(header->zeroes1));
	memcpy(header->timestamps, obj->timestamps, sizeof(header->timestamps));
	header->zeroes2 = 0;
	header->payload_len = obj->payload_len;
	header->name_len = name_len;

	/* Copy name */
	memcpy(buffer + sizeof(zlib_obj_header_t), obj->name, name_len);

	/* Copy payload */
	if (obj->payload && obj->payload_len > 0) {
		memcpy(buffer + sizeof(zlib_obj_header_t) + name_len, obj->payload,
		       obj->payload_len);
	}

	*out_size = total_size;
	return buffer;
}

/*
 * Compress data using the exact same method as Python implementation
 * This matches the Python set_cnt_payload_decompressed function exactly
 */
static uint8_t *compress_zlib_data(const uint8_t *input, size_t input_len, size_t *out_len,
				   size_t block_size)
{
	size_t max_output_size = input_len * 2 + 1024; /* Conservative estimate */
	uint8_t *buffer_out;
	size_t output_offset = 0;
	size_t offset = 0;
	uint32_t adler32;

	if ((buffer_out = malloc(max_output_size)) == NULL)
		err(EXIT_FAILURE, "malloc");

	/* Compression method magic - matches Python b"\x78\x01" */
	buffer_out[output_offset++] = 0x78;
	buffer_out[output_offset++] = 0x01;

	/* Initialize adler32 - matches Python zlib.adler32(b"") */
	adler32 = adler32_z(1L, NULL, 0);

	/* Process data in blocks - matches Python while loop */
	while (offset < input_len) {
		size_t buffer_in_len = (offset + block_size <= input_len) ? block_size :
									    (input_len - offset);
		const uint8_t *buffer_in = input + offset;
		uLong max_block_compressed = compressBound(buffer_in_len);
		uint8_t *compressed;
		uLong compressed_len;
		int result;

		if ((compressed = malloc(max_block_compressed)) == NULL)
			err(EXIT_FAILURE, "malloc");

		compressed_len = max_block_compressed;
		result = compress2(compressed, &compressed_len, buffer_in, buffer_in_len,
				   0); /* level=0 */

		if (result != Z_OK)
			err(EXIT_FAILURE, "compress2 failed: %d", result);

		/* Extract the right portion based on block type */
		if (buffer_in_len == block_size) {
			/* Not-last-block: block = b"\x00" + compressed[3:-4] */
			/* Skip first 3 bytes and last 4 bytes */
			size_t copy_len = compressed_len - 7;

			buffer_out[output_offset++] = 0x00;

			if (output_offset + copy_len >= max_output_size) {
				max_output_size *= 2;
				if ((buffer_out = realloc(buffer_out, max_output_size)) == NULL)
					err(EXIT_FAILURE, "realloc");
			}
			memcpy(buffer_out + output_offset, compressed + 3, copy_len);
			output_offset += copy_len;
		} else {
			/* Last block: block = compressed[2:-4] */
			size_t copy_len =
				compressed_len - 6; /* Skip first 2 bytes and last 4 bytes */

			if (output_offset + copy_len >= max_output_size) {
				max_output_size *= 2;
				if ((buffer_out = realloc(buffer_out, max_output_size)) == NULL)
					err(EXIT_FAILURE, "realloc");
			}
			memcpy(buffer_out + output_offset, compressed + 2, copy_len);
			output_offset += copy_len;
		}

		/* Update adler32 - matches Python zlib.adler32(compressed[7:-4], adler32) */
		if (compressed_len > 11) { /* Ensure we have enough bytes */
			adler32 = adler32_z(adler32, compressed + 7, compressed_len - 11);
		}

		free(compressed);
		offset += block_size;
	}

	/* Add final adler32 checksum - matches Python struct.pack(">L", adler32) */
	if (output_offset + 4 >= max_output_size) {
		max_output_size += 4;
		if ((buffer_out = realloc(buffer_out, max_output_size)) == NULL)
			err(EXIT_FAILURE, "realloc");
	}

	buffer_out[output_offset++] = (adler32 >> 24) & 0xFF;
	buffer_out[output_offset++] = (adler32 >> 16) & 0xFF;
	buffer_out[output_offset++] = (adler32 >> 8) & 0xFF;
	buffer_out[output_offset++] = adler32 & 0xFF;

	/* Shrink to actual size */
	if ((buffer_out = realloc(buffer_out, output_offset)) == NULL)
		err(EXIT_FAILURE, "realloc final");

	*out_len = output_offset;
	return buffer_out;
}

/*
 * Create a zlib compressed container with kernel objects
 */
static container_t create_zlib_container(const uint8_t *kernel_data, size_t kernel_size)
{
	container_t cnt = { 0 };
	zlib_object_t objects[3];
	uint8_t *obj_data[3];
	size_t obj_sizes[3];
	size_t total_uncompressed = 0;
	uint8_t *uncompressed_data;
	size_t offset = 0;
	size_t compressed_len;
	uint8_t *compressed_data;
	int i;

	cnt.cnt_id = NPK_ZLIB_COMPRESSED_DATA;

	/* Create zlib objects */

	/* Boot directory object */
	objects[0].obj_mode = S_IFDIR | FILE_MODE_EXEC;
	objects[0].name = "boot";
	objects[0].payload = NULL;
	objects[0].payload_len = 0;
	memset(objects[0].timestamps, 0, sizeof(objects[0].timestamps));

	/* Kernel file object */
	objects[1].obj_mode = S_IFREG | FILE_MODE_EXEC;
	objects[1].name = "boot/kernel";
	objects[1].payload = (uint8_t *)kernel_data;
	objects[1].payload_len = kernel_size;
	memset(objects[1].timestamps, 0, sizeof(objects[1].timestamps));

	/* UPGRADED file object */
	objects[2].obj_mode = S_IFREG | FILE_MODE_REG;
	objects[2].name = "UPGRADED";
	if ((objects[2].payload = calloc(1, 0x20)) == NULL)
		err(EXIT_FAILURE, "calloc");
	objects[2].payload_len = 0x20;
	memset(objects[2].timestamps, 0, sizeof(objects[2].timestamps));

	/* Serialize objects */
	for (i = 0; i < 3; i++) {
		obj_data[i] = serialize_zlib_object(&objects[i], &obj_sizes[i]);
		total_uncompressed += obj_sizes[i];
	}

	/* Concatenate all objects */
	if ((uncompressed_data = malloc(total_uncompressed)) == NULL)
		err(EXIT_FAILURE, "malloc");

	for (i = 0; i < 3; i++) {
		memcpy(uncompressed_data + offset, obj_data[i], obj_sizes[i]);
		offset += obj_sizes[i];
		free(obj_data[i]);
	}

	/* Compress the data */
	compressed_data =
		compress_zlib_data(uncompressed_data, total_uncompressed, &compressed_len, 0x8000);

	free(uncompressed_data);
	free(objects[2].payload); /* Free the UPGRADED payload we allocated */

	cnt.payload = compressed_data;
	cnt.payload_len = compressed_len;

	return cnt;
}

/*
 * Read file contents into memory
 */
static uint8_t *read_file(const char *filename, size_t *file_size)
{
	int fd;
	struct stat st;
	uint8_t *buffer;
	ssize_t read_bytes;

	if ((fd = open(filename, O_RDONLY)) == -1)
		err(EXIT_FAILURE, "%s", filename);

	if (fstat(fd, &st) == -1)
		err(EXIT_FAILURE, "%s", filename);

	*file_size = st.st_size;

	if ((buffer = malloc(*file_size)) == NULL)
		err(EXIT_FAILURE, "malloc");

	if ((read_bytes = read(fd, buffer, *file_size)) != *file_size)
		err(EXIT_FAILURE, "read %s", filename);

	close(fd);
	return buffer;
}

/*
 * Write NPK file
 */
static int write_npk_file(const char *filename, container_t *containers, int num_containers)
{
	int fd;
	uint32_t total_payload = 0;
	npk_header_t header;
	int i;

	/* Calculate total payload size */
	for (i = 0; i < num_containers; i++) {
		total_payload += container_full_size(&containers[i]);
	}

	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		err(EXIT_FAILURE, "%s", filename);

	/* Write NPK header */
	header.magic = NPK_MAGIC_BYTES;
	header.payload_len = total_payload;

	if (write(fd, &header, sizeof(header)) != sizeof(header))
		err(EXIT_FAILURE, "write header");

	/* Write containers */
	for (i = 0; i < num_containers; i++) {
		size_t container_size = container_full_size(&containers[i]);
		uint8_t *buffer;

		if ((buffer = malloc(container_size)) == NULL)
			err(EXIT_FAILURE, "malloc");

		write_container(buffer, &containers[i]);

		if (write(fd, buffer, container_size) != container_size)
			err(EXIT_FAILURE, "write container");

		free(buffer);
	}

	close(fd);
	return 0;
}

/*
 * Print usage information
 */
static void usage(void)
{
	fprintf(stderr, "Usage: %s <kernel> <output>\n", progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	const char *kernel_file;
	const char *output_file;
	size_t kernel_size;
	uint8_t *kernel_data;
	container_t containers[3];
	int i;

	progname = argv[0];

	if (argc != 3)
		usage();

	kernel_file = argv[1];
	output_file = argv[2];

	/* Read kernel file */
	kernel_data = read_file(kernel_file, &kernel_size);

	/* Create containers */
	/* Null block for alignment */
	containers[0] = create_null_block(SQUASHFS_ALIGNMENT);

	/* SquashFS container */
	containers[1] = create_squashfs_container();

	/* Zlib container with kernel */
	containers[2] = create_zlib_container(kernel_data, kernel_size);

	/* Write NPK file */
	write_npk_file(output_file, containers, 3);

	/* Cleanup */
	free(kernel_data);
	for (i = 0; i < 3; i++)
		if (containers[i].payload)
			free(containers[i].payload);

	return EXIT_SUCCESS;
}
