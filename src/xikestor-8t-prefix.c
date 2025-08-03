// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * xikestor-8t-prefix.c - XikeStor 8T/8X Boot Prefix Tool
 * 
 * Prepends a 16-byte vendor-specific boot prefix required by XikeStor
 * SKS8300-8T and SKS8310-8X switches.
 * 
 * The prefix contains:
 *   - Segment count (2) and boot segment index (1)
 *   - Firmware version (1)
 *   - CRC32 checksum of the uImage and payload
 * 
 * This prefix is required for the bootloader to validate and boot the firmware.
 * Input should be a standard uImage file.
 *
 * Copyright (C) 2025 Samy Younsi <samy@neroteam.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#define XIKESTOR_PREFIX_SIZE  16
#define SEGMENTS              0x00000002
#define BOOT_SEGMENT          0x00000001
#define VERSION               0x00000001

/* CRC32 polynomial */
#define CRC32_POLY            0xedb88320L

/* CRC32 lookup table */
static uint32_t crc32_table[256];
static int crc32_table_initialized = 0;

/* Initialize CRC32 lookup table */
static void init_crc32_table(void)
{
    uint32_t c;
    int n, k;
    
    for (n = 0; n < 256; n++) {
        c = (uint32_t)n;
        for (k = 0; k < 8; k++) {
            c = (c & 1) ? (CRC32_POLY ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[n] = c;
    }
    crc32_table_initialized = 1;
}

/* Calculate CRC32 checksum */
static uint32_t crc32(const uint8_t *buf, size_t len)
{
    uint32_t c = 0xffffffffL;
    size_t n;
    
    if (!crc32_table_initialized)
        init_crc32_table();
    
    for (n = 0; n < len; n++) {
        c = crc32_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
    }
    
    return c ^ 0xffffffffL;
}

/* Write 32-bit value in big-endian format */
static inline void write_be32(uint8_t *buf, uint32_t val)
{
    buf[0] = (val >> 24) & 0xff;
    buf[1] = (val >> 16) & 0xff;
    buf[2] = (val >> 8) & 0xff;
    buf[3] = val & 0xff;
}

/* Print usage information */
static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -i <input> -o <output>\n", prog);
    fprintf(stderr, "  -i <input>   Input uImage file\n");
    fprintf(stderr, "  -o <output>  Output file with XikeStor prefix\n");
    fprintf(stderr, "  -h           Show this help message\n");
}

int main(int argc, char *argv[])
{
    const char *input_file = NULL;
    const char *output_file = NULL;
    int in_fd = -1, out_fd = -1;
    struct stat st;
    uint8_t *in_data = NULL;
    uint8_t prefix[XIKESTOR_PREFIX_SIZE];
    uint32_t crc;
    ssize_t written;
    int opt;
    int ret = EXIT_FAILURE;
    
    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "i:o:h")) != -1) {
        switch (opt) {
        case 'i':
            input_file = optarg;
            break;
        case 'o':
            output_file = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }
    
    if (!input_file || !output_file) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    /* Open input file */
    in_fd = open(input_file, O_RDONLY);
    if (in_fd < 0) {
        fprintf(stderr, "Error: Cannot open input file '%s': %s\n", 
                input_file, strerror(errno));
        goto cleanup;
    }
    
    /* Get file size */
    if (fstat(in_fd, &st) < 0) {
        fprintf(stderr, "Error: Cannot stat input file: %s\n", strerror(errno));
        goto cleanup;
    }
    
    /* Validate file size */
    if (st.st_size == 0) {
        fprintf(stderr, "Error: Input file is empty\n");
        goto cleanup;
    }
    
    if (st.st_size > (1024 * 1024 * 32)) {  /* 32MB sanity check */
        fprintf(stderr, "Error: Input file too large (%ld bytes)\n", 
                (long)st.st_size);
        goto cleanup;
    }
    
    /* Memory map input file */
    in_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, in_fd, 0);
    if (in_data == MAP_FAILED) {
        fprintf(stderr, "Error: Cannot mmap input file: %s\n", strerror(errno));
        in_data = NULL;
        goto cleanup;
    }
    
    /* Build XikeStor prefix */
    memset(prefix, 0, sizeof(prefix));
    write_be32(prefix + 0x00, SEGMENTS);
    write_be32(prefix + 0x04, BOOT_SEGMENT);
    write_be32(prefix + 0x08, VERSION);
    
    /* Calculate CRC32 of uImage + data */
    crc = crc32(in_data, st.st_size);
    write_be32(prefix + 0x0C, crc);
    
    /* Create output file */
    out_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        fprintf(stderr, "Error: Cannot create output file '%s': %s\n", 
                output_file, strerror(errno));
        goto cleanup;
    }
    
    /* Write prefix */
    written = write(out_fd, prefix, sizeof(prefix));
    if (written != sizeof(prefix)) {
        fprintf(stderr, "Error: Cannot write prefix: %s\n", 
                written < 0 ? strerror(errno) : "short write");
        goto cleanup;
    }
    
    /* Write original uImage */
    written = write(out_fd, in_data, st.st_size);
    if (written != st.st_size) {
        fprintf(stderr, "Error: Cannot write data: %s\n", 
                written < 0 ? strerror(errno) : "short write");
        goto cleanup;
    }
    
    /* Success */
    printf("Successfully prepended XikeStor prefix:\n");
    printf("  Input:  %s (%ld bytes)\n", input_file, (long)st.st_size);
    printf("  Output: %s (%ld bytes)\n", output_file, 
           (long)(st.st_size + sizeof(prefix)));
    printf("  CRC32:  0x%08x\n", crc);
    
    ret = EXIT_SUCCESS;
    
cleanup:
    if (in_data && in_data != MAP_FAILED)
        munmap(in_data, st.st_size);
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    
    return ret;
}
