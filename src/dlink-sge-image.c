// SPDX-License-Identifier: GPL-2.0-or-later OR MIT
/*
 * Copyright (C) 2023 Sebastian Schaper <openwrt@sebastianschaper.net>
 *
 * This tool encrypts factory images for certain D-Link Devices
 * manufactured by SGE / T&W, e.g. COVR-C1200, COVR-P2500, DIR-882, ...
 *
 * Usage:
 *   ./dlink-sge-image DEVICE_MODEL infile outfile [-d: decrypt]
 *
 */

#include "dlink-sge-image.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE		4096

#define HEAD_MAGIC		"SHRS"
#define HEAD_MAGIC_LEN		4
#define SHA512_DIGEST_LENGTH	64
#define RSA_KEY_LENGTH_BYTES	512
#define AES_BLOCK_SIZE		16
#define HEADER_LEN		1756

unsigned char aes_iv[AES_BLOCK_SIZE];

unsigned char readbuf[BUFSIZE];
unsigned char encbuf[BUFSIZE];

unsigned int read_bytes;
unsigned long read_total;
unsigned int i;

unsigned char vendor_key[AES_BLOCK_SIZE];
BIO *rsa_private_bio;
const EVP_CIPHER *aes128;
EVP_CIPHER_CTX *aes_ctx;

FILE *input_file;
FILE *output_file;

int pass_cb(char *buf, int size, int rwflag, void *u)
{
    char *tmp = "12345678";
    size_t len = strlen(tmp);

    if (len > size)
        len = size;
    memcpy(buf, tmp, len);
    return len;
}

void image_encrypt(void)
{
	char buf[HEADER_LEN];
	const EVP_MD *sha512;
	EVP_MD_CTX *digest_before;
	EVP_MD_CTX *digest_post;
	EVP_MD_CTX *digest_vendor;
	EVP_PKEY *signing_key;
	EVP_PKEY_CTX *rsa_ctx;
	uint32_t payload_length_before, pad_len, sizebuf;
	unsigned char md_before[SHA512_DIGEST_LENGTH];
	unsigned char md_post[SHA512_DIGEST_LENGTH];
	unsigned char md_vendor[SHA512_DIGEST_LENGTH];
	unsigned char sigret[RSA_KEY_LENGTH_BYTES];
	size_t siglen;
	char footer[] = {0x00, 0x00, 0x00, 0x00, 0x30};

	// seek to position 1756 (begin of AES-encrypted data),
	// write image headers later
	memset(buf, 0, HEADER_LEN);
	fwrite(&buf, 1, HEADER_LEN, output_file);
	digest_before = EVP_MD_CTX_new();
	digest_post = EVP_MD_CTX_new();
	digest_vendor = EVP_MD_CTX_new();
	sha512 = EVP_sha512();
	EVP_DigestInit_ex(digest_before, sha512, NULL);
	EVP_DigestInit_ex(digest_post, sha512, NULL);
	EVP_DigestInit_ex(digest_vendor, sha512, NULL);

	signing_key = PEM_read_bio_PrivateKey(rsa_private_bio, NULL, pass_cb, NULL);
	rsa_ctx = EVP_PKEY_CTX_new(signing_key, NULL);

	EVP_PKEY_sign_init(rsa_ctx);
	EVP_PKEY_CTX_set_signature_md(rsa_ctx, sha512);

	memcpy(&aes_iv, &salt, AES_BLOCK_SIZE);
	aes_ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(aes_ctx, aes128, NULL, &vendor_key[0], aes_iv);
	EVP_CIPHER_CTX_set_padding(aes_ctx, 0);
	int outlen;

	while ((read_bytes = fread(&readbuf, 1, BUFSIZE, input_file)) == BUFSIZE) {
		EVP_DigestUpdate(digest_before, &readbuf[0], read_bytes);
		read_total += read_bytes;

		EVP_EncryptUpdate(aes_ctx, encbuf, &outlen, &readbuf[0], BUFSIZE);
		fwrite(&encbuf, 1, BUFSIZE, output_file);

		EVP_DigestUpdate(digest_post, &encbuf[0], BUFSIZE);
	}

	// handle last block of data (read_bytes < BUFSIZE)
	EVP_DigestUpdate(digest_before, &readbuf[0], read_bytes);
	read_total += read_bytes;

	pad_len = AES_BLOCK_SIZE - (read_total % AES_BLOCK_SIZE);
	if (pad_len == 0)
		pad_len = AES_BLOCK_SIZE;
	memset(&readbuf[read_bytes], 0, pad_len);

	EVP_EncryptUpdate(aes_ctx, encbuf, &outlen, &readbuf[0], read_bytes + pad_len);
	EVP_CIPHER_CTX_free(aes_ctx);
	fwrite(&encbuf, 1, read_bytes + pad_len, output_file);

	EVP_DigestUpdate(digest_post, &encbuf[0], read_bytes + pad_len);

	fclose(input_file);
	payload_length_before = read_total;
	printf("\npayload_length_before: %li\n", read_total);

	// copy digest state, since we need another one with vendor key appended
	EVP_MD_CTX_copy_ex(digest_vendor, digest_before);

	EVP_DigestFinal_ex(digest_before, &md_before[0], NULL);
	EVP_MD_CTX_free(digest_before);

	printf("\ndigest_before: ");
	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		printf("%02x", md_before[i]);

	EVP_DigestUpdate(digest_vendor, &vendor_key[0], AES_BLOCK_SIZE);
	EVP_DigestFinal_ex(digest_vendor, &md_vendor[0], NULL);
	EVP_MD_CTX_free(digest_vendor);

	printf("\ndigest_vendor: ");
	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		printf("%02x", md_vendor[i]);

	EVP_DigestFinal_ex(digest_post, &md_post[0], NULL);
	EVP_MD_CTX_free(digest_post);

	printf("\ndigest_post: ");
	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		printf("%02x", md_post[i]);

	fwrite(&footer, 1, 5, output_file);

	// go back to file header and write all the digests and signatures
	fseek(output_file, 0, SEEK_SET);

	fwrite(HEAD_MAGIC, 1, HEAD_MAGIC_LEN, output_file);

	// write payload length before
	sizebuf = htonl(payload_length_before);
	fwrite((char *) &sizebuf, 1, 4, output_file);

	// write payload length post
	payload_length_before += pad_len;
	sizebuf = htonl(payload_length_before);
	fwrite((char *) &sizebuf, 1, 4, output_file);

	// write salt and digests
	fwrite(salt, 1, AES_BLOCK_SIZE, output_file);
	fwrite(&md_vendor[0], 1, SHA512_DIGEST_LENGTH, output_file);
	fwrite(&md_before[0], 1, SHA512_DIGEST_LENGTH, output_file);
	fwrite(&md_post[0],   1, SHA512_DIGEST_LENGTH, output_file);

	// zero-fill rsa_pub field, unused in header
	memset(sigret, 0, RSA_KEY_LENGTH_BYTES);
	fwrite(&sigret[0], 1, RSA_KEY_LENGTH_BYTES, output_file);

	// sign md_before
	EVP_PKEY_sign(rsa_ctx, &sigret[0], &siglen, &md_before[0], SHA512_DIGEST_LENGTH);
	printf("\nsigned before:\n");
	for (i = 0; i < RSA_KEY_LENGTH_BYTES; i++)
		printf("%02x", sigret[i]);
	fwrite(&sigret[0], 1, RSA_KEY_LENGTH_BYTES, output_file);

	// sign md_post
	EVP_PKEY_sign(rsa_ctx, &sigret[0], &siglen, &md_post[0], SHA512_DIGEST_LENGTH);
	printf("\nsigned post:\n");
	for (i = 0; i < RSA_KEY_LENGTH_BYTES; i++)
		printf("%02x", sigret[i]);
	fwrite(&sigret[0], 1, RSA_KEY_LENGTH_BYTES, output_file);

	printf("\n");

	fclose(output_file);
}

void image_decrypt(void)
{
	char magic[4];
	uint32_t payload_length_before, payload_length_post, pad_len;
	char salt[AES_BLOCK_SIZE];
	char md_vendor[SHA512_DIGEST_LENGTH];
	char md_before[SHA512_DIGEST_LENGTH];
	char md_post[SHA512_DIGEST_LENGTH];
	EVP_PKEY *signing_key;
	EVP_PKEY_CTX *rsa_ctx;
	unsigned char rsa_sign_before[RSA_KEY_LENGTH_BYTES];
	unsigned char rsa_sign_post[RSA_KEY_LENGTH_BYTES];
	unsigned char md_post_actual[SHA512_DIGEST_LENGTH];
	unsigned char md_before_actual[SHA512_DIGEST_LENGTH];
	unsigned char md_vendor_actual[SHA512_DIGEST_LENGTH];
	const EVP_MD *sha512;
	EVP_MD_CTX *digest_before;
	EVP_MD_CTX *digest_post;
	EVP_MD_CTX *digest_vendor;

	printf("\ndecrypt mode\n");

	if (fread(&magic, 1, HEAD_MAGIC_LEN, input_file) == 0)
		goto error_read;
	if (strncmp(magic, HEAD_MAGIC, HEAD_MAGIC_LEN) != 0) {
		fprintf(stderr, "Input File header magic does not match '%s'.\n"
			"Maybe this file is not encrypted?\n", HEAD_MAGIC);
		goto error;
	}

	if (fread((char *) &payload_length_before, 1, 4, input_file) == 0)
		goto error_read;
	if (fread((char *) &payload_length_post, 1, 4, input_file) == 0)
		goto error_read;
	payload_length_before = ntohl(payload_length_before);
	payload_length_post   = ntohl(payload_length_post);

	if (fread(salt, 1, AES_BLOCK_SIZE, input_file) == 0)
		goto error_read;
	if (fread(md_vendor, 1, SHA512_DIGEST_LENGTH, input_file) == 0)
		goto error_read;
	if (fread(md_before, 1, SHA512_DIGEST_LENGTH, input_file) == 0)
		goto error_read;
	if (fread(md_post, 1, SHA512_DIGEST_LENGTH, input_file) == 0)
		goto error_read;

	// skip rsa_pub
	if (fread(readbuf, 1, RSA_KEY_LENGTH_BYTES, input_file) == 0)
		goto error_read;

	if (fread(rsa_sign_before, 1, RSA_KEY_LENGTH_BYTES, input_file) == 0)
		goto error_read;
	if (fread(rsa_sign_post, 1, RSA_KEY_LENGTH_BYTES, input_file) == 0)
		goto error_read;

	// file should be at position HEADER_LEN now, start AES decryption
	digest_before = EVP_MD_CTX_new();
	digest_post = EVP_MD_CTX_new();
	digest_vendor = EVP_MD_CTX_new();
	sha512 = EVP_sha512();
	EVP_DigestInit_ex(digest_before, sha512, NULL);
	EVP_DigestInit_ex(digest_post, sha512, NULL);
	EVP_DigestInit_ex(digest_vendor, sha512, NULL);

	memcpy(&aes_iv, &salt, AES_BLOCK_SIZE);
	aes_ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(aes_ctx, aes128, NULL, &vendor_key[0], aes_iv);
	EVP_CIPHER_CTX_set_padding(aes_ctx, 0);
	int outlen;
	pad_len = payload_length_post - payload_length_before;

	while (read_total < payload_length_post) {
		if (read_total + BUFSIZE <= payload_length_post)
			read_bytes = fread(&readbuf, 1, BUFSIZE, input_file);
		else
			read_bytes = fread(&readbuf, 1, payload_length_post - read_total, \
				input_file);

		read_total += read_bytes;

		EVP_DigestUpdate(digest_post, &readbuf[0], read_bytes);

		EVP_DecryptUpdate(aes_ctx, encbuf, &outlen, &readbuf[0], read_bytes);

		// only update digest_before until payload_length_before,
		// do not hash decrypted padding
		if (read_total > payload_length_before) {
			// only calc hash for data before padding
			EVP_DigestUpdate(digest_before, &encbuf[0], read_bytes - pad_len);
			fwrite(&encbuf[0], 1, read_bytes - pad_len, output_file);

			// copy digest state, since we need another one with vendor key appended
			EVP_MD_CTX_copy_ex(digest_vendor, digest_before);

			// append vendor_key
			EVP_DigestUpdate(digest_vendor, &vendor_key[0], AES_BLOCK_SIZE);
		} else {
			// calc hash for all of read_bytes
			EVP_DigestUpdate(digest_before, &encbuf[0], read_bytes);
			fwrite(&encbuf[0], 1, read_bytes, output_file);
		}
	}

	fclose(input_file);
	fclose(output_file);
	EVP_CIPHER_CTX_free(aes_ctx);

	EVP_DigestFinal_ex(digest_post, &md_post_actual[0], NULL);
	EVP_MD_CTX_free(digest_post);

	printf("\ndigest_post: ");
	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		printf("%02x", md_post_actual[i]);

	if (strncmp(md_post, (char *) md_post_actual, SHA512_DIGEST_LENGTH) != 0) {
		fprintf(stderr, "SHA512 post does not match file contents.\n");
		goto error;
	}

	EVP_DigestFinal_ex(digest_before, &md_before_actual[0], NULL);
	EVP_MD_CTX_free(digest_before);

	printf("\ndigest_before: ");
	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		printf("%02x", md_before_actual[i]);

	if (strncmp(md_before, (char *) md_before_actual, SHA512_DIGEST_LENGTH) != 0) {
		fprintf(stderr, "SHA512 before does not match decrypted payload.\n");
		goto error;
	}

	EVP_DigestFinal_ex(digest_vendor, &md_vendor_actual[0], NULL);
	EVP_MD_CTX_free(digest_vendor);

	printf("\ndigest_vendor: ");
	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		printf("%02x", md_vendor_actual[i]);

	if (strncmp(md_vendor, (char *) md_vendor_actual, SHA512_DIGEST_LENGTH) != 0) {
		fprintf(stderr, "SHA512 vendor does not match decrypted payload padded" \
			" with vendor key.\n");
		goto error;
	}

	signing_key = PEM_read_bio_PrivateKey(rsa_private_bio, NULL, pass_cb, NULL);
	rsa_ctx = EVP_PKEY_CTX_new(signing_key, NULL);
	EVP_PKEY_verify_init(rsa_ctx);
	EVP_PKEY_CTX_set_signature_md(rsa_ctx, sha512);

	if (EVP_PKEY_verify(rsa_ctx, &rsa_sign_before[0], RSA_KEY_LENGTH_BYTES, \
		&md_before_actual[0], SHA512_DIGEST_LENGTH)) {
		printf("\nsignature before verification success");
	} else {
		fprintf(stderr, "Signature before verification failed.\nThe decrypted" \
			" image file may however be flashable via bootloader recovery.\n");
	}

	if (EVP_PKEY_verify(rsa_ctx, &rsa_sign_post[0], RSA_KEY_LENGTH_BYTES, \
		&md_post_actual[0], SHA512_DIGEST_LENGTH)) {
		printf("\nsignature post verification success");
	} else {
		fprintf(stderr, "Signature post verification failed.\nThe decrypted" \
			" image file may however be flashable via bootloader recovery.\n");
	}

	printf("\n");

	return;

error_read:
	fprintf(stderr, "Error reading header fields from input file.\n");
error:
	fclose(input_file);
	fclose(output_file);
	exit(1);
}

/*
  generate legacy vendor key for COVR-C1200, COVR-P2500, DIR-882, DIR-2660, ...
  decrypt ciphertext key2 using aes128 with key1 and iv, write result to *vkey
*/
void generate_vendorkey_legacy(unsigned char *vkey)
{
	int outlen;
	memcpy(&aes_iv, &iv, AES_BLOCK_SIZE);
	aes_ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(aes_ctx, aes128, NULL, &key1[0], &aes_iv[0]);
	EVP_CIPHER_CTX_set_padding(aes_ctx, 0);
	EVP_DecryptUpdate(aes_ctx, vkey, &outlen, &key2[0], AES_BLOCK_SIZE);
	EVP_CIPHER_CTX_free(aes_ctx);
}

/*
  helper function for generate_vendorkey_dimgkey()
  deinterleave input in chunks of 8 bytes according to pattern,
  last block shorter than 8 bytes is appended in reverse order
*/
void deinterleave(unsigned char *enk, size_t len, unsigned char *vkey)
{
	unsigned char i, pattern = 0;

	while (len >= INTERLEAVE_BLOCK_SIZE)
	{
		for (i = 0; i < INTERLEAVE_BLOCK_SIZE; i++)
			*(vkey + i) = *(enk + interleaving_pattern[pattern][i]);

		vkey += INTERLEAVE_BLOCK_SIZE;
		enk += INTERLEAVE_BLOCK_SIZE;
		len -= INTERLEAVE_BLOCK_SIZE;

		if (pattern++ >= INTERLEAVE_BLOCK_SIZE)
			pattern = 0;
	}

	for (i = 0; i < len; i++)
		*(vkey + i) = *(enk + (len - i - 1));
}

/*
  generate vendor key for COVR-X1860, DIR-X3260, ...
  base64 decode enk, pass to deinterleave, result will be in *vkey
*/
void generate_vendorkey_dimgkey(const unsigned char *enk, size_t len, unsigned char *vkey)
{
	unsigned char *decode_buf = malloc(3 * (len / 4));
	int outlen;
	EVP_ENCODE_CTX *base64_ctx = EVP_ENCODE_CTX_new();
	EVP_DecodeInit(base64_ctx);
	EVP_DecodeUpdate(base64_ctx, decode_buf, &outlen, enk, len);
	EVP_DecodeFinal(base64_ctx, decode_buf + outlen, &outlen);
	EVP_ENCODE_CTX_free(base64_ctx);

	// limit deinterleaving output to first 16 bytes
	deinterleave(decode_buf, AES_BLOCK_SIZE, vkey);
}

int main(int argc, char **argv)
{
	if (argc < 3 || argc > 5) {
		fprintf(stderr, "Usage:\n"
			"\tdlink-sge-image DEVICE_MODEL infile outfile [-d: decrypt]\n\n"
			"DEVICE_MODEL can be any of:\n"
			"\tCOVR-C1200\n"
			"\tCOVR-P2500\n"
			"\tCOVR-X1860\n"
			"\tDIR-853\n"
			"\tDIR-867\n"
			"\tDIR-878\n"
			"\tDIR-882\n"
			"\tDIR-1935\n"
			"\tDIR-2150\n"
			"\tDIR-X3260\n\n"
			"Any other value will default to COVR-C1200/P2500/DIR-8xx keys\n"
			"which may work to decrypt images for several further devices,\n"
			"however there are currently no private keys known that would\n"
			"allow for signing images to be used for flashing those devices.\n\n"
			);
		exit(1);
	}

	input_file = fopen(argv[2], "rb");
	if (input_file == NULL) {
		fprintf(stderr, "Input File %s could not be opened.\n", argv[2]);
		exit(1);
	}

	output_file = fopen(argv[3], "wb");
	if (input_file == NULL) {
		fprintf(stderr, "Output File %s could not be opened.\n", argv[3]);
		fclose(input_file);
		exit(1);
	}

	aes128 = EVP_aes_128_cbc();

	if (strncmp(argv[1], "COVR-X1860", 10) == 0)
	{
		generate_vendorkey_dimgkey(enk_covrx1860, sizeof(enk_covrx1860), &vendor_key[0]);
		rsa_private_bio = BIO_new_mem_buf(key_covrx1860_pem, -1);
	}
	else if (strncmp(argv[1], "DIR-X3260", 9) == 0)
	{
		generate_vendorkey_dimgkey(enk_dirx3260, sizeof(enk_dirx3260), &vendor_key[0]);
		rsa_private_bio = BIO_new_mem_buf(key_dirx3260_pem, -1);
	}
	else if (strncmp(argv[1], "DIR-1260", 8) == 0)
	{
		generate_vendorkey_legacy(&vendor_key[0]);
		rsa_private_bio = BIO_new_mem_buf(key_dir1260_pem, -1);
	}
	else if (strncmp(argv[1], "DIR-2150", 8) == 0)
	{
		generate_vendorkey_legacy(&vendor_key[0]);
		rsa_private_bio = BIO_new_mem_buf(key_dir2150_pem, -1);
	}
	else
	{
		/* COVR-C1200, COVR-P2500, DIR-853, DIR-867, DIR-878, DIR-882, DIR-1935 */
		generate_vendorkey_legacy(&vendor_key[0]);
		rsa_private_bio = BIO_new_mem_buf(key_legacy_pem, -1);
	}

	printf("\nvendor_key: ");
	for (i = 0; i < AES_BLOCK_SIZE; i++)
		printf("%02x", vendor_key[i]);

	if (argc == 5 && strncmp(argv[4], "-d", 2) == 0)
		image_decrypt();
	else
		image_encrypt();
}
