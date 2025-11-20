// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mktag_kernel.c - utility to write the tag_kernel file for TP Link Deco X20 jffs2 filesystem lookup
 *
 * Copyright (C) 2024 Damien Mascord <tusker@tusker.org>
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>

int fpread(void *buffer, size_t size, size_t nitems, size_t offset, FILE *fp);

typedef struct __attribute__((scalar_storage_order("little-endian"))) _LINUX_FILE_TAG
{
	int32_t rootfsLen;
	int32_t binCrc32;
	int32_t reserved[126];
}LINUX_FILE_TAG;

void usage(void) __attribute__ (( __noreturn__ ));

void usage(void)
{
	fprintf(stderr, "Usage: mktag_kernel [-s <rootfsLen>] [-o <outputfile>] [-t (test mode)]\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	char buf[1024];	/* keep this at 1k or adjust garbage calc below */
	FILE *in = stdin, *out = stdout;
	char *ofn = NULL, *rootfsLen = NULL;
	size_t n;
	int c, first_block = 1;
	unsigned char tag_buf[sizeof(LINUX_FILE_TAG)];
	LINUX_FILE_TAG * pKern_tag = (LINUX_FILE_TAG *)tag_buf;
	int testMode = 0;

	while ((c = getopt(argc, argv, "s:o:h:t")) != -1) {
		switch (c) {
			case 's':
				rootfsLen = optarg;
				break;
			case 'o':
				ofn = optarg;
				break;
			case 't':
				testMode = 1;
				break;
			case 'h':
			default:
				usage();
		}
	}
	
	if (ofn && !(out = fopen(ofn, "wb"))) {
		fprintf(stderr, "can not open \"%s\" for writing\n", ofn);
		usage();
	}
	
	memset(tag_buf, 0, sizeof(LINUX_FILE_TAG));
	
	if (!rootfsLen)
	{
		usage();
	}
	
	pKern_tag->rootfsLen = strtol(rootfsLen, NULL, 10);
	pKern_tag->binCrc32 = 0;
	
	if (testMode)
	{
		for (int xx = 0; xx < sizeof(LINUX_FILE_TAG); xx++)
		{
			 printf("%.2X", ((unsigned char *)pKern_tag)[xx]);
		}
		printf("\n");
	}
	
	int flag = 0;
    flag = fwrite(pKern_tag, sizeof(LINUX_FILE_TAG), 1, out);
    fflush(out);
    fclose(out);
    
    if (testMode)
	{
		if (ofn && !(out = fopen(ofn, "rb"))) {
			fprintf(stderr, "can not open \"%s\" for reading\n", ofn);
			usage();
		}
		//clear it out
		memset(tag_buf, 0, sizeof(LINUX_FILE_TAG));
		fpread(tag_buf, 1, sizeof(LINUX_FILE_TAG), 0, out);
	}
	
}


int fpread(void *buffer, size_t size, size_t nitems, size_t offset, FILE *fp)
{
	 printf("fpread %d %d %d \n", size, nitems, offset);
     int seekPosition = fseek(fp, offset, SEEK_SET);
     printf("seekPosition: %d\n", seekPosition);
     if(seekPosition != 0)
     {
		 printf("unable to seek to %d\n", offset);
         return 0;
	 }
     int returnValue = fread(buffer, size, nitems, fp);
     printf("returnValue %d:\n",returnValue);
     for (int i = 0; i < nitems; i++)
     {
	 	 printf("%.2X", ((unsigned char *)buffer)[i]);
	 }
	 printf(".\n");
     return returnValue;
}

