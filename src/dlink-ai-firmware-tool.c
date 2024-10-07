// SPDX-License-Identifier: GPL-2.0-or-later

/* 
This tool can be used to process firmware images for routers of the D-Llink AI series:
- EAGLE PRO AI AX3200 Mesh-System (M32)
- EAGLE PRO AI AX3200 Smart Router (R32)
- AQUILA PRO AI AX3000 Smart Mesh Router (M30)

Usage:
dlink-ai-firmware-tool <Device> <Operation> <InputFile> <OutputFile>

where
- <Device> can be M30, M32 or R32
- <Operation> can be:
  --UpdateFirmwareHeader: To update the length information and checksums in a firmware header
  --CreateFactoryImage: To create a factory image from a recovery image
  --DecryptFactoryImage: To decrypt a factory image (resulting in a recovery image)
*/
/***************************************************************************************************
 Description of the OEM firmware layout (Example base on M32 images)
***************************************************************************************************/
/*
The OEM firmware has the following layout, the example is based on M32_REVA_FIRMWARE_v1.00B34.bin.
----------------------------------------------------------------------------------------------------
| Address (hex)    | Length (hex) | Data
|------------------|--------------|-----------------------------------------------------------------
| 0x00000000       | 0x10         | Header for SHA512 verification of the image, details below.
| 0x00000010       | 0x10         | Header for AES-CBC decryption of the image, details below.
| 0x00000020       | 0x20         | IV for AES-CBC decryption as ASCII string.
| 0x00000040       | 0x01         | Constant 0x0A (LF)
| 0x00000041       | 0x08         | ASCII "Salted___" without trailing \0
| 0x00000049       | 0x08         | The salt for the firmware decryption.
| 0x00000051       | variable     | The encrypted data.
| variable         | 0x100        | The signature for the SHA512 verification.
----------------------------------------------------------------------------------------------------

After decrypting the encrypted data (starting at 0x00000051 in the OEM firmware image),
there can be one or more partitions in the decrypted image. In the example below, there is
a second partition, but it's optional.
Overall, there is the following layout (offset 0x00000051 not included):
----------------------------------------------------------------------------------------------------
| Address (hex)    | Length (hex) | Data
|------------------|--------------|-----------------------------------------------------------------
| 0x00000000       | 0x10         | Header for SHA512 verification of the image, details below.
| 0x00000010       | 0x50         | Header of the first partition to flash, details below.
| 0x00000060       | variable     | The decrypted data of the first partition.
| variable         | 0x50         | Header of the ssecond partition to flash, details below.
| 0x00000060       | variable     | The decrypted data of the second partition.
| variable         | 0x100        | The signature for the SHA512 verification.
----------------------------------------------------------------------------------------------------

A header for SHA512 verification has the following layout:
----------------------------------------------------------------------------------------------------
| Address (hex)    | Length (hex) | Data
|------------------|--------------|-----------------------------------------------------------------
| 0x00000000       | 0x04         | ASCII "MH01" without trailing \0
| 0x00000004       | 0x04         | Length of the data to verify (little endian format)
| 0x00000008       | 0x04         | Constant 0x00 0x01 0x00 0x00
| 0x0000000C       | 0x02         | Constant 0x2B 0x1A
| 0x0000000E       | 0x01         | Byte sum of byte 0-13
| 0x0000000F       | 0x01         | XOR of byte 0-13
----------------------------------------------------------------------------------------------------

A header for AES-CBC decryption has the following layout:
----------------------------------------------------------------------------------------------------
| Address (hex)    | Length (hex) | Data
|------------------|--------------|-----------------------------------------------------------------
| 0x00000000       | 0x04         | ASCII "MH01" without trailing \0
| 0x00000004       | 0x04         | Constant 0x21 0x01 0x00 0x00
| 0x00000008       | 0x04         | Length of the data to decrypt (little endian format)
| 0x0000000C       | 0x02         | Constant 0x2B 0x1A
| 0x0000000E       | 0x01         | Byte sum of byte 0-13
| 0x0000000F       | 0x01         | XOR of byte 0-13
----------------------------------------------------------------------------------------------------

A header of the decrypted firmware image parition has the following layout:
----------------------------------------------------------------------------------------------------
| Address (hex)    | Length (hex) | Data
|------------------|--------------|-----------------------------------------------------------------
| 0x00000000       | 0x0C         | ASCII "DLK6E6010001" without trailing \0
| 0x0000000C	     | 0x02	        | Constant 0x00 0x00
| 0x0000000E	     | 0x02         | 2-Byte sum over the data area of the partition. 
                                    If there is an overflow during calculation, the sum is increased by one.
| 0x00000010       | 0x0C         | Hex 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01 0x00
| 0x0000001C       | 0x04         | Constant 0x4E 0xCC 0xD1 0x0B (differs in different FW versions)
| 0x00000020       | 0x04         | Erase start address of the partition (little endian format)
| 0x00000024       | 0x04         | Erase length of the partition (little endian format)
| 0x00000028       | 0x04         | Write start address of the partition (little endian format)
| 0x0000002C       | 0x04         | Write length of the partition (little endian format)
| 0x00000030       | 0x10         | 16 bytes 0x00
| 0x00000040       | 0x02         | Firware header ID: 0x42 0x48
| 0x00000042       | 0x02         | Firware header major version: 0x02 0x00
| 0x00000044       | 0x02         | Firware header minior version: 0x00 0x00
| 0x00000046       | 0x02         | Firware SID: 0x09 0x00
| 0x00000048       | 0x02         | Firware image info type: 0x00 0x00
| 0x0000004A       | 0x02         | Unknown, set to 0x00 0x00
| 0x0000004C       | 0x02         | FM fmid: 0x60 0x6E. Has to be match the "fmid" of the device.
| 0x0000004E       | 0x02         | Header checksum. It must be set to that the sum of all words
|                                   in the firware equals 0xFFFF. An overflow will increase the 
|                                   checksum by 1. See function "UpdateHeaderInRecoveryImage".
----------------------------------------------------------------------------------------------------
*/
/***************************************************************************************************
 Includes
***************************************************************************************************/
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/***************************************************************************************************
 Defines
***************************************************************************************************/
/*
* Length of the header in a firmware image which can be used in the recovery web interface.
*/
#define DLINK_AI_FIRMWARE_TOOL_FW_HEADER_LENGTH          (80u)


/**
 * Maximum number of partitions in a recovery image. Assume there is a maximum of 16.
 * Currently M32 has 13 partitions, so 16 should be sufficient overall.
*/
#define DLINK_AI_FIRMWARE_TOOL_MAX_PARTITIONS            (16u)

/*
* Offset of the entry "data length" in the header of a firmware image 
* which can be used in the recovery web interface.
*/
#define DLINK_AI_FIRMWARE_TOOL_FW_DATA_LENGTH_OFFSET     (0x2C)

/*
* Offset of the entry "data checksum" in the header of a firmware image 
* which can be used in the recovery web interface.
*/
#define DLINK_AI_FIRMWARE_TOOL_DATA_CHECKSUM_OFFSET        (0x0E)

/*
* Offset of the entry "header checksum" in the header of a firmware image 
* which can be used in the recovery web interface.
*/
#define DLINK_AI_FIRMWARE_TOOL_HEADER_CHECKSUM_OFFSET      (DLINK_AI_FIRMWARE_TOOL_FW_HEADER_LENGTH - 2u)

/*
* The length of headers in the OEM images.
*/
#define DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH                  (16u)

/*
* The length of signatures in the OEM images.
*/
#define DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SIGNATURE_LENGTH               (256u)

/*
* The length of the initialization vector in the OEM images.
* It's a 32 bytes string for the IV plus a trailing 0x0A.
*/
#define DLINK_AI_FIRMWARE_TOOL_FIRMWARE_INITIALIZATION_VECTOR_LENGTH   (33u)

/**
 * 0x08 bytes for ASCII "Salted__" without trailing \0
 * 0x08 bytes for the salt
*/
#define DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SALT_INFO_LENGTH               (16u)

/**
 * Length of the data which are required for decryption of the image.
 * 0x20 bytes IV for AES-CBC decryption as ASCII string
 * 0x01 byte for terminating the IV ASCII string with 0x0A (LF)
 * 0x08 bytes for ASCII "Salted__" without trailing \0
 * 0x08 bytes for the salt
*/
#define DLINK_AI_FIRMWARE_TOOL_FIRMWARE_DECRYPTION_INFO_LENGTH \
  (DLINK_AI_FIRMWARE_TOOL_FIRMWARE_INITIALIZATION_VECTOR_LENGTH + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SALT_INFO_LENGTH)

/**
 * Enable writing of debug files.
*/
#define M32_FIMRWARE_UTIL_ENABLE_DEBUG_FILES
/***************************************************************************************************
 Types
***************************************************************************************************/
typedef struct
{
  const char* Name;
  const char* Description;
  const char* RecoveryHeaderStart;
  const char* FirmwareKey;
  const char* PrivateKey;
  const char* PublicKey;
  const char* Passphrase;
} M32FirmwareUtilDeviceInfoType;

/**
 * Function pointer type for operations in M32FirmwareUtilOperationsType.
 * Arguments:
 * inputfile: FILE handle for the input file.
 * fileStatus: Input file stats.
 * oupufFile: Name of the output file.
 * device: Pointer to the structure containing device specific information.
*/
typedef int (*M32FirmwareUtilOperation)(FILE* inputFile, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device);

/**
 * Structure for maintaining command line arguments in this tool.
 */
typedef struct
{
  /**
   * The command line argument (long version).
  */
  const char* LongArgument;

  /**
   * The command line argument (short version).
  */
  const char* ShortArgument;

  /**
   * Descsription what the argument is used for.
  */
  const char* Description;
  /**
   * The function which will be executed for this argument.
  */
  M32FirmwareUtilOperation Operation;
  /**
   * The minimum expected input file size for this argument.
  */
  size_t MinimumFileSize;
} M32FirmwareUtilOperationsType;

/***************************************************************************************************
 Function prototpyes
***************************************************************************************************/
/*****************************************************************************************
 Main Operations
*****************************************************************************************/
static int UpdateHeaderInRecoveryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device);
static int CreateFactoryImageFromRecoveryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device);
static int DecryptFactoryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device);

/*****************************************************************************************
 Signature APIs
*****************************************************************************************/
static int VerifySha512Signture(const uint8_t* buffer, const size_t bufferLength, const M32FirmwareUtilDeviceInfoType* device);
static int CreateSha512VerificatioinSignature(uint8_t* buffer, size_t imageSize, const M32FirmwareUtilDeviceInfoType* device);

/*****************************************************************************************
 AES128 CBBC APIs
*****************************************************************************************/
static int DecryptAes128Cbc(const uint8_t* encryptedData, const size_t encryptedLength, uint8_t* outputBuffer, const char* keyString, const uint8_t* ivHex);
static int EncryptAes128Cbc(const uint8_t* plainData, const size_t plainDataLength, uint8_t* outputBuffer, uint8_t* saltBuffer, const char* keyString, const uint8_t* ivHex, int* encryptedDataLength);

static int GetDataLengthFromVerificationHeader(uint8_t* header, size_t* dataLength);
static int GetDataLengthFromEncryptionHeader(uint8_t* header, size_t* dataLength);
static int ConvertAsciiIvToHexArray(const uint8_t ivAscii[AES_BLOCK_SIZE * 2], uint8_t ivHex[AES_BLOCK_SIZE]);
static int CreateAes128CbcEncryptionHeader(uint8_t* buffer, size_t imageSize);
static int CreateSha512VerificatioinHeader(uint8_t* buffer, size_t imageSize);
static int WriteBufferToFile(const uint8_t* buffer, const size_t bufferSize, const char* outputFile);
static int WriteDebugBufferToFile(const uint8_t* buffer, const size_t bufferSize, const char* outputFile);
static int WriteAes128CbcIvToBuffer(uint8_t* buffer, const uint8_t* iv, const size_t ivLength);
static void PrintUsage(char* programName);
static void PrintOpenSSLError(const char* api);

/*****************************************************************************************
 Checksum calculation
*****************************************************************************************/
static void Caclulate16BitSum(const char* name, uint32_t partitionIndex, uint8_t* buffer, size_t bufferLength, uint8_t* checksumBuffer, bool inverted);
/***************************************************************************************************
 Constants
***************************************************************************************************/
const M32FirmwareUtilOperationsType M32FirmwareUtilOperations[] =
{
  {
    "--UpdateFirmwareHeader",
    "-u",
    "Updates data length information and checksum in an existing header in a recovery image",
    &UpdateHeaderInRecoveryImage,
    DLINK_AI_FIRMWARE_TOOL_FW_HEADER_LENGTH
  },
  {
    "--CreateFactoryImage",
    "-c",
    "Create a factory image from a recovery image",
    &CreateFactoryImageFromRecoveryImage,
    /* At least 1kB of payload expected */
    1024
  },
  {
    "--DecryptFactoryImage",
    "-d",
    "Decrypts a factory image",
    &DecryptFactoryImage,
    /* Signature and header for inner and outer image plus at least 1kB payload */
    2 * (DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SIGNATURE_LENGTH + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH) + 1024
  }
};

const int M32FirmwareUtilOperationsLength = 
  sizeof(M32FirmwareUtilOperations) / sizeof(M32FirmwareUtilOperationsType);

const char E30PrivateKey[] = R"(
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,208CDA78F5F7987BE3B9C9FD4B57944E

JzjsX60KT+e+mEmpZa/zU4mX6hN5XupLnyZ70oAO2EcnsW5UIAkT7KwTYv5Htxcw
td3O7Cxg1i403v/Nof3dGsNrEZIK8x4pLS35ZE0KHsUqWrjdmASIH/MlT6cnnhlt
+Wmk4USjpbFRXvsXs7/ai1d9L7Dnd17v0yxLJIuMdhfoh4EKQ08hlB2JvJZJMNOY
cmoeEuizIPb+FgWxR6B0YXoetrBsO8qqYjcc8r7Ho/usVFcRBGM1bKBGsob44E1m
nH+fvyUVOo+9A3dx+NIfWX0PP/zjidHsQ3PmjmI7TTfqaNJJndukLS9cH269Ujgp
M77U6IxzUd3hPDRx057XAUjSOpm/CmYXN514rkt4ZXJYMyBHJ4JnNAIAqWc96lDQ
cMeKUxKTpgi24NqKldZ7Bd0pTj1Ct/+X7F5MuHAEcNH7H4tQsWkcObT5z568m0Tf
Pi+pS7XonR7OrOW6Kz8BC21pYmqCZi75k7mav3MrVDsM94jGOEmumVtEibrRsEvz
ihg3Y6bNbCjAV43ey2RTFgnhXFlvRsKOHadCLgJhhAnvqb/mHSmvUsGazw461dfb
6d1MW6oDmbNLMDo3BuLvcBixKuJfAerRTmORkBWXW6rv7o4ac7L207fXpwKVjjOs
4s39Yr73kJuPrHqlnhaD52Yt96LwVl+DHzLxk+1ixG3ak4LdR6iUFGmhbpVcLTXx
S3gxRz/aM/k7IcLAbPx8cHBbaGLWpqaBEe/bn/nZBKoxcWDCGCK13QWs/w7NJ6zY
Zz2k0y/qsYJ6SKyDaiufCU0RWkgE+qZKnZdLHTj8wAwsnCmYLDm4Lctj9zllKrID
h8JaT1AnzGrX6BBZRFbtW9WFyw59xpa9gF89TFkcAnaRR7hCfCopSkNQi6LcOiq0
1bLnjDTd++2M8MiUiGR7CiHjSbuF7Njgche1PwB9dy+D1YRo/otooTsPhliugOb0
goC6NvkbTYoQu+2jR7hs/zQ92Bz62/0d7ghdTXQu+hjsyu7OOzf4tgaGwo2k5yw2
GPRZauD5iM7Eb8xgg3VB90cVQaw0yojIj0E1GG3dwAiz4XFOlu9Vh5eLUgBSN18v
7yIwr53+VunvfAUj449agxKTHzh2ScwxRqg+7l0JMrJfoPKh+QFAQ45lnAXQxF7I
DAdJwAQF3m31ASEUdWF74YQal2qYtTR8G1IiBYH693CN/d/FpU2TChKVIAQZzMYd
aThbiQRYGMaWy+COhDf7rylYMjQc+gs82eilKn1YVF/M1t5s3aMK2zLtAiasBFyX
8ICGsfrUisFyNo0SjlhN8dKrDJuCYWscEyvzsMpVUfAf3vGGXi0y2BxYjbRPK53d
JdR3I1cf8f/EAfv9YxLHT/UqYMzPMYDhepOPysWRCmAe+X+kUb2AFR6avnxY0Nlm
aUZ7zCxhbfDb0x4Bj453aXBIt3QBI8OH06xb3HT7ym9EKoGOPaYtu66r53CHYHi3
Jwmc6ifCUCnbs5JEtv8EpHDma4+h7hFzoVfyXPysknLe9zl/UXhj49m3NwpPUhTg
4jRHEkSBUNbiyAm0vJBPtIB12NW1FbrTTeUwPSQr+UaQZyO3BTXrR4/X6eSKbrO/
-----END RSA PRIVATE KEY-----
)";

const char E30PublicKey[] = R"(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvTlL2scVXnw1qr+Xdcaa
u7nDW+Fm6uO2Km74/U8K1qo0R+imonrZNWHR0FRw78Ber8adGaWXc2fctgMYN8Yx
r+W4MUW2y0q0FAsKzOtWf0QcntV7Q4WpPzLNpu7FcyOVi0ZbMTE5+R/fFGle30p/
emNyjhXBoNQVFFzlYxRKTP+uI9wcXuW1cU0tpw9XJj6zWfaXyMD7sTJuNhGk7+IQ
WWjSQ5TaTUjTI4QegdT+mM5t5UbVl2ZQV8I306v6oHtLf28/fhAorBsWy4jQgkro
5hQK6S+Y4xZJ/5nfUPdiFM+ApshFT8BqmA/en/842LlQ2p2i2inOnM5yNVknN/67
/wIDAQAB
-----END PUBLIC KEY-----
)";

const char M18PrivateKey[] = R"(
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,8C63043D878336AE1E360896BD00BED1

F7I0ReKfhAWfoDlw9fI0Hy44/MibwmeTzJWsJYedl6fqboivA1lbR6QN8nE+xgXi
NlI+/3ZiAfiEj53WiF1nEqE+qlzGEx4zEzeCXNLJqflJi+uS7iPB8Kg4wiwCwau/
6dtPPh1pAX0xfeFaqVzoNY4IDhl8lGxYsK9GTF/ZQICyCfC/h62uxEF4tx2v1GjM
DmKNKHLOrH+BlZTDSW6fhXHCFS4QucUTdSnq3PLETt4Fy5pFJAh700LqRHUDMwGN
b9UoaRH3w7G0dRcz+dCeOjRUJSXhbFsI7oOhVGpnTLiTAK39HC1xtJqcF+gLClyG
GmeFRvG1BOaPhiF5l8iebG5xMrwZQVqstVyF6oWijTphk9juZcAOXpkd3ffml9aJ
kVsFPsssv0GzKojSzMB188GinnKRCXS7AIYJEYd0jTokYxlSJ5+30UdnUazGHYPE
myiAOiw45Cs6VXKy/qYYDjAUjJaziFZHEE6jodBND92UXeyY3cO10qjsBLmqrcS5
PPzFHmp517uzKDlaAvMi4zkFFQkNwj7qJkz7XKPi129SFOvGS26qbST4siCy8ZLz
mUt6ORPl1kwG8HD4CgLpbq5ewSrRp06KFi/LC6+TZGhqBV5lhod1eak5lgbjoDHV
CxvUSuSq8BccGnSPHH0JJqqcIKcWeP2LlkEak8sutaLZA2nDuaLOaZef/jVpfIGN
OOMldQlJ+4wJHwTpCHt4zZBFklVsPm7oF8w/bjx0/stYW7gVo8w4OqTfyk6pOnkk
t1mnio5uNGdA0PIq+gsircUziJD6E4nQr/bxnYyVaz52mjjeWhOkT84IBMBWM4hZ
KRlEu8P6z1EDUxJ1FeLrmh2qtfggI48OEJIGYNYbiwS5M3f3AugLD32XJw8FiYrp
9Of1dejSIpgt3lku7uTL5avrDUlzC4iCRkUrF1NxnAKsOtpWBRWWgEvYAaqI5huy
GzageTMQkJ8l1EIeP8JGLaqQ8YTez/sOh0YNhFk5sVTZmtqh+zOyqJ7CNIfSgRil
NWtMIaehRJRFMSfcTgAJ4kElxUz7T5mnkoeu1Km5dBB2nVb9aT1ht8KKusObafIo
w17l1O438/ReTmDmg0ppPoFt26HDS6MRIRx5kwBYxQ892jrfo+pcdZaZv0vnwAoI
2Rwe736g1KRNacubB7ZQRE0UMZ7U3Y9ahZsPwj8mrBltUMUZnDII8pBCQkeNG+X/
VGyaUtkTOb5XQf11e9GMjlT0beFoMEbg1WRZIkl0Wx4VfhtEitjzKZUJymlhifAW
ZXFhUOTGMXSUy+2cTgxbheUanvNg9boOL7GnEnf4Wh6fleabpQlcF6oaKJENMKyU
CEaHfq8MXyxTzr7BMdRNWRMjPa2188FK7eztuVVB8mJd2PO3n3fr5tHYw6Rft6Xc
5FWEbhA2JONRyAMfJs1Y1s97hEw1OJFIpgqKBGgbodUMzpO/mk8LULEbQZLXS3EM
8SqWwjlCV/zwPz8JwIgSq0qShFEUAlR/5mAUjrO1XHHwJa5yCPREy3Si7ZQ7pTZ7
biWBOwePFEPWSWAjjDcPp84cDdUkOXbSXAuB7QVV8awZH2UhvVwoKlJeXo0Oz/Fc
-----END RSA PRIVATE KEY-----
)";

const char M18PublicKey[] = R"(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmcqoYlvTSxjWWe7dOcvV
q+YNzThGeLmWXWJVpPz4YeO/1C8Fugg7JlccJYKSNHTcQT7x4F9hgdbn4rxBnssY
EUEaf74M1SCOmOm+Lnm8BxkE92WBLW7S2S2aATtr2etkbv0sRjDQta1VuE09nJkN
xgXByxs48LSjtofGmMAlAkxRjhjPfbSwNPi2GxF5mbqN27FX3qO0I21LR7OY0FWK
Y7UtgwArcxH16I3p9REf+T+uG/9JdRLCnUvZmuifXhLcwksQDMPAjERppsJnWYxD
fLAUVtRNIV0BnkCVsbs720dKF97dcuD5+VEB1MciWCxl5ACl/MK6ruC9I81a/TH+
3QIDAQAB
-----END PUBLIC KEY-----
)";

const char M30PrivateKey[] = R"(
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,8A0BF905B77DC148004E713C828DC660

iFD5lI2LhcgxPVAuBU5E/PMABnLNTzasvFfonExni1D2NdTxATjiA88Urk0+cSiw
Tb6Z9a8ODVw6jX2NiH5rm7TzSDUoaF9y/d+67EKMpyz/+vYgl9ZtHwesi5L5Hn+0
0ukeL1IgTlZX3SzbFAyRHDOmt/AJBc1lhrB4wSIJkMggZxF3s+EHLjf5I0Mo6rvQ
sFyYJ28gy5CFvwN+xIcy3DRASdKjl0PIRCUPaJYdRkF0TjiyVMvy17tiI/ZAuMdJ
5FwzPg7VksHFJ08Vvd96/1IW+Z5f3RIya00q+4+eH6G4ksmZiWvd0Gyy9U8yt/TW
yb7h7LxGvaeGhPeEIdjQp90dMBDo+JdsVXbDIhI83z6NR0W+QV3db1lIUXapV1a0
NH6KgFe40/Z/foSqX6G0stbnmVZHEEtKqDEilFNImORJQDJyeC/OvKqWx+yF9Xh4
ML/WHMBW1XJQBnJgng/Y690H2JUa6M/d6ovyxZV50ANMFlurGJMXCVV8Li2kC87C
C/2Kcajl2xEi4J0zRgqblZ6C5IRaSuaYPSdSjVXScz/qRG2CE5uAEXfhMy9cBU5E
xeCdBSHktTTB3FYvUGFEz3oKzakLwi1iUKMM7uQhgehP+DV/TD1bMm3WT25rNXi8
m+Vq9Ieu+ObqTqGX/FSa3QxQx8WbO0YGW0l/46JzbusiP+mGxZH94r+CtB+3TflS
9xrXx+uV6UKNHWFIaKAlVYTCou6SUYGENGSTOEN2v/oPUfN2gUuh31p9muJXpA6t
Wd8oEcOCMk9FSN12TQ/3HK2tXB/DoRQRwDu837Bk4Fh0lQQy9DjBo9kPC5ZTlXN4
6MB+E3P72MuSsLOCAkcD0kJ6Uug1bM8rNqkEevsi7UPyNtilharewhHImG1oou2q
OwdeweLZlDE/nXb+gmTkhzOa0zDtZck4TBotwxCmvBU+CEXvLpAeqyaHAP4NKYMc
QGDqYMAVyxH2hNtXXSkpDy6ojSTCAamZBtS/3tE1C7YkSWHedeoPmkUMxvgcAwH/
E4piO5KJ7PtYEkFbZ5Fo63cHvnVndW1F0/INn3GsmiNerSa75u2VUWOZ0m0fg2nR
L18hu9CsxcBB9wIPEEVVkGmvGIZgYZz9IuntLmO5Njr1k8PBoTyLmM55NRS3yXvA
/MleG6nkUdZ+pemhhUnoST5JIf8qEZuwpZ1bvx095ZJsDxIUbQqBBW+cKgIi2SCW
OP8qltuE0hfG/inOerWN9GDrXwb9C3/hTkyb+yecCAQGbu5fkHYGnniVUFgUu7dd
Kv/Aorn3I6HMFBk2+XoH5BMS+It17wORVMOfXHdmyem0w6SjLdciuoE869mvkk22
uNvC9GS+puyqxae1SMorH5DOBLCmxgYrfu/+WOfjktxLOYmvguQUzJ2MfuejHejd
XPDLYXZnqBxDq4jFkuz/lBy+niq/m2jqlVLhTxKU98CkeYhhdoDPRqolZu15lULQ
ghDShGIkpLoRJD42+6Ddhm0i7TmubNPtB/AwOie2tkyYNf+vkZZLL0UyHXhJJTeb
UA5Bcn8QXE1gzoqLedid5TKFUss3hUrqwmp7sbhycRUdOZaty9LwS71Ogh0YQ048
-----END RSA PRIVATE KEY-----
)";

const char M30PublicKey[] = R"(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvIj1OH7L1Wza1aa+ZJl1
Tb2+6jFxTC4fQhWF+tuHngbAD2YEJVVliQZ27biYR+AOOyKKrp3X6yEZQ28iwio2
qmvgCrs+UMftKZkozbD+A8JKmrEx2RRloIpFWHEQCgw1JWkWngC2vguoSbP8rtlB
Qeuevp+oa0fewZd4iPG37b8+dvRucaDyDJgrXXosCTKQVeuGdqF/l6jIDEzLX9c5
A2k2zBwhTzRUbwrhMF8FPhv8pxN3+YXx75vfYZnw3/dasu6RT2NyWVKlRt86HbfF
LvNSHDaUNDa5gjmZ4NTm0uR39X15fO+vAsqQBRnURN1uaJzJRQWazMlKtHR5WfHO
2QIDAQAB
-----END PUBLIC KEY-----
)";

const char M32PrivateKey[] = R"(
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,D7727E22F450CD0662339F7281626762

kJW0MGY6OnlxhnUPqwmWC2nTuYMrbKlSnQ8vHzL5XY7W6XoJQD9qZiP7YmoMB+Jd
lgoJ/GMnok+il2/0cTQEkLdOghsw3KfvVRBSgSh77imOSugpq6IaSZZsekwQFNYn
bsY+Yo2C6KF48a1oO9i4vPCmxqapNBINUtrjo2YHIkPo5SGdgfGg4E4vZyuvD5+q
AJ7X4qaz78WpezHKod7aaE7tAiX0+iP+H59rUnSpTh8f3/1jJLAxZEqBX8deDl/m
B51GeOIMArSzqUW4WHBPBXfiJTCL5ql63wgFfTE9gj3VATA3CoOQyXCDAR12Aihc
xCSFbATOOmzZxr0XYhP9QUmkVY6Pa14rg4HsxbwxzhBtM9SMgOI2ZNRuNO5nLab8
+Rro8NkDrbJw2uh6lHKmlfmW7nfrKnHdxqoI6eugRGPKG093+qZfCYJw5Gme9bmM
Cz7nFSwP8M9Zc2QFoo20x86NFxZOCkJwy0+9FsGPFYIxT/kZt+cS2votpp7kQizU
Ij8Zs6x8HCflG5EClpp5K2ZtZg/C8g34R5KBMae4B8n+l4YSeUfq/r7XKXoLFT/h
lvUlfC3pb0w1bpxSTtD0g5rJLdHPYQVNUAla6igqdIGN+nMpa+ug+vB7aA/DmFUz
ARDDr4n+GhScVmCjpK1/bO7sBp4XNU9u2ZJ6XmGPtQYGJX0uwQDK5F8+kV+bLdb7
3R7od2unRYONDhFIje6CQIZwzPdrZILs+z7kduP/ohyJJ0F3c4FF0R2FADQCfgu1
Zbk7egIMu8DD7m/ZK1R5PETa+IAwhclOngcELOb5TScNdBs1EQUtGhiRI3KxFX1H
PVjbONcHdxLmatVai0AR5OJHdQWBbS4Ely8PIl6IQbG0rPh5Sel7YpMLTIF/QEvK
NKseRQywV7n69j2QUjMqhDJYp66i53u/UbK2ceoeqf2LkRYWWwyUS7wRsColhwxv
LQjrmy1Ck5yXyd3hAXakOmBytGneuUbpUixmoyP05+vISo5cmTcxFhoAcm6nMFvT
0J6rIJrDJojTLm2WG3Fn3oAmDzhmAr8bQu1fu43jFqCMUjeirDmMzlzfiP6PeNE6
7mygxuqprynPz5lZBDuNOHZ/IyyNYIJkuFEzCYrsi6TlYRksmwlzgdm6xwb/3kgX
jgSU/BHFSbjQ6HkQ0Z6C6kt4R6Q1MCyMfqGzhmwK3XCIa8m9UfYc5m9jCtTECCX9
FDgOot7Z1cuPfI39k/qjedz0z8/3HWqmw5sgZJswaJS25N3oj7IV2sYqbqApJpaR
t0yfOjs3daJxiuMktcGzMIs+uIBGBPLvl3psZ2B8idcFJfxXjQ+JaVEWSAB8WGRr
QjIzqlaDdg6/+0iL+R5C6dpyKcpt7mAl1sRtW4KpYNLHnr3rc6PhS9ezLQ7IH7Cp
96pKlUZ70XGBOcDdH4uUTiheSbswUj3CIBGj2mvXcnMvGLTq6aoJT1rNr8Gc7Mrd
B16iFKjfVPvRtNLkjxOfGkt7YaMhT6olBCWOyVd276+m1fRF9c1KvtFJEYw/ebnD
FxqYe2clwJkpuUBJe/8dd6ZI+lJMAh4jH8KNHDomtsEuAjAO3Hi4KnA4oS3WEgRm
-----END RSA PRIVATE KEY-----
)";

const char M32PublicKey[] = R"(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2H2vHvLcNi7uImWDJm3A
eXMV+Nzma0sSHaNjH/fo0LrsDjJnRA23kkcaw1L1z3Ts5qD60Dd0yuHD9xrYgsLc
2IEEHd8oBv+JOJzsqIOdcPCK47sKFqqd0R7ugz5ZfxHVx4K9ZufMO1g9WRe9Us1+
ULSACIBTJW7Zv7XFkInMPzJCzbWa05NozyP4NyBsqt3zaysjfAP6G7kHf+J60tCU
maOH1T/XnqeogzaDZ5FrQHIKMPOXLXuuSumHzr33XNo2vfiUEXIcaH+01NNfBEAa
FYqnIeHEm/eCVdwbL5qr/b+A70Co05tKNlr1fTnUBslAJX+GZ8+oj6JP6dV8B8sE
JwIDAQAB
-----END PUBLIC KEY-----
)";

const M32FirmwareUtilDeviceInfoType M32FirmwareUtilDeviceInfos[] = 
{
  {
    "E30",
    "D-Link EAGLE PRO AI AX3000 Wi-Fi 6 Mesh Range Extender",
    "DLK6E6110002",
    "4d5ee2c8b5d0fdd9a9a2d351ba897752",
    E30PrivateKey,
    E30PublicKey,
    "wrpd"
  },
  {
    "M18",
    "D-Link EAGLE PRO AI AX1800 Mesh Router",
    "DLK6E8105001",
    "1ae6c79be7d069ca74df7670bdfc4952",
    M18PrivateKey,
    M18PublicKey,
    "wrpd"
  },
  {
    "M30",
    "D-Link AQUILA PRO AI AX3000 Smart Mesh Router",
    "DLK6E6110001",
    "b4517d9b98e04d9f075f5e78c743e097",
    M30PrivateKey,
    M30PublicKey,
    "wrpd"
  },
  {
    "M32",
    "D-Link EAGLE PRO AI AX3200 Mesh-System",
    "DLK6E6010001",
    "6b29f1d663a21b35fb45b69a42649f5e",
    M32PrivateKey,
    M32PublicKey,
    "wrpd"
  },
  {
    "R32",
    "D-Link EAGLE PRO AI AX3200 Smart Router",
    "DLK6E6015001",
    "6b29f1d663a21b35fb45b69a42649f5e",
    M32PrivateKey,
    M32PublicKey,
    "wrpd"
  }
};

const int M32FirmwareUtilDeviceInfosLength = 
  sizeof(M32FirmwareUtilDeviceInfos) / sizeof(M32FirmwareUtilDeviceInfoType);

/**
 * String which indicates the start of a header for SHA512 verification or AES 128 CBC encryption.
 * Note: The trailing \0 is not present in the firmware data.
*/
const char* M32FirmwareUtilHeaderStart = "MH01";

/***************************************************************************************************
 Variables
***************************************************************************************************/
static bool M32FirmwareUtilWriteDebugFiles = false;

static char* M32FirmwareUtilDebugTargetFolder = NULL;
/***************************************************************************************************
 Implementation
***************************************************************************************************/
int main(int argc, char *argv[]) 
{
  int status = 1;
  if ((argc != 5) && (argc != 7))
  {
    PrintUsage(argv[0]);
  }
  else
  {
    char* deviceArg = argv[1];
    char* operationArg = argv[2];
    char* inputFileArg = argv[3];
    char* outputFileArg = argv[4];

    const M32FirmwareUtilOperationsType* entry = NULL;
    for (int i = 0; i < M32FirmwareUtilOperationsLength; i++)
    {
      if ((strcmp(M32FirmwareUtilOperations[i].LongArgument, operationArg) == 0) ||
          (strcmp(M32FirmwareUtilOperations[i].ShortArgument, operationArg) == 0))
      {
        entry = &(M32FirmwareUtilOperations[i]);
      }
    }

    const M32FirmwareUtilDeviceInfoType* device = NULL;
    for (int i = 0; i < M32FirmwareUtilDeviceInfosLength; i++)
    {
      if (strcmp(M32FirmwareUtilDeviceInfos[i].Name, deviceArg) == 0)
      {
        device = &(M32FirmwareUtilDeviceInfos[i]);
      }
    }

    if ((argc > 6) && (strcmp("--debug", argv[5])== 0))
    {
      M32FirmwareUtilWriteDebugFiles = true;
      M32FirmwareUtilDebugTargetFolder = argv[6];
    }

    if ((entry == NULL) || (device == NULL))
    {
      PrintUsage(argv[0]);
    }
    else
    {
      FILE* file = NULL;
      
      int fileDescriptor;
      struct stat fileStatus;

      if ((file = fopen(inputFileArg, "rb+")) == NULL)
      {
        printf("Unable to open file %s\n", inputFileArg);
      }
      else if ((fileDescriptor = fileno(file)) == -1)
      {
        printf("Unable to get file descriptor for %s\n", inputFileArg);
      }
      else if ((fileDescriptor = fstat(fileDescriptor, &fileStatus)) == -1)
      {
        printf("Unable to get file status for %s\n", inputFileArg);
      }
      else if (fileStatus.st_size < entry->MinimumFileSize)
      {
        printf("File %s is smaller than %zu bytes\n", inputFileArg, entry->MinimumFileSize);
      }
      else
      {
        status = entry->Operation(file, &fileStatus, outputFileArg, device);
      }

      if (file != NULL)
      {
        fclose(file);
        file = NULL;
      }
    }
  }

  return status;
}


static void PrintUsage(char* programName)
{
  printf("Usage: %s <Device> <Operation> <InputFile> <OutputFile> [--debug] <Directory>\n", programName);
  
  printf("\n<Device> can be one of the following:\n");
  for (int i = 0; i < M32FirmwareUtilDeviceInfosLength; i++)
  {
    printf("%s: %s\n",M32FirmwareUtilDeviceInfos[i].Name, M32FirmwareUtilDeviceInfos[i].Description);
  }

  printf("\n<Operation> can be one of the following:\n");
  for (int i = 0; i < M32FirmwareUtilOperationsLength; i++)
  {
    printf("%s (%s): %s\n", M32FirmwareUtilOperations[i].LongArgument, M32FirmwareUtilOperations[i].ShortArgument, M32FirmwareUtilOperations[i].Description);
  }

  printf("\nThe argument \"--debug\" is optional.\n");
  printf("If present, debug files will be written to the directory specified by <Directory>\n");
}

/// @brief
///   Updates the block length and the checksum in a recovery image header.
/// @param file
///   The FILE handle of the input file.
/// @param fileStatus
///   The file status of the input file.
/// @param outputFile
///   The name of the output file.
/// @return
///   The function returns 0 if the update of the header was successful; otherwise 1.
static int UpdateHeaderInRecoveryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device)
{
  int status = 1;
  unsigned char* buffer = NULL;
  
  if ((buffer = malloc(fileStatus->st_size)) == NULL)
  {
    printf("Unable to allocate buffer to read input file\n");
  }
  else if (fread(buffer, 1, fileStatus->st_size, file) != fileStatus->st_size)
  {
    printf("Unable to read data from input file\n");
  }
  else
  {
    uint32_t partitionCount = 0;
    size_t headerAddresses[DLINK_AI_FIRMWARE_TOOL_MAX_PARTITIONS];

    /* Initialize array to default values, SIZE_MAX is used to mark invalid addresses */
    for (int i = 0; i < DLINK_AI_FIRMWARE_TOOL_MAX_PARTITIONS; i++)
    {
      headerAddresses[i] = SIZE_MAX;
    }

    /* Search for all partitions in the image */
    size_t headerStartLength = strlen(device->RecoveryHeaderStart);
    for (size_t bufferIndex = 0; bufferIndex < (fileStatus->st_size - DLINK_AI_FIRMWARE_TOOL_FW_HEADER_LENGTH); bufferIndex++)
    {
      if (memcmp(&(buffer[bufferIndex]), device->RecoveryHeaderStart, headerStartLength) == 0)
      {
        printf("Found partition header at address 0x%08lX\n", bufferIndex);
        headerAddresses[partitionCount] = bufferIndex;
        partitionCount++;

        if (partitionCount == DLINK_AI_FIRMWARE_TOOL_MAX_PARTITIONS)
        {
          printf("Reached maximum of %i partitions, stopping search", partitionCount);
          break;
        }
      }
    }

    for (int partition = 0; partition < partitionCount; partition++)
    {
      size_t partitionStart; 
      size_t partitionLength;
      uint8_t* partitionData;

      partitionStart = headerAddresses[partition];
      partitionData = &(buffer[partitionStart]);

      if (((partition + 1) < DLINK_AI_FIRMWARE_TOOL_MAX_PARTITIONS) &&
          (headerAddresses[partition + 1] != SIZE_MAX))
      {
        /* There is another valid partition afterwards, just calcualte the adress difference */
        partitionLength = headerAddresses[partition + 1] - headerAddresses[partition];
      }
      else
      {
        /* There are no further partitions, the current one must be the last one */
        partitionLength = fileStatus->st_size - headerAddresses[partition];
      }

      partitionLength -= DLINK_AI_FIRMWARE_TOOL_FW_HEADER_LENGTH;

      size_t partitionLengthOld = partitionData[DLINK_AI_FIRMWARE_TOOL_FW_DATA_LENGTH_OFFSET] | 
                                 (partitionData[DLINK_AI_FIRMWARE_TOOL_FW_DATA_LENGTH_OFFSET + 1] << 8) | 
                                 (partitionData[DLINK_AI_FIRMWARE_TOOL_FW_DATA_LENGTH_OFFSET + 2] << 16) | 
                                 (partitionData[DLINK_AI_FIRMWARE_TOOL_FW_DATA_LENGTH_OFFSET + 3] << 24);

      if (partitionLengthOld != partitionLength)
      {
        printf("Updating data length in partition %i from %li (0x%08lX) to %li (0x%08lX)\n", 
        partition, partitionLengthOld, partitionLengthOld, partitionLength, partitionLength);
        partitionData[DLINK_AI_FIRMWARE_TOOL_FW_DATA_LENGTH_OFFSET] = partitionLength & 0xFFu;
        partitionData[DLINK_AI_FIRMWARE_TOOL_FW_DATA_LENGTH_OFFSET + 1] = (partitionLength >> 8) & 0xFFu; 
        partitionData[DLINK_AI_FIRMWARE_TOOL_FW_DATA_LENGTH_OFFSET + 2] = (partitionLength >> 16) & 0xFFu;
        partitionData[DLINK_AI_FIRMWARE_TOOL_FW_DATA_LENGTH_OFFSET + 3] = (partitionLength >> 24) & 0xFFu;
      }

      Caclulate16BitSum(
        "data",
        partition,
        &(partitionData[DLINK_AI_FIRMWARE_TOOL_FW_HEADER_LENGTH]),
        partitionLength,
        &(partitionData[DLINK_AI_FIRMWARE_TOOL_DATA_CHECKSUM_OFFSET]),
        false);
      Caclulate16BitSum(
        "header",
        partition,
        partitionData,
        DLINK_AI_FIRMWARE_TOOL_HEADER_CHECKSUM_OFFSET,
        &(partitionData[DLINK_AI_FIRMWARE_TOOL_HEADER_CHECKSUM_OFFSET]), 
        true);
    }
    
    if (partitionCount == 0)
    {
      printf("No partitions found in input file");
    }
    else if (WriteBufferToFile(buffer, fileStatus->st_size, outputFile) != 0)
    {
      printf("Error during writing the updated recovery image to file %s\n", outputFile);
    }
    else
    {
      status = 0;
    }
  }

  if (buffer != NULL)
  {
    free(buffer);
    buffer = NULL;
  }

  return status;
}

static int CreateFactoryImageFromRecoveryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device)
{
  int status = 1;
  uint8_t* factoryImage = NULL;

  size_t factoryImageSize = 0;

  const size_t recoveryImageSize = fileStatus->st_size;
  factoryImageSize += recoveryImageSize;
  
  /* 3 Headers are added, two for SHA512 verification, one for AES encryption */
  factoryImageSize += 3 * DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH;

  /* 2 signature are added, one for the decrypted image, one for the factory image */
  factoryImageSize += 2 * DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SIGNATURE_LENGTH;

  /* Data for the decryption is added: IV and Salt */
  factoryImageSize += DLINK_AI_FIRMWARE_TOOL_FIRMWARE_DECRYPTION_INFO_LENGTH;

  /* Size of the encrypted image wihtout encryption header */
  const size_t encryptedImageWithoutHeaderSize = recoveryImageSize + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SIGNATURE_LENGTH;

  /* Size of the factory image wihtout SHA512 header and without signature */
  const size_t factoryImageWithoutHeaderSize = encryptedImageWithoutHeaderSize + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_DECRYPTION_INFO_LENGTH;

  uint8_t IV[16] = { 0x99, 0x38, 0x0c, 0x25, 0xae, 0xcc, 0x79, 0xd3, 0x9b, 0x14, 0x5a, 0xc0, 0x43, 0x53, 0xbb, 0xe9 };

  /* Add AES_BLOCK_SIZE because encrypted data can be larger with AES CBC padding */
  if ((factoryImage = malloc(factoryImageSize + AES_BLOCK_SIZE)) == NULL)
  {
    printf("Unable to allocate buffer to create the factory image\n");
  }
  else
  {
    int encryptedDataLength = 0;
    uint8_t* factoryImageHeader = factoryImage;
    uint8_t* encryptionHeader = &(factoryImageHeader[DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH]);
    uint8_t* ecnryptionInfo = &(encryptionHeader[DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH]);
    uint8_t* saltHeader = &(ecnryptionInfo[DLINK_AI_FIRMWARE_TOOL_FIRMWARE_INITIALIZATION_VECTOR_LENGTH]);
    uint8_t* recoveryImageWithHeader = &(ecnryptionInfo[DLINK_AI_FIRMWARE_TOOL_FIRMWARE_DECRYPTION_INFO_LENGTH]);
    uint8_t* recoveryImage = &(recoveryImageWithHeader[DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH]);
    uint8_t* recoveryImageSignature = &(recoveryImage[recoveryImageSize]);
  
    if (fread(recoveryImage, 1, fileStatus->st_size, file) != fileStatus->st_size)
    {
      printf("Unable to read recovery image from input file\n");
    }
    else if (CreateSha512VerificatioinHeader(recoveryImageWithHeader, recoveryImageSize) != 0)
    {
      printf("Unable to create SHA512 verification header for recovery image\n");
    }
    else if (CreateSha512VerificatioinSignature(recoveryImage, recoveryImageSize, device) != 0)
    {
      printf("Unable to create SHA512 verification signature for recovery image\n");
    }
    else if (WriteDebugBufferToFile(recoveryImageSignature, DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SIGNATURE_LENGTH, "Sig1.bin") != 0)
    {
      printf("Error during writing debug output file %s\n", "Sig1.bin");
    }
    else if (WriteDebugBufferToFile(recoveryImageWithHeader, recoveryImageSize + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SIGNATURE_LENGTH, "FW_and_Sig1.bin") != 0)
    {
      printf("Error during writing debug output file %s\n", "FW_and_Sig1.bin");
    }
    else if (EncryptAes128Cbc(recoveryImageWithHeader, 
                              encryptedImageWithoutHeaderSize, 
                              recoveryImageWithHeader,
                              saltHeader,
                              device->FirmwareKey, 
                              IV,
                              &encryptedDataLength) != 0)
    {
      printf("Unable to encrypt image\n");
    }
    else if (WriteDebugBufferToFile(saltHeader, encryptedDataLength + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SALT_INFO_LENGTH, "FWenc.bin") != 0)
    {
      printf("Error during writing debug output file %s\n", "FWenc.bin");
    }
    else if (CreateAes128CbcEncryptionHeader(encryptionHeader, encryptedDataLength + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SALT_INFO_LENGTH) != 0)
    {
      printf("Unable to create AES128 CBC header\n");
    }
    else if (WriteAes128CbcIvToBuffer(ecnryptionInfo, IV, sizeof(IV)) != 0)
    {
      printf("Unable to write AES128 CBD IV\n");
    }
    else if (WriteDebugBufferToFile(ecnryptionInfo, DLINK_AI_FIRMWARE_TOOL_FIRMWARE_INITIALIZATION_VECTOR_LENGTH, "IV.bin") != 0)
    {
      printf("Error during writing debug output file %s\n", "FWenc.bin");
    }
    else if (CreateSha512VerificatioinHeader(factoryImageHeader, encryptedDataLength + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_DECRYPTION_INFO_LENGTH + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH) != 0)
    {
      printf("Unable to create SHA512 verification header for recovery image\n");
    }
    else if (CreateSha512VerificatioinSignature(encryptionHeader, encryptedDataLength + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_DECRYPTION_INFO_LENGTH + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH, device) != 0)
    {
      printf("Unable to create SHA512 verification signature for recovery image\n");
    }
    else if (WriteBufferToFile(factoryImage, encryptedDataLength + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_DECRYPTION_INFO_LENGTH + 2* DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SIGNATURE_LENGTH, outputFile) != 0)
    {
      printf("Error during writing the factory image to file %s\n", outputFile);
    }
    else
    {
      status = 0;
    }
  }

  if (factoryImage != NULL)
  {
    free(factoryImage);
    factoryImage = NULL;
  }
  return status;
}

/// @brief
///   Creates a AES128 CBD encryption header for the specific image size.
/// @param buffer
///   The buffer to which the verification header is written to.
/// @param imageSize
///   The size of the image for which the header is created.
/// @return
///   The function returns 0 if the creation of the header was successful; otherwise 1.
static int CreateAes128CbcEncryptionHeader(uint8_t* buffer, size_t imageSize)
{
  memcpy(buffer, M32FirmwareUtilHeaderStart, strlen(M32FirmwareUtilHeaderStart));

  /* Constant 0x21 0x00 0x00 0x00 */
  buffer[4] = 0x21;
  buffer[5] = 0x00;
  buffer[6] = 0x00;
  buffer[7] = 0x00;

  /* Length of the data to verify (little endian format) */
  buffer[8] = imageSize & 0xFF;
  buffer[9] = (imageSize >> 8) & 0xFF;
  buffer[10] = (imageSize >> 16) & 0xFF;
  buffer[11] = (imageSize >> 24) & 0xFF;

  /* Constant 0x2B 0x1A */
  buffer[12] = 0x2B;
  buffer[13] = 0x1A;

  buffer[14] = 0;
  buffer[15] = 0;

  for (uint8_t position = 0; position < 14; position++)
  {
    buffer[14] += buffer[position]; /* Byte sum of byte 0-13 */
    buffer[15] ^= buffer[position]; /* XOR of byte 0-13 */
  }

  return 0;
}

/// @brief
///   Creates a SHA512 verification header for the specific image size.
/// @param buffer
///   The buffer to which the verification header is written to.
/// @param imageSize
///   The size of the image for which the header is created.
/// @return
///   The function returns 0 if the creation of the header was successful; otherwise 1.
static int CreateSha512VerificatioinHeader(uint8_t* buffer, size_t imageSize)
{
  memcpy(buffer, M32FirmwareUtilHeaderStart, strlen(M32FirmwareUtilHeaderStart));

  /* Length of the data to verify (little endian format) */
  buffer[4] = imageSize & 0xFF;
  buffer[5] = (imageSize >> 8) & 0xFF;
  buffer[6] = (imageSize >> 16) & 0xFF;
  buffer[7] = (imageSize >> 24) & 0xFF;

  /* Constant 0x00 0x01 0x00 0x00 */
  buffer[8] = 0x00;
  buffer[9] = 0x01;
  buffer[10] = 0x00;
  buffer[11] = 0x00;


  /* Constant 0x2B 0x1A */
  buffer[12] = 0x2B;
  buffer[13] = 0x1A;

  buffer[14] = 0;
  buffer[15] = 0;

  for (uint8_t position = 0; position < 14; position++)
  {
    buffer[14] += buffer[position]; /* Byte sum of byte 0-13 */
    buffer[15] ^= buffer[position]; /* XOR of byte 0-13 */
  }

  return 0;
}

/// @brief
///   Creates a SHA512 verification signature and stores it at the end of the buffer.
/// @param buffer
///   The buffer containing the data for which the signature is created.
///   There must be 256 additional bytes at the end of the buffer to store the signature.
/// @param imageSize
///   The size of the image without the signature.
/// @param device
///   Pointer to device specific information.
/// @return
///   The function returns 0 if the creation of the signature was successful; otherwise 1.
static int CreateSha512VerificatioinSignature(uint8_t* buffer, size_t imageSize, const M32FirmwareUtilDeviceInfoType* device)
{
  int status = 1;
  BIO* bio = NULL;
  uint8_t digest[SHA512_DIGEST_LENGTH];
  SHA512_CTX sha512Context;
  RSA* rsaPrivateKey = NULL;
  EVP_PKEY* pkey = NULL;
  EVP_MD_CTX* mdctx = NULL;
  unsigned int signatureLength;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  if (SHA512_Init(&sha512Context) != 1)
  {
    PrintOpenSSLError("SHA512_Init");
  }
  else if (SHA512_Update(&sha512Context, buffer, imageSize) != 1)
  {
    PrintOpenSSLError("SHA512_Update");
  }
  else if (SHA512_Final(digest, &sha512Context) != 1)
  {
    PrintOpenSSLError("SHA512_Final");
  }
  else if ((bio = BIO_new_mem_buf(device->PrivateKey, -1)) == NULL)
  {
    PrintOpenSSLError("BIO_new_mem_buf");
  }
  else if ((rsaPrivateKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, (void*)device->Passphrase)) == NULL)
  {
    PrintOpenSSLError("PEM_read_bio_RSAPrivateKey");
  }
  else if ((pkey = EVP_PKEY_new()) == NULL)
  {
    PrintOpenSSLError("EVP_PKEY_new");
  }
  else if ((EVP_PKEY_assign_RSA(pkey, rsaPrivateKey)) != 1)
  {
    PrintOpenSSLError("EVP_PKEY_assign_RSA");
  }
  else if ((mdctx = EVP_MD_CTX_new()) == NULL)
  {
    PrintOpenSSLError("EVP_MD_CTX_new");
  }
  else if ((EVP_SignInit(mdctx, EVP_sha512())) != 1)
  {
    PrintOpenSSLError("EVP_SignInit");
  }
  else if ((EVP_SignUpdate(mdctx, digest, sizeof(digest))) != 1)
  {
    PrintOpenSSLError("EVP_SignUpdate");
  }
  else if ((EVP_SignFinal(mdctx, &(buffer[imageSize]), &signatureLength, pkey)) != 1)
  {
    PrintOpenSSLError("EVP_SignFinal");
  }
  else if (signatureLength != DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SIGNATURE_LENGTH)
  {
    printf("Invalid signature length. Acutal: %u, expected: %u", signatureLength, DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SIGNATURE_LENGTH);
  }
  else
  {
    status = 0;
  }

  if (bio != NULL)
  {
    BIO_free(bio);
    bio = NULL;
  }

  if (mdctx != NULL)
  {
    EVP_MD_CTX_free(mdctx);
    mdctx = NULL;
  }

  if (pkey != NULL)
  {
    EVP_PKEY_free(pkey);
    pkey = NULL;
  }

  ERR_free_strings();
}

/// @brief
///   Decrypts and verifies a OEM firmware file to get the firmware image which can be used with TFTP.
/// @param file
///   The FILE handle of the input file.
/// @param fileStatus
///   The file status of the input file.
/// @param outputFile
///   The name of the output file.
/// @return
///   The function returns 0 if the decryption and verification was successful; otherwise 1.
static int DecryptFactoryImage(FILE* file, struct stat* fileStatus, const char* outputFile, const M32FirmwareUtilDeviceInfoType* device)
{
  int status = 1;
  uint8_t* fileBuffer = NULL;
  size_t currentBlockLength = 0;
  size_t currentBlockOffset = 0;

  uint8_t* decrpytedData = NULL;
  uint8_t ivHex[AES_BLOCK_SIZE];

  /* Offset 0x00: Header of OEM firmware */
  if ((fileBuffer = malloc(fileStatus->st_size)) == NULL)
  {
    printf("Unable to allocate buffer to read OEM firmware\n");
  }
  else if (fread(fileBuffer, 1, fileStatus->st_size, file) != fileStatus->st_size)
  {
    printf("Unable to read OEM firmware from input file\n");
  }
  else if (GetDataLengthFromVerificationHeader(&(fileBuffer[currentBlockOffset]), &currentBlockLength) != 0)
  {
    printf("Unable to get block length of OEM firmware\n");
  }
  /* Offset 0x10: Header for verification of IV and encrypted firmware */
  else if ((currentBlockOffset += DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH) > fileStatus->st_size)
  {
    printf("Block offset for OEM firmware out of range\n");
  }
  else if (VerifySha512Signture(&(fileBuffer[currentBlockOffset]), currentBlockLength, device) != 0)
  {
    printf("Verification of IVandFWenc failed\n");
  }
  else if (GetDataLengthFromEncryptionHeader(&(fileBuffer[currentBlockOffset]), &currentBlockLength) != 0)
  {
    printf("Unable to get block length of IV and ecnrypted firmware\n");
  }
  /* Offset 0x20: IV and encrypted firmware */
  else if ((currentBlockOffset += DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH) > fileStatus->st_size)
  {
    printf("Block offset for IV and encrypted firmware out of range\n");
  }
  else if (ConvertAsciiIvToHexArray(&(fileBuffer[currentBlockOffset]), ivHex) != 0)
  {
    printf("Unable to convert ASCII IV to hexadecimal values\n");
  }
  /* Offset 0x31: Encrypted data */
  else if ((currentBlockOffset += DLINK_AI_FIRMWARE_TOOL_FIRMWARE_INITIALIZATION_VECTOR_LENGTH) > fileStatus->st_size)
  {
    printf("Block offset for encrypted firmware out of range\n");
  }
  else if ((decrpytedData = malloc(currentBlockLength)) == NULL)
  {
    printf("Unable to allocate buffer for decryption\n");
  }
  else if (DecryptAes128Cbc(&(fileBuffer[currentBlockOffset]), currentBlockLength, decrpytedData, device->FirmwareKey, ivHex) != 0)
  {
    printf("Decryption of firmware failed\n");
  }
  /* Still offset 0x31: but decrypted data */
  else if (GetDataLengthFromVerificationHeader(decrpytedData, &currentBlockLength) != 0)
  {
    printf("Unable to get block length of decrypted firmware\n");
  }
  else if ((currentBlockOffset += DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH) > fileStatus->st_size)
  {
    printf("Block offset for decrypted firmware out of range\n");
  }
  else if (VerifySha512Signture(decrpytedData + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH, currentBlockLength, device) != 0)
  {
    printf("Verification of FWorig failed\n");
  }
  else if (WriteBufferToFile(decrpytedData + DLINK_AI_FIRMWARE_TOOL_FIRMWARE_HEADER_LENGTH, currentBlockLength, outputFile) != 0)
  {
    printf("Error during writing the recovery image to file %s\n", outputFile);
  }
  else
  {
    status = 0;
  }

  if (decrpytedData != NULL)
  {
    free(decrpytedData);
    decrpytedData = NULL;
  }

  if (fileBuffer != NULL)
  {
    free(fileBuffer);
    fileBuffer = NULL;
  }

  return status;
}


/// @brief
///   Performs SHA512 verification of a firmware image. The implementation represents the OpenSSL invocation
///   openssl dgst -sha512 -binary -out ${IV_AND_FIRMWARE_ENCRYPTED_DIGEST} ${IV_AND_FIRMWARE_ENCRYPTED}
///   openssl dgst -verify ${PUBLIC_KEY} -sha512 -binary -signature ${SIGNATURE_2} ${IV_AND_FIRMWARE_ENCRYPTED_DIGEST}
/// @param buffer
///   The buffer which contains the data to verify. The signature must be appended to the buffer.
/// @param bufferLength
///   The length of the buffer without signature.
/// @return
///   The function returns 0 if the verification was successful; otherwise 1.
static int VerifySha512Signture(const uint8_t* buffer, const size_t bufferLength, const M32FirmwareUtilDeviceInfoType* device)
{
  int status = 1;
  uint8_t digest[SHA512_DIGEST_LENGTH];
  SHA512_CTX sha512Context;
  BIO *bufio = NULL;
  EVP_PKEY* publicKey = NULL;

  EVP_MD_CTX* context;

  const uint8_t* signature = &(buffer[bufferLength]);
  
  if (SHA512_Init(&sha512Context) == 0)
  {
    PrintOpenSSLError("SHA512_Init");
  }
  else if (SHA512_Update(&sha512Context, buffer, bufferLength) == 0)
  {
    PrintOpenSSLError("SHA512_Update");
  }
  else if (SHA512_Final(digest, &sha512Context) == 0)
  {
    PrintOpenSSLError("SHA512_Final");
  }
  else if ((bufio = BIO_new_mem_buf(device->PublicKey, -1))  == 0)
  {
    PrintOpenSSLError("BIO_new_mem_buf");
  }
  else if ((publicKey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL)) == NULL)
  {
    PrintOpenSSLError("PEM_read_bio_RSA_PUBKEY");
  }
  else if ((context = EVP_MD_CTX_new()) == NULL)
  {
    PrintOpenSSLError("EVP_MD_CTX_new");
  }
  else if ((EVP_DigestVerifyInit(context, NULL, EVP_sha512(), NULL, publicKey)) == 0)
  {
    PrintOpenSSLError("EVP_DigestVerifyInit");
  }
  else if (EVP_DigestVerifyUpdate(context, digest, SHA512_DIGEST_LENGTH) == 0)
  {
    PrintOpenSSLError("EVP_DigestVerifyUpdate");
  }
  else if (EVP_DigestVerifyFinal(context, signature, DLINK_AI_FIRMWARE_TOOL_FIRMWARE_SIGNATURE_LENGTH) == 0)
  {
    PrintOpenSSLError("EVP_DigestVerifyFinal");
  }
  else 
  {
    status = 0;
  }

  if (publicKey != NULL)
  {
    EVP_PKEY_free(publicKey);
    publicKey = NULL;
  }

  if (bufio != NULL)
  {
    BIO_free(bufio);
    bufio = NULL;
  }

  return status;
}

/// @brief 
///   Performs AES decryption of a firmware image. The implementation represents the OpenSSL invocation
///   openssl aes-128-cbc -d -md sha256 -in ${encryptedData} -out ${outputBuffer} -kfile {keyString} -iv {ivHex}
/// @param encryptedData
///   Buffer containing the encrypted data
/// @param encryptedLength
///   Length of the buffer in bytes containing the encrypted data
/// @param outputBuffer
///   Buffer for storing the decrypted data
/// @param keyString
///   The firmware key as string for decrypting the data
/// @param ivHex
///   The initialization vector as array of hex values
/// @return
///   The function returns 0 if decryption was successful; otherwise 1.
static int DecryptAes128Cbc(const uint8_t* encryptedData, size_t encryptedLength, uint8_t* outputBuffer, const char* keyString, const uint8_t* ivHex)
{
  int status = 1;
  EVP_CIPHER_CTX* ctx = NULL;
  int decryptedLength = 0;

  uint8_t iv[EVP_MAX_IV_LENGTH], key[EVP_MAX_KEY_LENGTH];
  EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), &(encryptedData[8]), keyString, strlen(keyString), 1, key, iv);

  // The first 8 bytes contain the string "Salted__" and the salt, the are not used for decryption
  encryptedData += 16;
  encryptedLength -= 16;

  if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
  {
    PrintOpenSSLError("EVP_CIPHER_CTX_new");
  }
  else if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, ivHex) == 0)
  {
    PrintOpenSSLError("EVP_DecryptInit_ex");
  }
  else if (EVP_DecryptUpdate(ctx, outputBuffer, &decryptedLength, encryptedData, encryptedLength) != 1)
  {
    PrintOpenSSLError("EVP_DecryptUpdate");
  }
  else if (EVP_DecryptFinal_ex(ctx, outputBuffer + decryptedLength, &decryptedLength) != 1)
  {
    PrintOpenSSLError("EVP_DecryptFinal_ex");
  }
  else
  {
    status = 0;
  }

  if (ctx != NULL)
  {
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
  }

  return status;
}


/// @brief
///   Performs AES encryption of a firmware image. The implementation represents the OpenSSL invocation
///   openssl aes-128-cbc -e -md sha256 -in {plainData} -out {outputBuffer} -kfile {keyString} -iv {ivHex}
/// @param plainData
///   Buffer containing the plain data
/// @param plainDataLength
///   Length of the buffer in bytes containing the plain data
/// @param outputBuffer
///   Buffer for storing the encrypted data
/// @param saltBuffer
///   Buffer for storing the salt data
/// @param keyString
///   The firmware key as string for encrypting the data
/// @param ivHex
///   The initialization vector as array of hex values
/// @param encryptedDataLength
///   Pointer to store the length of the encryted data. Because of AES CBC padding, the encrypted data can be longer than the input data.
/// @return 
static int EncryptAes128Cbc(const uint8_t* plainData, const size_t plainDataLength, uint8_t* outputBuffer, uint8_t* saltBuffer, const char* keyString, const uint8_t* ivHex, int* encryptedDataLength)
{
  int status = 1;
  EVP_CIPHER_CTX *ctx = NULL;
  int templength = 0;
  const uint8_t salt[8] = {0x65, 0xFC, 0x43, 0xBC, 0x67, 0xA3, 0x23, 0x35};

  /* Write "Salted__" and salt */
  memcpy(saltBuffer, "Salted__", 8);
  memcpy(saltBuffer + 8, salt, 8);
  
  *encryptedDataLength = 0;

  uint8_t iv[EVP_MAX_IV_LENGTH] = {0}, key[EVP_MAX_KEY_LENGTH] = {0};
  EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), salt, keyString, strlen(keyString), 1, key, iv);

  if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
  {
    PrintOpenSSLError("EVP_CIPHER_CTX_new");
  }
  else if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, ivHex) == 0)
  {
    PrintOpenSSLError("EVP_EncryptInit_ex");
  }
  else if (EVP_EncryptUpdate(ctx, outputBuffer, &templength, plainData, plainDataLength) != 1)
  {
    PrintOpenSSLError("EVP_EncryptUpdate");
  }
  else
  {
    *encryptedDataLength += templength;
    if (EVP_EncryptFinal_ex(ctx, outputBuffer + (*encryptedDataLength), &templength) != 1) 
    {
      PrintOpenSSLError("EVP_EncryptFinal_ex");
    }
    else
    {
      *encryptedDataLength += templength;
      status = 0;
    }
  }

  if (ctx != NULL)
  {
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
  }

  return status;
}

/// @brief
///   Reads the length of the data block (payload) from an header which is used for SHA512 verification.
///   The length of the block is stored in byte 4-7 in this case.
/// @param header
///   Pointer to the header data.
/// @param dataLength
///   Pointer to store the header length.
/// @return
///   The function returns 0 if reading of the header was successful; otherwise 1.
static int GetDataLengthFromVerificationHeader(uint8_t* header, size_t* dataLength)
{
  int status = 1;
  /* Header must begin with ASCII MH01 */
  if ((header[0] == 'M') && (header[1] == 'H') && (header[2] == '0') && (header[3] == '1'))
  {
    *dataLength = header[4] | (header[5] << 8) | (header[6] << 16) | (header[7] << 24);
    status = 0;
  }
  
  return status;
}

/// @brief
///   Reads the length of the data block (payload) from an header which is used for AES encryption.
///   The length of the block is stored in byte 8-11 in this case.
/// @param header
///   Pointer to the header data.
/// @param dataLength
///   Pointer to store the header length.
/// @return
///   The function returns 0 if reading of the header was successful; otherwise 1.
static int GetDataLengthFromEncryptionHeader(uint8_t* header, size_t* dataLength)
{
  int status = 1;
  /* Header must begin with ASCII MH01 */
  if ((header[0] == 'M') && (header[1] == 'H') && (header[2] == '0') && (header[3] == '1'))
  {
    *dataLength = header[8] | (header[9] << 8) | (header[10] << 16) | (header[11] << 24);
    status = 0;
  }
  
  return status;
}


/// @brief
///   Converts the ASCII IV for AES decryption which is stored in the firmware to hexadecimal values.
/// @param ivAscii
///   The ASCII IV string.
/// @param ivHex
///   The array in which the hex values are stored.
/// @return
///   The function returns 0 if converting of the IV was successful; otherwise 1.
static int ConvertAsciiIvToHexArray(const uint8_t ivAscii[AES_BLOCK_SIZE * 2], uint8_t ivHex[AES_BLOCK_SIZE])
{
  /* Convert ASCII IV to hex values */
  for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
  {
    sscanf(&(ivAscii[i * 2]), "%2hhx", &(ivHex[i]));
  }

  return 0;
}

/// @brief
///   Writes data from a buffer to a file.
/// @param buffer
///   The buffer containing the data.
/// @param bufferSize
///   The lengths of the buffer.
/// @param outputFile
///   The path to the file to which the data will be written.
/// @return
///   The function returns 0 if writing was successful; otherwise 1.
static int WriteBufferToFile(const uint8_t* buffer, const size_t bufferSize, const char* outputFile)
{
  int status = 1;
  FILE* file = NULL;
  if ((file = fopen(outputFile, "wb")) == NULL)
  {
    printf("Unable to open file %s for writing\n", outputFile);
  }
  else if (fwrite(buffer, 1, bufferSize, file) != bufferSize)
  {
    printf("Error during writing to file %s\n", outputFile);
  }
  else
  {
    status = 0;
  }

  if (file != NULL)
  {
    fclose(file);
    file = NULL;
  }

  return status;
}

/// @brief
///   Writes data from a buffer to a file if debug output is enabled.
/// @param buffer
///   The buffer containing the data.
/// @param bufferSize
///   The lengths of the buffer.
/// @param outputFile
///   The path to the file to which the data will be written.
/// @return
///   The function returns 0 if writing was successful; otherwise 1.
static int WriteDebugBufferToFile(const uint8_t* buffer, const size_t bufferSize, const char* outputFile)
{
  int status = 1;
  if (M32FirmwareUtilWriteDebugFiles == true)
  {
    const char* pathSeparator = "/";
    const size_t outputFilePathLength = strlen(M32FirmwareUtilDebugTargetFolder) + strlen(pathSeparator) + strlen(outputFile) + 1;
    char* outputFilePath = malloc(outputFilePathLength);
    snprintf(outputFilePath, outputFilePathLength, "%s%s%s", M32FirmwareUtilDebugTargetFolder, pathSeparator, outputFile);
    
    status = WriteBufferToFile(buffer, bufferSize, outputFilePath);

    if (outputFilePath != NULL)
    {
      free(outputFilePath);
      outputFilePath = NULL;
    }
  }
  else
  {
    status = 0;
  }

  return status;
}

static int WriteAes128CbcIvToBuffer(uint8_t* buffer, const uint8_t* iv, const size_t ivLength)
{
  size_t i;
  for (i = 0; i < ivLength; i++)
  {
    sprintf(&(buffer[2 * i]), "%02x", iv[i]);
  }

  buffer[(2 * i)] = 0x0A;

  return 0;
}

/// @brief Prints errors messages of a failed OpenSSL API call.
/// @param api
///   The API which was called.
static void PrintOpenSSLError(const char* api)
{
  printf("%s failed\n", api);
  ERR_print_errors_fp(stdout);
}

static void Caclulate16BitSum(const char* name, uint32_t partitionIndex, uint8_t* buffer, size_t bufferLength, uint8_t* checksumBuffer, bool inverted)
{
  uint16_t checksumOld;
  uint16_t checksumNew;

  checksumOld = checksumBuffer[0] | (checksumBuffer[1] << 8);
  checksumNew = 0;
                              
  for (int i = 0; i < bufferLength; i+= 2)
  {
    unsigned short currentValue = buffer[i] | (buffer[i + 1] << 8);
    checksumNew += currentValue;
    
    /* Detect overflow */
    if (checksumNew < currentValue)
    {
      checksumNew++;
    }
  }

  if (inverted == true)
  {
    checksumNew = 0xFFFFu - checksumNew;
  }

  if (checksumNew != checksumOld)
  {
    printf("Updating %s checksum in partition %i from 0x%04X to 0x%04X\n", name, partitionIndex, checksumOld, checksumNew);
    checksumBuffer[0] = checksumNew & 0xFFu;
    checksumBuffer[1] = (checksumNew >> 8) & 0xFFu; 
  }
  else
  {
    printf("Keeping %s checksum in partition %i: 0x%04X\n", name, partitionIndex, checksumOld);
  }
}
