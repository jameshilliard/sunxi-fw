// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2018, Andre Przywara
 * (C) Copyright 2025, James Hilliard
 *
 * sunxi-toc0: dump very basic information about an Allwinner TOC0 image
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifdef WITH_OPENSSL
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#endif

#include "sunxi-fw.h"

#define TOC0_MAIN_INFO_NAME "TOC0.GLH"
#define BROM_STAMP_VALUE 0x5f0a6c39
#define TOC0_MAIN_MAGIC 0x89119800
#define TOC0_MAIN_END 0x3b45494d
#define TOC0_ITEM_END 0x3b454949

#define TOC0_ITEM_NAME_CERT 0x010101
#define TOC0_ITEM_NAME_FW 0x010202
#define TOC0_ITEM_NAME_KEY 0x010303

#define RSA_MOD_LEN 256
#define RSA_EXP_LEN 3

typedef struct {
	uint8_t name[8];
	uint32_t magic;
	uint32_t checksum;
	uint32_t serial;
	uint32_t status;
	uint32_t num_items;
	uint32_t length;
	uint8_t platform[4];
	uint8_t reserved[8];
	uint32_t end_marker;
} toc0_main_info;

typedef struct {
	uint32_t name;
	uint32_t offset;
	uint32_t length;
	uint32_t status;
	uint32_t type;
	uint32_t load_addr;
	uint8_t reserved[4];
	uint8_t end_marker[4];
} toc0_item_info;

typedef struct {
	unsigned int ChannelCnt;
	/*count of total nand chips are currently connecting on the CE pin*/
	unsigned int ChipCnt;
	/*chip connect info, bit=1 means one chip connecting on the CE pin*/
	unsigned int ChipConnectInfo;
	unsigned int RbCnt;
	/*connect info of all rb  chips are connected*/
	unsigned int RbConnectInfo;
	unsigned int RbConnectMode;	/*rb connect mode*/
	/*count of banks in one nand chip, multi banks can support Inter-Leave*/
	unsigned int BankCntPerChip;
	/*count of dies in one nand chip, block management is based on Die*/
	unsigned int DieCntPerChip;
	/*count of planes in one die, >1 can support multi-plane operation*/
	unsigned int PlaneCntPerDie;
	/*count of sectors in one single physic page, one sector is 0.5k*/
	unsigned int SectorCntPerPage;
	/*count of physic pages in one physic block*/
	unsigned int PageCntPerPhyBlk;
	/*count of physic blocks in one die, include valid and invalid blocks*/
	unsigned int BlkCntPerDie;
	/*mask of operation types which current nand flash can support support*/
	unsigned int OperationOpt;
	/*parameter of hardware access clock, based on 'MHz'*/
	unsigned int FrequencePar;
	/*Ecc Mode for nand chip, 0: bch-16, 1:bch-28, 2:bch_32*/
	unsigned int EccMode;
	/*nand chip id of current connecting nand chip*/
	unsigned char NandChipId[8];
	/*ratio of valid physical blocks, based on 1024*/
	unsigned int ValidBlkRatio;
	unsigned int good_block_ratio; /*good block ratio get from hwscan*/
	unsigned int ReadRetryType; /*read retry type*/
	unsigned int DDRType;
	unsigned int Reserved[32];
} boot_nand_para_t; // nand_type_rawnand.h redefine

struct toc0_key_item {
	uint32_t vendor_id;
	uint32_t key0_n_len;
	uint32_t key0_e_len;
	uint32_t key1_n_len;
	uint32_t key1_e_len;
	uint32_t sig_len;
	uint8_t key0[512];
	uint8_t key1[512];
	uint8_t reserved[32];
	uint8_t sig[256];
};

#define __packed __attribute__((__packed__))

struct __packed toc0_small_tag {
	uint8_t tag;
	uint8_t length;
};

typedef struct toc0_small_tag toc0_small_int;
typedef struct toc0_small_tag toc0_small_oct;
typedef struct toc0_small_tag toc0_small_seq;
typedef struct toc0_small_tag toc0_small_exp;

#define TOC0_LARGE_INT(len)                        \
	{                                          \
		0x02, 0x82, (len) >> 8, (len)&0xff \
	}
#define TOC0_LARGE_BIT(len)                        \
	{                                          \
		0x03, 0x82, (len) >> 8, (len)&0xff \
	}
#define TOC0_LARGE_SEQ(len)                        \
	{                                          \
		0x30, 0x82, (len) >> 8, (len)&0xff \
	}

struct __packed toc0_large_tag {
	uint8_t tag;
	uint8_t prefix;
	uint8_t length_hi;
	uint8_t length_lo;
};

typedef struct toc0_large_tag toc0_large_int;
typedef struct toc0_large_tag toc0_large_bit;
typedef struct toc0_large_tag toc0_large_seq;

struct __packed toc0_cert_item {
	toc0_large_seq tag_totalSequence;
	struct __packed toc0_totalSequence {
		toc0_large_seq tag_mainSequence;
		struct __packed toc0_mainSequence {
			toc0_small_exp tag_explicit0;
			struct __packed toc0_explicit0 {
				toc0_small_int tag_version;
				uint8_t version;
			} explicit0;
			toc0_small_int tag_serialNumber;
			uint8_t serialNumber;
			toc0_small_seq tag_signature;
			toc0_small_seq tag_issuer;
			toc0_small_seq tag_validity;
			toc0_small_seq tag_subject;
			toc0_large_seq tag_subjectPublicKeyInfo;
			struct __packed toc0_subjectPublicKeyInfo {
				toc0_small_seq tag_algorithm;
				toc0_large_seq tag_publicKey;
				struct __packed toc0_publicKey {
					toc0_large_int tag_n;
					uint8_t n[256];
					toc0_small_int tag_e;
					uint8_t e[3];
				} publicKey;
			} subjectPublicKeyInfo;
			toc0_small_exp tag_explicit3;
			struct __packed toc0_explicit3 {
				toc0_small_seq tag_extension;
				struct __packed toc0_extension {
					toc0_small_int tag_digest;
					uint8_t digest[32];
				} extension;
			} explicit3;
		} mainSequence;
		toc0_large_bit tag_sigSequence;
		struct __packed toc0_sigSequence {
			toc0_small_seq tag_algorithm;
			toc0_large_bit tag_signature;
			uint8_t signature[256];
		} sigSequence;
	} totalSequence;
};

static inline bool is_rsa_pubkey_tag(const uint8_t *buf)
{
	return (buf[0] == 0x02 && buf[1] == 0x82 && buf[2] == 0x01 &&
		buf[3] == 0x00 && buf[4 + RSA_MOD_LEN] == 0x02 &&
		buf[4 + RSA_MOD_LEN + 1] == 0x03 &&
		buf[4 + RSA_MOD_LEN + 2 + RSA_EXP_LEN] == 0xa3);
}

static const char *item_name(uint32_t id)
{
	switch (id) {
	case TOC0_ITEM_NAME_CERT:
		return "SBROMSW_CERTIF";
	case TOC0_ITEM_NAME_FW:
		return "SBROMSW_FW";
	case TOC0_ITEM_NAME_KEY:
		return "SBROMSW_KEY";
	default:
		return "UNKNOWN";
	}
}

static uint32_t calc_checksum(void *buff, uint32_t length)
{
	uint32_t *buf = buff;
	uint32_t sum = BROM_STAMP_VALUE;
	uint32_t i;

	for (i = 0; i < length / 4; i++)
		sum += buf[i];

	return sum;
}

#ifdef WITH_OPENSSL
static void dump_hex(const char *label, const uint8_t *data, size_t len,
		     FILE *stream)
{
	size_t i;

	fprintf(stream, "%s:", label);

	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			fprintf(stream, "\n  ");
		fprintf(stream, "%02x ", data[i]);
	}

	fprintf(stream, "\n");
}

static bool parse_cert_for_rotpk(const uint8_t *cert_buf, size_t cert_len,
				 FILE *stream)
{
	size_t i;
	uint8_t rotpk[512];
	uint8_t rotpk_hash[SHA256_DIGEST_LENGTH];
	const uint8_t *mod;
	const uint8_t *exp;

	for (i = 0; i + 4 + RSA_MOD_LEN + 2 + RSA_EXP_LEN <= (ssize_t)cert_len;
	     i++) {
		if (is_rsa_pubkey_tag(&cert_buf[i])) {
			mod = &cert_buf[i + 4];
			exp = &cert_buf[i + 4 + RSA_MOD_LEN + 2];

			memset(rotpk, 0x91, sizeof(rotpk));
			memcpy(rotpk, mod, RSA_MOD_LEN);
			memcpy(rotpk + RSA_MOD_LEN, exp, RSA_EXP_LEN);

			dump_hex("  ROTPK (modulus + exponent)", rotpk,
				 RSA_MOD_LEN + RSA_EXP_LEN, stream);
			SHA256(rotpk, sizeof(rotpk), rotpk_hash);
			dump_hex("  ROTPK SHA256 (from CERTIF)", rotpk_hash,
				 sizeof(rotpk_hash), stream);
			return true;
		}
	}

	fprintf(stderr,
		"ROTPK extraction failed: RSA key structure not found in certificate\n");
	return false;
}

static int verify_signature(const uint8_t *sig, size_t sig_len,
			    const uint8_t *tbs, size_t tbs_len,
			    const uint8_t *mod, size_t mod_len,
			    const uint8_t *exp, size_t exp_len, FILE *stream)
{
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *ctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
	int ret = -1;

	bld = OSSL_PARAM_BLD_new();
	if (!bld ||
	    !OSSL_PARAM_BLD_push_BN(bld, "n", BN_bin2bn(mod, mod_len, NULL)) ||
	    !OSSL_PARAM_BLD_push_BN(bld, "e", BN_bin2bn(exp, exp_len, NULL))) {
		fprintf(stderr, "Failed to build RSA parameters\n");
		goto cleanup;
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) {
		fprintf(stderr, "OSSL_PARAM_BLD_to_param failed\n");
		goto cleanup;
	}

	pkctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!pkctx || EVP_PKEY_fromdata_init(pkctx) <= 0 ||
	    EVP_PKEY_fromdata(pkctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
		fprintf(stderr, "EVP_PKEY_fromdata failed\n");
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "EVP_MD_CTX_new failed\n");
		goto cleanup;
	}

	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
		fprintf(stderr, "EVP_DigestVerifyInit failed\n");
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if (EVP_DigestVerifyUpdate(ctx, tbs, tbs_len) <= 0) {
		fprintf(stderr, "EVP_DigestVerifyUpdate failed\n");
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if (EVP_DigestVerifyFinal(ctx, sig, sig_len) != 1) {
		fprintf(stderr, "EVP_DigestVerifyFinal failed\n");
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	fprintf(stream, "  Signature verification: SUCCESS\n");
	ret = 0;

cleanup:
	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (pkctx)
		EVP_PKEY_CTX_free(pkctx);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (bld)
		OSSL_PARAM_BLD_free(bld);
	if (params)
		OSSL_PARAM_free(params);

	return ret;
}

int parse_cert_item(const uint8_t *buf, size_t len,
		    const uint8_t *expected_digest)
{
	const struct toc0_cert_item *cert_item = (const void *)buf;
	uint8_t cert_digest[SHA256_DIGEST_LENGTH];

	const struct toc0_totalSequence *totalSequence =
		&cert_item->totalSequence;
	const struct toc0_sigSequence *sigSequence =
		&totalSequence->sigSequence;
	const struct toc0_publicKey *publicKey =
		&totalSequence->mainSequence.subjectPublicKeyInfo.publicKey;

	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *pub_params = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int ret = -1;

	SHA256((uint8_t *)totalSequence, sizeof(struct toc0_mainSequence),
	       cert_digest);

	bld = OSSL_PARAM_BLD_new();
	n = BN_bin2bn(publicKey->n, sizeof(publicKey->n), NULL);
	e = BN_bin2bn(publicKey->e, sizeof(publicKey->e), NULL);

	if (!n || !e) {
		fprintf(stderr, "Failed to create BIGNUMs for RSA key\n");
		goto cleanup;
	}

	if (!bld || !OSSL_PARAM_BLD_push_BN(bld, "n", n) ||
	    !OSSL_PARAM_BLD_push_BN(bld, "e", e)) {
		fprintf(stderr, "Failed to build RSA params\n");
		goto cleanup;
	}

	pub_params = OSSL_PARAM_BLD_to_param(bld);
	if (!pub_params) {
		fprintf(stderr, "OSSL_PARAM_BLD_to_param failed\n");
		goto cleanup;
	}

	pkctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!pkctx || EVP_PKEY_fromdata_init(pkctx) <= 0 ||
	    EVP_PKEY_fromdata(pkctx, &pkey, EVP_PKEY_PUBLIC_KEY, pub_params) <=
		    0) {
		fprintf(stderr, "EVP_PKEY_fromdata failed\n");
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx) {
		fprintf(stderr, "Failed to create EVP_PKEY_CTX\n");
		goto cleanup;
	}

	if (EVP_PKEY_verify_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
	    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
		fprintf(stderr, "Failed to set up verification context\n");
		goto cleanup;
	}

	if (EVP_PKEY_verify(ctx, sigSequence->signature,
			    sizeof(sigSequence->signature), cert_digest,
			    SHA256_DIGEST_LENGTH) <= 0) {
		fprintf(stderr, "Bad certificate signature\n");
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (pkctx)
		EVP_PKEY_CTX_free(pkctx);
	if (bld)
		OSSL_PARAM_BLD_free(bld);
	if (pub_params)
		OSSL_PARAM_free(pub_params);
	if (n)
		BN_free(n);
	if (e)
		BN_free(e);

	return ret;
}

static void parse_key_item(const uint8_t *buf, size_t len, FILE *stream)
{
	const struct toc0_key_item *item;
	size_t signed_len;

	if (len < sizeof(struct toc0_key_item)) {
		fprintf(stderr, "Error: Buffer too small (len=%zu)\n", len);
		return;
	}

	item = (const struct toc0_key_item *)buf;
	signed_len = (size_t)(item->sig - buf);

	verify_signature(item->sig, item->sig_len, buf, signed_len, item->key0,
			 item->key0_n_len, item->key0 + item->key0_n_len,
			 item->key0_e_len, stream);
}

#endif


/* Storage data validation flags */
#define STORAGE_VALID_RAW      0x0001  /* Valid raw NAND parameters */
#define STORAGE_VALID_TLV      0x0002  /* Valid TLV format */
#define STORAGE_RSA_OVERWRITE  0x0004  /* RSA key overwrote storage */
#define STORAGE_EMPTY          0x0008  /* Storage data is all zeros */
#define STORAGE_INVALID_FORMAT 0x0010  /* Invalid/unknown format */
#define STORAGE_TLV_NO_SEQ     0x0020  /* TLV missing SEQUENCE marker */
#define STORAGE_TLV_NO_INT     0x0040  /* TLV missing INTEGER marker */
#define STORAGE_HAS_CODE_DATA  0x0080  /* Contains non-storage data (code/keys) */

/* Helper macros for checking storage validity */
#define STORAGE_SBROM_OK(flags) ((flags) & (STORAGE_VALID_RAW | STORAGE_VALID_TLV))
#define STORAGE_KERNEL_OK(flags) 1  /* Kernel always accepts (will overwrite) */
#define STORAGE_KERNEL_CORRUPT(flags) ((flags) & (STORAGE_RSA_OVERWRITE | STORAGE_HAS_CODE_DATA))

/* Convert ECC mode to string - based on kernel ecc_mode_to_string() */
static const char *ecc_mode_to_string(unsigned int ecc_mode)
{
	switch (ecc_mode) {
	case 0x00: return "BCH-16";
	case 0x01: return "BCH-24";
	case 0x02: return "BCH-28";
	case 0x03: return "BCH-32";
	case 0x04: return "BCH-40";
	case 0x05: return "BCH-44";
	case 0x06: return "BCH-48";
	case 0x07: return "BCH-52";
	case 0x08: return "BCH-56";
	case 0x09: return "BCH-60";
	case 0x0A: return "BCH-64";
	case 0x0B: return "BCH-68";
	case 0x0C: return "BCH-72";
	case 0x0D: return "BCH-76";
	case 0x0E: return "BCH-80";
	default:   return "Unknown";
	}
}

/* Print boot compatibility status based on validation flags */
static void print_boot_compatibility(int validation_flags, FILE *stream)
{
	/* Print detected issues first if any */
	if (validation_flags & ~(STORAGE_VALID_RAW | STORAGE_VALID_TLV)) {
		fprintf(stream, "\n  Detected Issues:\n");
		if (validation_flags & STORAGE_RSA_OVERWRITE)
			fprintf(stream, "    • RSA key overwrote storage_data (TOC0 generation bug)\n");
		if (validation_flags & STORAGE_EMPTY)
			fprintf(stream, "    • Empty storage_data (all zeros)\n");
		if (validation_flags & STORAGE_INVALID_FORMAT)
			fprintf(stream, "    • Invalid/unknown format\n");
		if (validation_flags & STORAGE_TLV_NO_SEQ)
			fprintf(stream, "    • TLV format missing SEQUENCE marker\n");
		if (validation_flags & STORAGE_TLV_NO_INT)
			fprintf(stream, "    • TLV format missing INTEGER marker\n");
	}

	fprintf(stream, "\n  Boot Compatibility:\n");

	/* Check SBROM compatibility */
	if (STORAGE_SBROM_OK(validation_flags)) {
		fprintf(stream, "    ✓ SBROM acceptable (direct NAND boot works)\n");
	} else {
		fprintf(stream, "    ✗ SBROM acceptable");
		if (validation_flags & STORAGE_RSA_OVERWRITE) {
			fprintf(stream, " - Will fail and enter FEL mode\n");
		} else if (validation_flags & STORAGE_EMPTY) {
			fprintf(stream, " - No valid NAND parameters\n");
		} else {
			fprintf(stream, " - Invalid format\n");
		}
	}

	/* Kernel always accepts but may corrupt */
	fprintf(stream, "    ⚠ Kernel acceptable");
	if (STORAGE_KERNEL_CORRUPT(validation_flags)) {
		fprintf(stream, " - WARNING: Driver will CORRUPT image!\n");
		fprintf(stream, "      Kernel expects storage_data at fixed offset 0x2D4\n");
		if (validation_flags & STORAGE_RSA_OVERWRITE) {
			fprintf(stream, "      RSA key data currently occupies 0x2D4-0x453\n");
			fprintf(stream, "      This critical data will be DESTROYED when flashing!\n");
		} else if (validation_flags & STORAGE_HAS_CODE_DATA) {
			fprintf(stream, "      Code/data currently occupies 0x2D4-0x453\n");
			fprintf(stream, "      This will be OVERWRITTEN with NAND parameters!\n");
		}
		fprintf(stream, "      Solution: Pre-populate storage_data or use direct NAND write\n");
	} else if (validation_flags & STORAGE_EMPTY) {
		fprintf(stream, " - Driver will populate with detected params\n");
	} else if (!STORAGE_SBROM_OK(validation_flags)) {
		fprintf(stream, " - WARNING: Driver may corrupt image!\n");
		fprintf(stream, "      Invalid format at 0x2D4 will be overwritten\n");
	} else {
		fprintf(stream, " - Safe to flash via Linux driver\n");
	}

	/* Overall compatibility */
	if (STORAGE_SBROM_OK(validation_flags)) {
		fprintf(stream, "    ✓ FULLY COMPATIBLE - Works for both methods\n");
	} else if (validation_flags & STORAGE_RSA_OVERWRITE) {
		fprintf(stream, "    ✗ IMAGE WILL BE CORRUPTED - Do not flash via kernel!\n");
		fprintf(stream, "      Pre-populate storage_data first or use direct NAND write\n");
	} else if (validation_flags & STORAGE_EMPTY) {
		fprintf(stream, "    ⚠ KERNEL ONLY - Must flash via Linux, not direct NAND write\n");
	} else {
		fprintf(stream, "    ✗ INCOMPATIBLE - Invalid storage_data format\n");
		fprintf(stream, "      Kernel will corrupt, SBROM will reject\n");
	}
}

/* Detect what type of data is at a given offset (for kernel corruption detection)
 * Returns flags indicating the type of data found
 */
static int detect_data_type_at_offset(const uint8_t *data, size_t len)
{
	if (len < 4) {
		return STORAGE_INVALID_FORMAT;
	}

	/* Check for ARM instruction patterns (common in code sections) */
	/* ARM instructions often have patterns like:
	 * - Branch instructions: 0xEAxxxxxx or 0xEBxxxxxx
	 * - Push/Pop: 0xE92xxxxx, 0xE8Bxxxxx
	 * - MOV/ADD/SUB: 0xE3xxxxxx, 0xE2xxxxxx
	 * - LDR/STR: 0xE5xxxxxx
	 */
	uint32_t first_word = *(uint32_t *)data;
	uint32_t arm_mask = first_word & 0xF0000000;
	if (arm_mask == 0xE0000000 || arm_mask == 0xF0000000) {
		/* Check multiple words for consistency */
		int arm_instructions = 0;
		for (int i = 0; i < 16 && i < len/4; i++) {
			uint32_t word = ((uint32_t *)data)[i];
			if ((word & 0xF0000000) == 0xE0000000 ||
			    (word & 0xF0000000) == 0xF0000000) {
				arm_instructions++;
			}
		}
		/* If most words look like ARM instructions */
		if (arm_instructions > 10) {
			return STORAGE_HAS_CODE_DATA;
		}
	}

	/* Check for Thumb2 instructions (16-bit aligned) */
	if ((data[1] & 0xF8) == 0xF0 || (data[1] & 0xF8) == 0xF8 ||
	    (data[1] & 0xE0) == 0xE0) {
		int thumb_instructions = 0;
		for (int i = 0; i < 32 && i < len/2; i++) {
			uint16_t halfword = ((uint16_t *)data)[i];
			if ((halfword & 0xF800) >= 0xE800) {
				thumb_instructions++;
			}
		}
		if (thumb_instructions > 10) {
			return STORAGE_HAS_CODE_DATA;
		}
	}

	/* Check for certificate/key data patterns */
	/* Certificates often start with ASN.1 SEQUENCE (0x30) or similar */
	if (data[0] == 0x30 && data[1] == 0x82) {
		return STORAGE_HAS_CODE_DATA;  /* Certificate data */
	}

	/* Check for high entropy data (likely encrypted/compressed/key material) */
	int non_zero = 0;
	int high_entropy = 0;
	for (int i = 0; i < 256 && i < len; i++) {
		if (data[i] != 0) {
			non_zero++;
			if (data[i] > 0x20 && data[i] < 0xFF) {
				high_entropy++;
			}
		}
	}

	if (non_zero > 200 && high_entropy > 150) {
		return STORAGE_HAS_CODE_DATA;  /* High entropy data */
	}

	/* Check for all zeros */
	int all_zeros = 1;
	for (int i = 0; i < 32 && i < len; i++) {
		if (data[i] != 0) {
			all_zeros = 0;
			break;
		}
	}
	if (all_zeros) {
		return STORAGE_EMPTY;
	}

	/* Check for valid storage_data patterns */
	if ((signed char)data[0] == -0x5d) {  /* 0xA3 - TLV format */
		return STORAGE_VALID_TLV;
	}

	/* Check for raw NAND parameters */
	boot_nand_para_t *nand = (boot_nand_para_t *)data;
	if (nand->ChannelCnt >= 1 && nand->ChannelCnt <= 4 &&
	    nand->ChipCnt >= 1 && nand->ChipCnt <= 8 &&
	    nand->SectorCntPerPage > 0 && nand->SectorCntPerPage <= 64) {
		return STORAGE_VALID_RAW;
	}

	return STORAGE_INVALID_FORMAT;
}

/* SBROM _parser_II exact implementation for validation
 *
 * Note: While the SBROM's _parser_II is called during certificate parsing,
 * the storage_data it validates is actually located in the TOC0 config
 * structure at offset 0x2D4, not inside the certificate itself.
 * The certificate parsing somehow references this external data.
 *
 * Returns bit flags indicating validation status
 */
static int sbrom_parser_ii_validate(const uint8_t *p_saddr, size_t len, size_t offset, FILE *stream)
{
	const uint8_t *pcVar1;

	fprintf(stream, "\nStorage Data Validation (TOC0 offset 0x%zX):\n", offset);

	/* Show all 384 bytes of storage_data */
	fprintf(stream, "  Complete storage_data (384 bytes):\n");
	int bytes_to_show = (len < 384) ? len : 384;
	for (int i = 0; i < bytes_to_show; i++) {
		if (i % 16 == 0) {
			if (i > 0) fprintf(stream, "\n");
			fprintf(stream, "    %04X: ", i);
		}
		fprintf(stream, "%02x ", p_saddr[i]);
	}
	fprintf(stream, "\n");

	/* SBROM exact check: if (*p_saddr == -0x5d) which is 0xA3 unsigned */
	if ((signed char)p_saddr[0] != -0x5d) {  /* 0xA3 check */
		/* Check if it's valid raw NAND parameters instead */
		/* SBROM accepts raw params if they look reasonable */
		boot_nand_para_t *nand_para = (boot_nand_para_t *)p_saddr;
		if (nand_para->ChannelCnt >= 1 && nand_para->ChannelCnt <= 4 &&
		    nand_para->ChipCnt >= 1 && nand_para->ChipCnt <= 8 &&
		    nand_para->SectorCntPerPage > 0 && nand_para->SectorCntPerPage <= 64) {
			fprintf(stream, "  Type: Raw NAND parameters (accepted by SBROM)\n");

			/* Decode NAND parameters using boot_nand_para_t structure */
			fprintf(stream, "\n  Decoded NAND Parameters:\n");
			fprintf(stream, "    ChannelCnt:        %u\n", nand_para->ChannelCnt);
			fprintf(stream, "    ChipCnt:           %u\n", nand_para->ChipCnt);
			fprintf(stream, "    ChipConnectInfo:   0x%08x\n", nand_para->ChipConnectInfo);
			fprintf(stream, "    RbCnt:             %u\n", nand_para->RbCnt);
			fprintf(stream, "    RbConnectInfo:     0x%08x\n", nand_para->RbConnectInfo);
			fprintf(stream, "    RbConnectMode:     %u\n", nand_para->RbConnectMode);
			fprintf(stream, "    BankCntPerChip:    %u\n", nand_para->BankCntPerChip);
			fprintf(stream, "    DieCntPerChip:     %u\n", nand_para->DieCntPerChip);
			fprintf(stream, "    PlaneCntPerDie:    %u\n", nand_para->PlaneCntPerDie);
			fprintf(stream, "    SectorCntPerPage:  %u (= %u KB page)\n",
				nand_para->SectorCntPerPage, nand_para->SectorCntPerPage / 2);
			fprintf(stream, "    PageCntPerPhyBlk:  %u\n", nand_para->PageCntPerPhyBlk);
			fprintf(stream, "    BlkCntPerDie:      %u\n", nand_para->BlkCntPerDie);
			fprintf(stream, "    OperationOpt:      0x%08x\n", nand_para->OperationOpt);
			fprintf(stream, "    FrequencePar:      %u MHz\n", nand_para->FrequencePar);
			fprintf(stream, "    EccMode:           %u (%s)\n",
				nand_para->EccMode, ecc_mode_to_string(nand_para->EccMode));

			/* NAND chip ID */
			fprintf(stream, "    NandChipId:        ");
			for (int i = 0; i < 8; i++) {
				fprintf(stream, "%02x ", nand_para->NandChipId[i]);
			}

			/* Try to identify manufacturer */
			fprintf(stream, "\n      Manufacturer:    0x%02x", nand_para->NandChipId[0]);
			switch(nand_para->NandChipId[0]) {
				case 0x01: fprintf(stream, " (Spansion/AMD)"); break;
				case 0x2c: fprintf(stream, " (Micron)"); break;
				case 0x45: fprintf(stream, " (SanDisk)"); break;
				case 0x89: fprintf(stream, " (Intel)"); break;
				case 0x92: fprintf(stream, " (EON)"); break;
				case 0x98: fprintf(stream, " (Toshiba/Kioxia)"); break;
				case 0x9b: fprintf(stream, " (ATO)"); break;
				case 0xad: fprintf(stream, " (Hynix)"); break;
				case 0xc2: fprintf(stream, " (Macronix)"); break;
				case 0xc8: fprintf(stream, " (ESMT/GigaDevice)"); break;
				case 0xec: fprintf(stream, " (Samsung)"); break;
				case 0xef: fprintf(stream, " (Winbond)"); break;
			}
			fprintf(stream, "\n");

			/* More parameters */
			fprintf(stream, "    ValidBlkRatio:     %u (%.1f%%)\n",
				nand_para->ValidBlkRatio, nand_para->ValidBlkRatio / 10.24);
			fprintf(stream, "    good_block_ratio:  %u (%.1f%%)\n",
				nand_para->good_block_ratio, nand_para->good_block_ratio / 10.24);
			fprintf(stream, "    ReadRetryType:     %u\n", nand_para->ReadRetryType);
			fprintf(stream, "    DDRType:           %u", nand_para->DDRType);
			switch(nand_para->DDRType) {
				case 0: fprintf(stream, " (SDR)\n"); break;
				case 1: fprintf(stream, " (ONFI DDR)\n"); break;
				case 2: fprintf(stream, " (ONFI DDR2)\n"); break;
				case 3: fprintf(stream, " (Toggle DDR)\n"); break;
				default: fprintf(stream, "\n"); break;
			}

			/* Reserved fields */
			fprintf(stream, "    Reserved fields:   ");
			int non_zero_reserved = 0;
			for (int i = 0; i < 32; i++) {
				if (nand_para->Reserved[i] != 0) {
					non_zero_reserved++;
				}
			}
			if (non_zero_reserved > 0) {
				fprintf(stream, "%d non-zero values in Reserved[32]\n", non_zero_reserved);
				for (int i = 0; i < 32; i++) {
					if (nand_para->Reserved[i] != 0) {
						fprintf(stream, "      Reserved[%d] = 0x%08x\n", i, nand_para->Reserved[i]);
					}
				}
			} else {
				fprintf(stream, "All zeros\n");
			}

			/* Calculate total capacity */
			uint32_t page_size = nand_para->SectorCntPerPage * 512;  /* sectors * 512 */
			uint32_t block_size = page_size * nand_para->PageCntPerPhyBlk;
			uint32_t die_size = block_size * nand_para->BlkCntPerDie;
			uint32_t total_size = die_size * nand_para->DieCntPerChip * nand_para->ChipCnt;

			fprintf(stream, "\n  Calculated Capacities:\n");
			fprintf(stream, "    Page size:         %u bytes\n", page_size);
			fprintf(stream, "    Block size:        %u KB\n", block_size / 1024);
			fprintf(stream, "    Die size:          %u MB\n", die_size / (1024*1024));
			fprintf(stream, "    Total size:        %u MB\n", total_size / (1024*1024));

			return STORAGE_VALID_RAW;  /* Valid raw NAND format */
		}

		/* Check if RSA key data has overwritten this area */
		/* RSA keys typically have high entropy and non-zero bytes throughout */
		if (len >= 256) {
			int non_zero_count = 0;
			int high_entropy_bytes = 0;

			/* Count non-zero bytes in first 256 bytes */
			for (int i = 0; i < 256; i++) {
				if (p_saddr[i] != 0) {
					non_zero_count++;
					/* High entropy: bytes > 0x20 and < 0xFF */
					if (p_saddr[i] > 0x20 && p_saddr[i] < 0xFF) {
						high_entropy_bytes++;
					}
				}
			}

			/* RSA key likely if:
			 * - Most bytes are non-zero (>200 out of 256)
			 * - High entropy content (>150 bytes in printable/high range)
			 * - Not a valid NAND structure pattern
			 */
			if (non_zero_count > 200 && high_entropy_bytes > 150) {
				fprintf(stream, "  ERROR: RSA key data detected (TOC0 generation bug)\n");
				fprintf(stream, "  The KEY item has overwritten the config structure!\n");
				fprintf(stream, "  (Found %d non-zero bytes with %d high-entropy bytes)\n",
					non_zero_count, high_entropy_bytes);
				return STORAGE_RSA_OVERWRITE;
			}
		}

		/* Check for empty storage_data (all zeros) */
		int all_zeros = 1;
		for (int i = 0; i < 32 && i < len; i++) {
			if (p_saddr[i] != 0) {
				all_zeros = 0;
				break;
			}
		}

		if (all_zeros) {
			fprintf(stream, "  WARNING: Empty storage_data (all zeros)\n");
			return STORAGE_EMPTY;
		}

		fprintf(stream, "  WARNING: No 0xA3 marker (found 0x%02X)\n", p_saddr[0]);
		fprintf(stream, "  WARNING: Not valid raw NAND parameters\n");
		return STORAGE_INVALID_FORMAT;
	}

	/* SBROM logic for parsing length after 0xA3 */
	/* The decompiled code checks p_saddr[1] in a complex way */
	if ((p_saddr[1] != 0) == 1) {
		if (p_saddr[1] != 0) {
			pcVar1 = p_saddr + 3;  /* Long form, skip 3 bytes */
		} else {
			pcVar1 = p_saddr;
			if ((p_saddr[1] != 0) == 1) {
				pcVar1 = p_saddr + 4;
			}
		}
	} else {
		pcVar1 = p_saddr + 2;  /* Short form, skip 2 bytes */
	}

	/* SBROM check for SEQUENCE marker: if (*pcVar1 == '0') which is 0x30 */
	if (*pcVar1 != 0x30) {  /* '0' in the decompiled code is 0x30 */
		fprintf(stream, "  ERROR: Missing 0x30 SEQUENCE marker\n");
		return STORAGE_TLV_NO_SEQ;
	}

	/* Skip SEQUENCE length using same logic */
	if ((pcVar1[1] != 0) == 1) {
		if (pcVar1[1] != 0) {
			pcVar1 = pcVar1 + 3;
		} else if ((pcVar1[1] != 0) == 1) {
			pcVar1 = pcVar1 + 4;
		}
	} else {
		pcVar1 = pcVar1 + 2;
	}

	/* SBROM check for INTEGER marker: if (*pcVar1 == '\x02') */
	if (*pcVar1 != 0x02) {
		fprintf(stream, "  ERROR: Missing 0x02 INTEGER marker\n");
		return STORAGE_TLV_NO_INT;
	}

	/* If we got here, SBROM will accept this and copy 32 bytes to context+0x358 */
	fprintf(stream, "  Type: ASN.1 DER TLV format (0xA3, 0x30, 0x02 markers found)\n");
	fprintf(stream, "  Note: SBROM will copy 32 bytes from offset %ld to context+0x358\n",
		(pcVar1 + 2) - p_saddr);

	return STORAGE_VALID_TLV;
}

static void print_toc0_item(const toc0_item_info *item,
			    const uint8_t *toc0_data, size_t data_size,
			    const uint8_t *fw_data, size_t fw_size,
			    FILE *stream)
{
#ifdef WITH_OPENSSL
	const uint8_t *blob;
#endif

	if (memcmp(item->end_marker, "IIE;", 4) != 0) {
		fprintf(stderr, "Invalid TOC0 item end marker\n");
		exit(EXIT_FAILURE);
	}

	if (item->offset + item->length > data_size) {
		fprintf(stderr, "Item offset and length exceed data size\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stream, "\nItem:\n");
	fprintf(stream, "  Name: 0x%06x (%s)\n", item->name,
		item_name(item->name));
	fprintf(stream, "  Offset: 0x%08x\n", item->offset);
	fprintf(stream, "  Length: %u bytes\n", item->length);
	fprintf(stream, "  Status: 0x%08x\n", item->status);
	fprintf(stream, "  Type: %u\n", item->type);
	fprintf(stream, "  Run Address: 0x%08x\n", item->load_addr);

#ifdef WITH_OPENSSL
	blob = toc0_data + item->offset;
#endif

	switch (item->name) {
	case TOC0_ITEM_NAME_CERT:
		fprintf(stream, "  -> Certificate File\n");

		/* Validate storage_data during certificate processing like SBROM does
		 * The SBROM's _parser_II is called during certificate parsing to
		 * validate the storage_data in the TOC0 config structure.
		 * Storage_data is 384 bytes starting at offset 0x2D4
		 */
		#define TOC0_STORAGE_DATA_OFFSET 0x2D4
		#define STORAGE_DATA_SIZE 384
		int validation_result = 0;

		/* First, detect what's actually at the kernel's expected offset */
		int kernel_offset_data_type = 0;
		if (data_size >= TOC0_STORAGE_DATA_OFFSET + STORAGE_DATA_SIZE) {
			kernel_offset_data_type = detect_data_type_at_offset(
				toc0_data + TOC0_STORAGE_DATA_OFFSET, STORAGE_DATA_SIZE);

			/* Now do the full validation */
			validation_result = sbrom_parser_ii_validate(toc0_data + TOC0_STORAGE_DATA_OFFSET,
						 STORAGE_DATA_SIZE,
						 TOC0_STORAGE_DATA_OFFSET, stream);
		} else if (data_size >= TOC0_STORAGE_DATA_OFFSET + 32) {
			/* If we have less than full storage_data, still validate what we have */
			kernel_offset_data_type = detect_data_type_at_offset(
				toc0_data + TOC0_STORAGE_DATA_OFFSET,
				data_size - TOC0_STORAGE_DATA_OFFSET);

			validation_result = sbrom_parser_ii_validate(toc0_data + TOC0_STORAGE_DATA_OFFSET,
						 data_size - TOC0_STORAGE_DATA_OFFSET,
						 TOC0_STORAGE_DATA_OFFSET, stream);
		}

		/* Check for alignment issues and enhance validation result */
		if (kernel_offset_data_type & STORAGE_HAS_CODE_DATA) {
			/* Code/data detected at kernel offset - will be corrupted */
			validation_result |= STORAGE_HAS_CODE_DATA;
			fprintf(stream, "\n  ⚠ ALIGNMENT ISSUE DETECTED:\n");
			fprintf(stream, "    Code or critical data found at offset 0x2D4\n");
			fprintf(stream, "    Kernel will blindly overwrite this with NAND parameters!\n");
		} else if ((kernel_offset_data_type & STORAGE_VALID_RAW) == 0 &&
		           (kernel_offset_data_type & STORAGE_VALID_TLV) == 0 &&
		           (kernel_offset_data_type & STORAGE_EMPTY) == 0) {
			/* Non-storage data at kernel offset */
			if (!(validation_result & STORAGE_RSA_OVERWRITE)) {
				validation_result |= STORAGE_HAS_CODE_DATA;
			}
		}

		/* Print boot compatibility once, after validation */
		if (validation_result != 0) {
			print_boot_compatibility(validation_result, stream);
		}

#ifdef WITH_OPENSSL
		parse_cert_for_rotpk(blob, item->length, stream);
		parse_cert_item(blob, item->length, fw_data);
#else
		fprintf(stderr, "Skipping cert parsing (OpenSSL disabled)\n");
#endif
		break;
	case TOC0_ITEM_NAME_FW:
		fprintf(stream, "  -> Signed Boot Firmware\n");
		break;
	case TOC0_ITEM_NAME_KEY:
		fprintf(stream, "  -> Key Ladder or Key Item\n");
#ifdef WITH_OPENSSL
		parse_key_item(blob, item->length, stream);
#else
		fprintf(stderr,
			"Skipping key item parsing (OpenSSL disabled)\n");
#endif
		break;
	default:
		fprintf(stderr, "Unknown item type 0x%08x\n", item->name);
		exit(EXIT_FAILURE);
	}
}

/* Validate TOC0 structure padding per BSP requirements
 * BSP createtoc0.c line 58 adds 3KB padding before first item:
 * offset = ((sizeof(sbrom_toc0_head_info_t) + 2 * sizeof(sbrom_toc0_item_info_t) + 31) & (~31)) + 3*1024;
 *
 * Returns: 0 if padding looks correct, flags indicating issues otherwise
 */
#define PADDING_OK              0x0000
#define PADDING_MISSING_3KB     0x0001  /* Missing 3KB padding */
#define PADDING_TOO_SMALL       0x0002  /* Padding smaller than expected */
#define PADDING_NO_ITEMS        0x0004  /* No items found */

static int validate_toc0_padding(const toc0_main_info *main_info,
                                  const toc0_item_info *items,
                                  FILE *stream)
{
	uint32_t expected_base;
	uint32_t expected_first_item_offset;
	uint32_t actual_first_item_offset = UINT32_MAX;
	const char *first_item_name = "UNKNOWN";
	int flags = PADDING_OK;

	if (main_info->num_items == 0) {
		fprintf(stream, "\nTOC0 Padding Validation:\n");
		fprintf(stream, "  No items found, cannot validate padding\n");
		return PADDING_NO_ITEMS;
	}

	/* Find the first item (lowest offset) */
	for (uint32_t i = 0; i < main_info->num_items; i++) {
		if (items[i].offset < actual_first_item_offset) {
			actual_first_item_offset = items[i].offset;
			first_item_name = item_name(items[i].name);
		}
	}

	/* Calculate expected first item offset with 3KB padding
	 * BSP formula: ((header + N*item + 31) & ~31) + 3072
	 */
	expected_base = (sizeof(toc0_main_info) + main_info->num_items * sizeof(toc0_item_info) + 31) & ~31;
	expected_first_item_offset = expected_base + 3072;  /* 3KB = 3072 bytes */

	fprintf(stream, "\nTOC0 Padding Validation:\n");
	fprintf(stream, "  Header + %u items base:      0x%03x (%u bytes)\n",
	        main_info->num_items, expected_base, expected_base);
	fprintf(stream, "  Expected first item offset:  0x%04x (%u bytes) [with 3KB padding]\n",
	        expected_first_item_offset, expected_first_item_offset);
	fprintf(stream, "  Actual first item offset:    0x%04x (%u bytes) [%s]\n",
	        actual_first_item_offset, actual_first_item_offset, first_item_name);

	/* Calculate actual padding */
	if (actual_first_item_offset > expected_base) {
		uint32_t actual_padding = actual_first_item_offset - expected_base;
		fprintf(stream, "  Actual padding:              0x%03x (%u bytes)\n",
		        actual_padding, actual_padding);

		if (actual_padding == 3072) {
			fprintf(stream, "  Status:                      ✓ CORRECT (3KB padding present)\n");
			fprintf(stream, "  Compliance:                  BSP-compatible structure\n");
		} else if (actual_padding < 3072) {
			flags |= PADDING_TOO_SMALL;
			fprintf(stream, "  Status:                      ✗ INCORRECT (padding too small by %u bytes)\n",
			        3072 - actual_padding);
			fprintf(stream, "  Compliance:                  NON-COMPLIANT with BSP requirements\n");
			fprintf(stream, "\n  ⚠ WARNING: Missing 3KB padding may cause NAND boot failure!\n");
			fprintf(stream, "    BSP TOC0 generation adds 3072 bytes before first item\n");
			fprintf(stream, "    This padding may be required for proper SBROM operation\n");
		} else {
			fprintf(stream, "  Status:                      ⚠ UNUSUAL (padding larger than expected by %u bytes)\n",
			        actual_padding - 3072);
		}
	} else if (actual_first_item_offset == expected_base) {
		flags |= PADDING_MISSING_3KB;
		fprintf(stream, "  Actual padding:              0x000 (0 bytes)\n");
		fprintf(stream, "  Status:                      ✗ MISSING (no 3KB padding)\n");
		fprintf(stream, "  Compliance:                  NON-COMPLIANT with BSP requirements\n");
		fprintf(stream, "\n  ✗ CRITICAL: Missing 3KB padding will likely cause NAND boot failure!\n");
		fprintf(stream, "    BSP TOC0 generation (createtoc0.c line 58):\n");
		fprintf(stream, "      offset = ((header + items + 31) & ~31) + 3*1024;\n");
		fprintf(stream, "    All working BSP TOC0 files have this padding\n");
		fprintf(stream, "    SBROM may require this for proper TOC0 parsing in 1K mode\n");
	} else {
		fprintf(stream, "  Status:                      ✗ INVALID (first item before items table end)\n");
		fprintf(stream, "  Compliance:                  CORRUPTED structure\n");
	}

	return flags;
}

void output_toc0_info(void *sector, FILE *inf, FILE *stream, bool verbose)
{
	toc0_main_info main_header;
	size_t bytes_in_sector = 512;
	size_t remain;
	uint32_t data_size;
	uint8_t *toc0_data;
	toc0_main_info *main_info;
	const toc0_item_info *items;
	const uint8_t *fw_data = NULL;
	size_t fw_size = 0;

	memcpy(&main_header, sector, sizeof(main_header));

	if (memcmp(main_header.name, TOC0_MAIN_INFO_NAME,
		   sizeof(main_header.name)) != 0) {
		fprintf(stderr, "Invalid TOC0 name: '%.8s' (expected '%s')\n",
			main_header.name, TOC0_MAIN_INFO_NAME);
		return;
	}

	if (main_header.magic != TOC0_MAIN_MAGIC) {
		fprintf(stderr,
			"Invalid TOC0 magic: 0x%08x (expected 0x%08x)\n",
			main_header.magic, TOC0_MAIN_MAGIC);
		return;
	}

	if (main_header.end_marker != TOC0_MAIN_END) {
		fprintf(stderr,
			"Invalid TOC0 end marker: 0x%08x (expected 0x%08x)\n",
			main_header.end_marker, TOC0_MAIN_END);
		return;
	}

	data_size = main_header.length;

	if (data_size < sizeof(toc0_main_info)) {
		fprintf(stderr, "Invalid/too-small TOC0 length from header\n");
		return;
	}

	toc0_data = malloc(data_size);

	if (!toc0_data) {
		fprintf(stderr, "Failed to allocate %u bytes for TOC0 data\n",
			data_size);
		return;
	}

	if (bytes_in_sector > data_size)
		bytes_in_sector = data_size;

	memcpy(toc0_data, sector, bytes_in_sector);

	remain = data_size - bytes_in_sector;

	if (remain > 0) {
		if (fread(toc0_data + bytes_in_sector, 1, remain, inf) !=
		    (size_t)remain) {
			fprintf(stderr,
				"Failed to read the remaining %zu bytes of TOC0\n",
				(size_t)remain);
			free(toc0_data);
			return;
		}
	}

	main_info = (toc0_main_info *)toc0_data;

	fprintf(stream, "TOC0 Name: '%.8s'\n", main_info->name);
	fprintf(stream, "Serial Number: 0x%08x\n", main_info->serial);
	fprintf(stream, "Status: 0x%08x\n", main_info->status);
	fprintf(stream, "Number of TOC0 items: %d\n", main_info->num_items);
	fprintf(stream, "Total size: %d bytes\n", main_info->length);

	if (verbose) {
		fprintf(stream, "Platform: %02x %02x %02x %02x\n",
			main_info->platform[0], main_info->platform[1],
			main_info->platform[2], main_info->platform[3]);
	}

	if (main_info->length <= data_size) {
		uint32_t calc = calc_checksum(toc0_data, main_info->length);
		uint32_t stored = main_info->checksum;

		if (calc != 2 * stored) {
			fprintf(stderr, "Checksum validation failed\n");
			fprintf(stream, "Checksum: 0x%08x (INVALID)\n", stored);
			fprintf(stream, "Calculated Checksum: 0x%08x\n", calc);
			free(toc0_data);
			return;
		}
	} else {
		fprintf(stderr, "TOC0 length field exceeds buffer size\n");
		free(toc0_data);
		return;
	}

	if (sizeof(toc0_main_info) +
		    main_info->num_items * sizeof(toc0_item_info) >
	    data_size) {
		fprintf(stderr, "Not enough data for all TOC0 items\n");
		free(toc0_data);
		return;
	}

	items = (toc0_item_info *)(toc0_data + sizeof(toc0_main_info));

	/* Validate TOC0 padding structure */
	validate_toc0_padding(main_info, items, stream);

	for (uint32_t i = 0; i < main_info->num_items; i++) {
		if (items[i].name == TOC0_ITEM_NAME_FW) {
			if (items[i].offset + items[i].length <= data_size) {
				fw_data = toc0_data + items[i].offset;
				fw_size = items[i].length;
			}
			break;
		}
	}

	for (uint32_t i = 0; i < main_info->num_items; i++) {
		if ((uintptr_t)(&items[i]) + sizeof(toc0_item_info) -
			    (uintptr_t)toc0_data >
		    data_size) {
			fprintf(stderr, "Truncated item info\n");
			break;
		}
		print_toc0_item(&items[i], toc0_data, data_size, fw_data,
				fw_size, stream);
	}

	free(toc0_data);
}
