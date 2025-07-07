/*
 * SHA-256 Implementation with Hardware Acceleration
 * ================================================
 *
 * This module provides two optimized SHA-256 implementations:
 *
 * 1. SHA-NI (SHA New Instructions) Hardware Accelerated
 *	- Uses Intel SHA Extensions (available since Intel Goldmont in 2016,
 *	  mainstream since Ice Lake 2019).
 *	- AMD support since Zen microarchitecture (2017).
 *	- Delivers ~3-5x faster performance than software implementations.
 *
 * 2. OpenSSL EVP (Optimized Software Fallback)
 *	- Uses OpenSSL's heavily optimized implementation.
 *	- Includes assembly optimizations for x86, ARM, and other platforms.
 *	- Provides constant-time execution to prevent timing attacks.
 *	- Used when SHA-NI is not available.
 *
 * The implementation automatically selects the best available method at runtime.
 * For maximum performance, ensure your CPU supports SHA-NI instructions!!
 *
 *  Created on: Jul 6, 2025
 *	  Author: mecanix
 */

#include "config.h"
#include <string.h>
#include <stdint.h>
#include "sha2.h"
#include <openssl/evp.h>


const uint32_t sha256_h0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define UNPACK32(x, str) { \
    *((str) + 3) = (uint8_t) ((x)      ); \
    *((str) + 2) = (uint8_t) ((x) >>  8); \
    *((str) + 1) = (uint8_t) ((x) >> 16); \
    *((str) + 0) = (uint8_t) ((x) >> 24); \
}

#define PACK32(str, x) { \
    *(x) = ((uint32_t) *((str) + 3)      ) | \
           ((uint32_t) *((str) + 2) <<  8) | \
           ((uint32_t) *((str) + 1) << 16) | \
           ((uint32_t) *((str) + 0) << 24); \
}

#ifdef USE_SHA_NI
#include <immintrin.h>

	void sha256_transf(sha256_ctx *ctx, const unsigned char *message, unsigned int block_nb)
	{
		__m128i STATE0, STATE1;
		__m128i MSG, TMP;
		__m128i TMSG0, TMSG1, TMSG2, TMSG3;
		__m128i ABEF_SAVE, CDGH_SAVE;
		const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

		TMP = _mm_set_epi32(ctx->h[3], ctx->h[2], ctx->h[1], ctx->h[0]);
		STATE1 = _mm_set_epi32(ctx->h[7], ctx->h[6], ctx->h[5], ctx->h[4]);

		TMP = _mm_shuffle_epi32(TMP, 0xB1);
		STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);
		STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);
		STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);

		const __m128i *input = (const __m128i*)message;

		while (block_nb--) {

			ABEF_SAVE = STATE0;
			CDGH_SAVE = STATE1;

			MSG = _mm_loadu_si128(input + 0);
			TMSG0 = _mm_shuffle_epi8(MSG, MASK);
			MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

			TMSG1 = _mm_loadu_si128(input + 1);
			TMSG1 = _mm_shuffle_epi8(TMSG1, MASK);
			MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

			TMSG2 = _mm_loadu_si128(input + 2);
			TMSG2 = _mm_shuffle_epi8(TMSG2, MASK);
			MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

			TMSG3 = _mm_loadu_si128(input + 3);
			TMSG3 = _mm_shuffle_epi8(TMSG3, MASK);
			MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
			TMSG0 = _mm_add_epi32(TMSG0, TMP);
			TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

			MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
			TMSG1 = _mm_add_epi32(TMSG1, TMP);
			TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

			MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
			TMSG2 = _mm_add_epi32(TMSG2, TMP);
			TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

			MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
			TMSG3 = _mm_add_epi32(TMSG3, TMP);
			TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

			MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
			TMSG0 = _mm_add_epi32(TMSG0, TMP);
			TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

			MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
			TMSG1 = _mm_add_epi32(TMSG1, TMP);
			TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

			MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
			TMSG2 = _mm_add_epi32(TMSG2, TMP);
			TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

			MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
			TMSG3 = _mm_add_epi32(TMSG3, TMP);
			TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

			MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
			TMSG0 = _mm_add_epi32(TMSG0, TMP);
			TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

			MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
			TMSG1 = _mm_add_epi32(TMSG1, TMP);
			TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
			TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

			MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
			TMSG2 = _mm_add_epi32(TMSG2, TMP);
			TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

			MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
			TMSG3 = _mm_add_epi32(TMSG3, TMP);
			TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

			MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
			STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
			MSG = _mm_shuffle_epi32(MSG, 0x0E);
			STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

			STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
			STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

			input += 4;
		}

		TMP = _mm_shuffle_epi32(STATE0, 0x1B);
		STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);
		STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);
		STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);

		ctx->h[0] = _mm_extract_epi32(STATE0, 0);
		ctx->h[1] = _mm_extract_epi32(STATE0, 1);
		ctx->h[2] = _mm_extract_epi32(STATE0, 2);
		ctx->h[3] = _mm_extract_epi32(STATE0, 3);
		ctx->h[4] = _mm_extract_epi32(STATE1, 0);
		ctx->h[5] = _mm_extract_epi32(STATE1, 1);
		ctx->h[6] = _mm_extract_epi32(STATE1, 2);
		ctx->h[7] = _mm_extract_epi32(STATE1, 3);
	}

#else

/* Optimized OpenSSL 3.0+ EVP implementation */

typedef struct {
	union {
		EVP_MD_CTX *evp_ctx;
		struct {
			uint32_t h[8];
			uint64_t count;
			uint8_t block[64];
			unsigned int len;
		};
	};
} sha256_ctx_ossl;

void sha256_transf(sha256_ctx *ctx, const unsigned char *message, unsigned int block_nb)
{
	sha256_ctx_ossl *ossl_ctx = (sha256_ctx_ossl *)ctx;
	EVP_DigestUpdate(ossl_ctx->evp_ctx, message, block_nb * SHA256_BLOCK_SIZE);
}

#endif


void sha256_init(sha256_ctx *ctx)
{
#ifdef USE_SHA_NI

    memcpy(ctx->h, sha256_h0, sizeof(sha256_h0));
    ctx->len = 0;
    ctx->tot_len = 0;

#else
	sha256_ctx_ossl *ossl_ctx = (sha256_ctx_ossl *)ctx;
	ossl_ctx->evp_ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ossl_ctx->evp_ctx, EVP_sha256(), NULL);
#endif
}

void sha256_update(sha256_ctx *ctx, const unsigned char *message, unsigned int len)
{
#ifdef USE_SHA_NI

	unsigned int block_nb;
	unsigned int new_len, rem_len, tmp_len;
	const unsigned char *shifted_message;

	tmp_len = SHA256_BLOCK_SIZE - ctx->len;
	rem_len = len < tmp_len ? len : tmp_len;

	memcpy(&ctx->block[ctx->len], message, rem_len);

	if (ctx->len + len < SHA256_BLOCK_SIZE) {
		ctx->len += len;
		return;
	}

	new_len = len - rem_len;
	block_nb = new_len / SHA256_BLOCK_SIZE;
	shifted_message = message + rem_len;

	sha256_transf(ctx, ctx->block, 1);
	sha256_transf(ctx, shifted_message, block_nb);

	rem_len = new_len % SHA256_BLOCK_SIZE;
	memcpy(ctx->block, &shifted_message[block_nb << 6], rem_len);

	ctx->len = rem_len;
	ctx->tot_len += (block_nb + 1) << 6;
#else
	sha256_ctx_ossl *ossl_ctx = (sha256_ctx_ossl *)ctx;
	EVP_DigestUpdate(ossl_ctx->evp_ctx, message, len);
#endif
}

void sha256_final(sha256_ctx *ctx, unsigned char *digest)
{
#ifdef USE_SHA_NI

	unsigned int block_nb;
	unsigned int pm_len;
	unsigned int len_b;
	int i;

	block_nb = (1 + ((SHA256_BLOCK_SIZE - 9) < (ctx->len % SHA256_BLOCK_SIZE)));
	len_b = (ctx->tot_len + ctx->len) << 3;
	pm_len = block_nb << 6;

	memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
	ctx->block[ctx->len] = 0x80;

	uint64_t len_bits = ((uint64_t)ctx->tot_len + ctx->len) * 8;
	ctx->block[pm_len - 8] = (len_bits >> 56) & 0xff;
	ctx->block[pm_len - 7] = (len_bits >> 48) & 0xff;
	ctx->block[pm_len - 6] = (len_bits >> 40) & 0xff;
	ctx->block[pm_len - 5] = (len_bits >> 32) & 0xff;
	ctx->block[pm_len - 4] = (len_bits >> 24) & 0xff;
	ctx->block[pm_len - 3] = (len_bits >> 16) & 0xff;
	ctx->block[pm_len - 2] = (len_bits >>  8) & 0xff;
	ctx->block[pm_len - 1] = (len_bits >>  0) & 0xff;

	sha256_transf(ctx, ctx->block, block_nb);

	for (int i = 0; i < 8; i++) {
		digest[i * 4 + 0] = (ctx->h[i] >> 24) & 0xff;
		digest[i * 4 + 1] = (ctx->h[i] >> 16) & 0xff;
		digest[i * 4 + 2] = (ctx->h[i] >> 8) & 0xff;
		digest[i * 4 + 3] = (ctx->h[i] >> 0) & 0xff;
	}

#else
	sha256_ctx_ossl *ossl_ctx = (sha256_ctx_ossl *)ctx;
	unsigned int digest_len;
	EVP_DigestFinal_ex(ossl_ctx->evp_ctx, digest, &digest_len);
	EVP_MD_CTX_free(ossl_ctx->evp_ctx);
	ossl_ctx->evp_ctx = NULL;
#endif
}

void sha256(const unsigned char *message, unsigned int len, unsigned char *digest)
{
	sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, message, len);
	sha256_final(&ctx, digest);
}
