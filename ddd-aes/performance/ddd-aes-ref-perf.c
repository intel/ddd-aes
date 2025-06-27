/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#include "ddd-aes-ref-perf.h"

/// @brief Calculate POLYVAL dot() operation result for two values.
/// @param a Left operand.
/// @param b Right operand.
/// @return dot(a, b) = (a * b * x^-128) mod (x^128 + x^127 + x^126 + x^121 + 1) (see RFC 8452).
FORCE_INLINE static inline __m128i polyval_dot(const __m128i a, const __m128i b)
{
    // References:
    // (1)
    // Gueron, Kounavis, "Intel Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode",
    // whitepaper, rev 2.02, April 2014.
    // URL: https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
    //
    // (2)
    // Gueron, "AES-GCM for Efficient Authenticated Encryption – Ending the Reign of HMAC-SHA-1?",
    // presentation on RWC 2013 workshop.
    // URL: https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf

    __m128i tmp1, tmp2, tmp3, tmp4;

    // Schoolbook multiplication (Algorithm 1 in the whitepaper)
    // Potential optimization: consider Karatsuba instead (Algorithm 2, 3x PCLMUL vs 4x in schoolbook)
    tmp1 = _mm_clmulepi64_si128(a, b, 0x00); // A0 * B0
    tmp2 = _mm_clmulepi64_si128(a, b, 0x10); // A1 * B0
    tmp3 = _mm_clmulepi64_si128(a, b, 0x01); // A0 * B1
    tmp4 = _mm_clmulepi64_si128(a, b, 0x11); // A1 * B1
    tmp2 = _mm_xor_si128(tmp2, tmp3);        // [F1 ^ E1 : F0 ^ E0]
    tmp3 = _mm_slli_si128(tmp2, 8);          // [F0 ^ E0 : zeroes]
    tmp2 = _mm_srli_si128(tmp2, 8);          // [zeroes : F1 ^ E1]
    tmp1 = _mm_xor_si128(tmp1, tmp3);        // [F0 ^ E0 ^ C1 : C0]
    tmp4 = _mm_xor_si128(tmp4, tmp2);        // [D1 : F1 ^ E1 ^ D0]

    // Multiplication result (unreduced yet, 256 bits):
    // [tmp4 : tmp1] = [D1 : F1 ^ E1 ^ D0 : F0 ^ E0 ^ C1 : C0], page 13 of the whitepaper or page 15 of the presentation

    // "Fast reduction modulo [POLYVAL field polynomial]" from the presentation (page 20)
    // Potential optimization: consider "Aggregated reduction method" from the whitepaper (page 24) to decrease the
    // number of reductions per number of blocks processed
    const __m128i FIELD_POLY = _mm_setr_epi32(0x1, 0, 0, (int)0xc2000000);

    tmp3 = _mm_clmulepi64_si128(tmp1, FIELD_POLY, 0x10); // X0 (which is the same as C0 above) * 0xc2<...>
    tmp2 = _mm_shuffle_epi32(tmp1, 78);                  // swap 64-bit parts for the subsequent XOR
    tmp1 = _mm_xor_si128(tmp3, tmp2);                    // [X0 ^ A1 : X1 ^ A0]

    tmp3 = _mm_clmulepi64_si128(tmp1, FIELD_POLY, 0x10); // B0 * 0xc2<...>
    tmp2 = _mm_shuffle_epi32(tmp1, 78);                  // swap 64-bit parts for the subsequent XOR
    tmp1 = _mm_xor_si128(tmp2, tmp3);                    // [B0 ^ C1 : B1 ^ C0]

    tmp2 = _mm_xor_si128(tmp1, tmp4); // [D1 ^ X3 (same as D1 in mul) : D0 ^ X2 (same as F1 ^ E1 ^ D0 in mul)]

    zeroize_secret(&tmp1, sizeof(tmp1));
    zeroize_secret(&tmp3, sizeof(tmp3));
    zeroize_secret(&tmp4, sizeof(tmp4));

    return tmp2;
}

/// @brief  Four-way POLYVAL calculation implementation.
/// @param[in,out] hval Calculated POLYVAL tag of POLYVAL_TAG_LEN_BYTES.
/// @param[in] state1 Incoming data block 1 of POLYVAL_BLOCK_LEN_BYTES.
/// @param[in] state2 Incoming data block 2 of POLYVAL_BLOCK_LEN_BYTES.
/// @param[in] state3 Incoming data block 3 of POLYVAL_BLOCK_LEN_BYTES.
/// @param[in] state4 Incoming data block 4 of POLYVAL_BLOCK_LEN_BYTES.
/// @param[in] hk POLYVAL key for incoming block 1.
/// @param[in] hk1 POLYVAL key for incoming block 2.
/// @param[in] hk2 POLYVAL key for incoming block 3.
/// @param[in] hk3 POLYVAL key for incoming block 4.
FORCE_INLINE static inline void polyval_x4(__m128i* hval,
                                           __m128i state1,
                                           __m128i state2,
                                           __m128i state3,
                                           __m128i state4,
                                           const __m128i hk,
                                           const __m128i hk1,
                                           const __m128i hk2,
                                           const __m128i hk3)
{
    *hval = _mm_xor_si128(*hval, state1);

    __m128i tmp1_1, tmp2_1, tmp3_1, tmp4_1;

    // Schoolbook multiplication (Algorithm 1 in the whitepaper)
    tmp1_1 = _mm_clmulepi64_si128(*hval, hk3, 0x00);
    tmp2_1 = _mm_clmulepi64_si128(*hval, hk3, 0x10);
    tmp3_1 = _mm_clmulepi64_si128(*hval, hk3, 0x01);
    tmp4_1 = _mm_clmulepi64_si128(*hval, hk3, 0x11);
    tmp2_1 = _mm_xor_si128(tmp2_1, tmp3_1);
    tmp3_1 = _mm_slli_si128(tmp2_1, 8);
    tmp2_1 = _mm_srli_si128(tmp2_1, 8);
    tmp1_1 = _mm_xor_si128(tmp1_1, tmp3_1);
    tmp4_1 = _mm_xor_si128(tmp4_1, tmp2_1);

    __m128i tmp1_2, tmp2_2, tmp3_2, tmp4_2;

    // Schoolbook multiplication (Algorithm 1 in the whitepaper)
    tmp1_2 = _mm_clmulepi64_si128(state2, hk2, 0x00);
    tmp2_2 = _mm_clmulepi64_si128(state2, hk2, 0x10);
    tmp3_2 = _mm_clmulepi64_si128(state2, hk2, 0x01);
    tmp4_2 = _mm_clmulepi64_si128(state2, hk2, 0x11);
    tmp2_2 = _mm_xor_si128(tmp2_2, tmp3_2);
    tmp3_2 = _mm_slli_si128(tmp2_2, 8);
    tmp2_2 = _mm_srli_si128(tmp2_2, 8);
    tmp1_2 = _mm_xor_si128(tmp1_2, tmp3_2);
    tmp4_2 = _mm_xor_si128(tmp4_2, tmp2_2);

    __m128i tmp1_3, tmp2_3, tmp3_3, tmp4_3;

    // Schoolbook multiplication (Algorithm 1 in the whitepaper)
    tmp1_3 = _mm_clmulepi64_si128(state3, hk1, 0x00);
    tmp2_3 = _mm_clmulepi64_si128(state3, hk1, 0x10);
    tmp3_3 = _mm_clmulepi64_si128(state3, hk1, 0x01);
    tmp4_3 = _mm_clmulepi64_si128(state3, hk1, 0x11);
    tmp2_3 = _mm_xor_si128(tmp2_3, tmp3_3);
    tmp3_3 = _mm_slli_si128(tmp2_3, 8);
    tmp2_3 = _mm_srli_si128(tmp2_3, 8);
    tmp1_3 = _mm_xor_si128(tmp1_3, tmp3_3);
    tmp4_3 = _mm_xor_si128(tmp4_3, tmp2_3);

    __m128i tmp1_4, tmp2_4, tmp3_4, tmp4_4;

    // Schoolbook multiplication (Algorithm 1 in the whitepaper)
    tmp1_4 = _mm_clmulepi64_si128(state4, hk, 0x00);
    tmp2_4 = _mm_clmulepi64_si128(state4, hk, 0x10);
    tmp3_4 = _mm_clmulepi64_si128(state4, hk, 0x01);
    tmp4_4 = _mm_clmulepi64_si128(state4, hk, 0x11);
    tmp2_4 = _mm_xor_si128(tmp2_4, tmp3_4);
    tmp3_4 = _mm_slli_si128(tmp2_4, 8);
    tmp2_4 = _mm_srli_si128(tmp2_4, 8);
    tmp1_4 = _mm_xor_si128(tmp1_4, tmp3_4);
    tmp4_4 = _mm_xor_si128(tmp4_4, tmp2_4);

    // Summing whole state
    tmp1_1 = _mm_xor_si128(tmp1_1, tmp1_2);
    tmp1_1 = _mm_xor_si128(tmp1_1, tmp1_3);
    tmp1_1 = _mm_xor_si128(tmp1_1, tmp1_4);
    tmp2_1 = _mm_xor_si128(tmp2_1, tmp2_2);
    tmp2_1 = _mm_xor_si128(tmp2_1, tmp2_3);
    tmp2_1 = _mm_xor_si128(tmp2_1, tmp2_4);
    tmp3_1 = _mm_xor_si128(tmp3_1, tmp3_2);
    tmp3_1 = _mm_xor_si128(tmp3_1, tmp3_3);
    tmp3_1 = _mm_xor_si128(tmp3_1, tmp3_4);
    tmp4_1 = _mm_xor_si128(tmp4_1, tmp4_2);
    tmp4_1 = _mm_xor_si128(tmp4_1, tmp4_3);
    tmp4_1 = _mm_xor_si128(tmp4_1, tmp4_4);

    // "Fast reduction modulo [POLYVAL field polynomial]" from the presentation (page 20)
    const __m128i FIELD_POLY = _mm_setr_epi32(0x1, 0, 0, (int)0xc2000000);

    tmp3_1 = _mm_clmulepi64_si128(tmp1_1, FIELD_POLY, 0x10);
    tmp2_1 = _mm_shuffle_epi32(tmp1_1, 78);
    tmp1_1 = _mm_xor_si128(tmp3_1, tmp2_1);

    tmp3_1 = _mm_clmulepi64_si128(tmp1_1, FIELD_POLY, 0x10);
    tmp2_1 = _mm_shuffle_epi32(tmp1_1, 78);
    tmp1_1 = _mm_xor_si128(tmp2_1, tmp3_1);

    *hval = _mm_xor_si128(tmp1_1, tmp4_1);

    zeroize_secret(&tmp1_1, sizeof(tmp1_1));
    zeroize_secret(&tmp1_2, sizeof(tmp1_2));
    zeroize_secret(&tmp1_3, sizeof(tmp1_3));
    zeroize_secret(&tmp1_4, sizeof(tmp1_4));
    zeroize_secret(&tmp2_1, sizeof(tmp2_1));
    zeroize_secret(&tmp2_2, sizeof(tmp2_2));
    zeroize_secret(&tmp2_3, sizeof(tmp2_3));
    zeroize_secret(&tmp2_4, sizeof(tmp2_4));
    zeroize_secret(&tmp3_1, sizeof(tmp3_1));
    zeroize_secret(&tmp3_2, sizeof(tmp3_2));
    zeroize_secret(&tmp3_3, sizeof(tmp3_3));
    zeroize_secret(&tmp3_4, sizeof(tmp3_4));
    zeroize_secret(&tmp4_1, sizeof(tmp4_1));
    zeroize_secret(&tmp4_2, sizeof(tmp4_2));
    zeroize_secret(&tmp4_3, sizeof(tmp4_3));
    zeroize_secret(&tmp4_4, sizeof(tmp4_4));
}

/// @brief AES-128 key scheduling helper function that based on the result of aeskeygenassist call in @p temp2
/// @brief and the previous round key in @p temp1 generates the next round key.
FORCE_INLINE static inline __m128i aes_128_assist(__m128i temp1, __m128i temp2)
{
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);

    zeroize_secret(&temp2, sizeof(temp2));
    zeroize_secret(&temp3, sizeof(temp3));

    return temp1;
}

/// @brief AES-128 key scheduling algorithm. Produces rounds keys from the input key.
/// @param[in] k Input data. Key.
/// @param[out] expanded_key Output data. Round keys.
static void precompute_aes_key(const uint8_t* const k, uint8_t* expanded_key)
{
    __m128i temp1, temp2;
    __m128i* key_schedule = (__m128i*)expanded_key;
    temp1 = _mm_loadu_si128((__m128i*)k);
    key_schedule[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
    temp1 = aes_128_assist(temp1, temp2);
    key_schedule[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
    temp1 = aes_128_assist(temp1, temp2);
    key_schedule[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
    temp1 = aes_128_assist(temp1, temp2);
    key_schedule[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
    temp1 = aes_128_assist(temp1, temp2);
    key_schedule[4] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
    temp1 = aes_128_assist(temp1, temp2);
    key_schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
    temp1 = aes_128_assist(temp1, temp2);
    key_schedule[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
    temp1 = aes_128_assist(temp1, temp2);
    key_schedule[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
    temp1 = aes_128_assist(temp1, temp2);
    key_schedule[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
    temp1 = aes_128_assist(temp1, temp2);
    key_schedule[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
    temp1 = aes_128_assist(temp1, temp2);
    key_schedule[10] = temp1;

    zeroize_secret(&temp1, sizeof(temp1));
    zeroize_secret(&temp2, sizeof(temp2));
}

void precompute_key(const uint8_t* const key, uint8_t* expanded_key)
{
    precompute_aes_key(key, expanded_key);
    for (size_t i = 0; i < POLYVAL_KEYSIZE_BYTES; i++) {
        expanded_key[(176) + i] = key[(2 * AES_KEYSIZE_BYTES) + i];
    }

    __m128i hk = _mm_loadu_si128((__m128i*)(expanded_key + ((176))));
    __m128i hk1;
    __m128i hk2;
    __m128i hk3;
    hk1 = polyval_dot(hk, hk);
    hk2 = polyval_dot(hk1, hk);
    hk3 = polyval_dot(hk2, hk);

    _mm_storeu_si128((__m128i*)(expanded_key + (176) + POLYVAL_KEYSIZE_BYTES), hk1);
    _mm_storeu_si128((__m128i*)(expanded_key + (176) + (2 * POLYVAL_KEYSIZE_BYTES)), hk2);
    _mm_storeu_si128((__m128i*)(expanded_key + (176) + (3 * POLYVAL_KEYSIZE_BYTES)), hk3);

    zeroize_secret(&hk, sizeof(hk));
    zeroize_secret(&hk1, sizeof(hk1));
    zeroize_secret(&hk2, sizeof(hk2));
    zeroize_secret(&hk3, sizeof(hk3));
}

/// @brief Finite-field multiplication by a constant 2.
/// @brief Same field as in AES-XTS.
/// @param[in,out] out Input/output data. out = 2 * out. Precondition: must be exactly 128 bits.
static void times_2(uint64_t out[static 2])
{
    // Multiplication by two is a shift by 1 with a conditional XOR with a constant
    uint64_t carry_in = 0;
    uint64_t carry_out = 0;
    for (size_t i = 0; i < 2; ++i) {
        carry_out = (out[i] >> 63);
        out[i] = (out[i] << 1) ^ carry_in;
        carry_in = carry_out;
    }

    out[0] ^= 0x87 & ((~carry_in) + 1);
}

/// @brief DDD-AES encryption function core implementation.
/// @param[in] m Plaintext (input).
/// @param[out] c Ciphertext (output). The result of DDD-AES encryption function application to @p m.
/// @param[in] blen Plaintext length (in bytes).
/// @param[in] k DDD-AES key (expanded form).
/// @param[in] t Tweak.
/// @return 0 on success, error code < 0 on error.
static int encrypt_with_precomputed_aes_key(const uint8_t* const m,
                                            uint8_t* c,
                                            const uint32_t blen,
                                            const uint8_t* const k,
                                            const uint8_t* const t)
{
    const uint32_t blen_full_blocks = (blen / BLOCKSIZE_BYTES) * BLOCKSIZE_BYTES;
    const uint32_t blen_full_4_blocks =
      (((blen - BLOCKSIZE_BYTES) / (4 * BLOCKSIZE_BYTES)) * (4 * BLOCKSIZE_BYTES)) + BLOCKSIZE_BYTES;
    const uint32_t blen_full_8_blocks =
      (((blen - BLOCKSIZE_BYTES) / (8 * BLOCKSIZE_BYTES)) * (8 * BLOCKSIZE_BYTES)) + BLOCKSIZE_BYTES;

    // We allocate for the worst case, that's suboptimal but we want to avoid dynamic data allocation and corresponding
    // performance hit.
    uint8_t ALIGN128 buffer[MAX_PERF_TEST_DATA_BLEN] = { 0 };

    // Prepare masks and keys
    uint64_t ALIGN128 help[2] = { 0ULL, 0ULL };
    for (size_t i = 0; i < 8; ++i) {
        help[0] |= (uint64_t)t[i] << (8 * i);
    }
    // Shift left to make space for B and fill in B
    help[0] = (help[0] << 4) | (0x1 & 0x0F);
    for (size_t i = 0; i < 8; ++i) {
        help[1] |= (uint64_t)t[8 + i] << (8 * i);
    }
    help[1] = help[1] << 4;
    // Move 4 MSB of t[7] to the second quadword of tweak
    help[1] |= ((t[7]) & 0xF0) >> 4;
    __m128i mask1 = _mm_loadu_si128((__m128i*)help);
    help[0] &= ~0x0FULL;
    help[0] |= 0x2;
    __m128i mask2 = _mm_loadu_si128((__m128i*)help);

    mask1 = _mm_xor_si128(mask1, ((__m128i*)k)[0]);
    mask2 = _mm_xor_si128(mask2, ((__m128i*)k)[0]);
    for (uint32_t j = 1; j < 10; j++) {
        mask1 = _mm_aesenc_si128(mask1, ((__m128i*)k)[j]);
        mask2 = _mm_aesenc_si128(mask2, ((__m128i*)k)[j]);
    }
    mask1 = _mm_aesenclast_si128(mask1, ((__m128i*)k)[10]);
    mask2 = _mm_aesenclast_si128(mask2, ((__m128i*)k)[10]);

    uint64_t ALIGN128 bmask2[2];
    _mm_storeu_si128((__m128i*)(bmask2), mask2);

    __m128i hk = _mm_loadu_si128((__m128i*)(k + ((176))));
    __m128i hk1;
    __m128i hk2;
    __m128i hk3;
    if (blen_full_4_blocks > 16) {
        hk1 = _mm_loadu_si128((__m128i*)(k + (176) + POLYVAL_KEYSIZE_BYTES));
        hk2 = _mm_loadu_si128((__m128i*)(k + (176) + (2 * POLYVAL_KEYSIZE_BYTES)));
        hk3 = _mm_loadu_si128((__m128i*)(k + (176) + (3 * POLYVAL_KEYSIZE_BYTES)));
    }

    __m128i hval = _mm_set1_epi16(0);
    for (uint32_t i = BLOCKSIZE_BYTES; i < blen_full_4_blocks; i += (4 * BLOCKSIZE_BYTES)) {
        // prepare masks second PRF
        memcpy((buffer + i - BLOCKSIZE_BYTES), bmask2, BLOCKSIZE_BYTES);
        times_2(bmask2);
        memcpy((buffer + i), bmask2, BLOCKSIZE_BYTES);
        times_2(bmask2);
        memcpy((buffer + i + BLOCKSIZE_BYTES), bmask2, BLOCKSIZE_BYTES);
        times_2(bmask2);
        memcpy((buffer + i + (2 * BLOCKSIZE_BYTES)), bmask2, BLOCKSIZE_BYTES);
        times_2(bmask2);

        // Load state
        __m128i state1 = _mm_loadu_si128((__m128i*)(m + i));
        __m128i state2 = _mm_loadu_si128((__m128i*)(m + i + BLOCKSIZE_BYTES));
        __m128i state3 = _mm_loadu_si128((__m128i*)(m + i + (2 * BLOCKSIZE_BYTES)));
        __m128i state4 = _mm_loadu_si128((__m128i*)(m + i + (3 * BLOCKSIZE_BYTES)));

        // First universal hash
        polyval_x4(&hval, state1, state2, state3, state4, hk, hk1, hk2, hk3);

        // While these probably will be reused very soon, we go for additional assurance and zeroize anyway
        zeroize_secret(&state1, sizeof(state1));
        zeroize_secret(&state2, sizeof(state2));
        zeroize_secret(&state3, sizeof(state3));
        zeroize_secret(&state4, sizeof(state4));
    }
    for (uint32_t i = blen_full_4_blocks; i < blen_full_blocks; i += BLOCKSIZE_BYTES) {
        // Prepare masks for the second PRF
        memcpy((buffer + i - BLOCKSIZE_BYTES), bmask2, BLOCKSIZE_BYTES);
        times_2(bmask2);
        // Load state
        __m128i state = _mm_loadu_si128((__m128i*)(m + i));

        // First universal hash
        hval = _mm_xor_si128(hval, state);
        hval = polyval_dot(hval, hk);

        zeroize_secret(&state, sizeof(state));
    }
    if (blen_full_blocks != blen) {

        // Load state
        uint8_t ALIGN128 one_block_buffer[BLOCKSIZE_BYTES] = { 0 };
        uint32_t j = 0;
        for (uint32_t i = blen_full_blocks; i < blen; i++) {
            one_block_buffer[j++] = m[i];
        }
        __m128i state = _mm_loadu_si128((__m128i*)one_block_buffer);

        // Prepare masks for the second PRF
        memcpy((buffer + blen_full_blocks - BLOCKSIZE_BYTES), bmask2, BLOCKSIZE_BYTES);
        // first universal hash
        hval = _mm_xor_si128(hval, state);
        hval = polyval_dot(hval, hk);

        zeroize_secret(one_block_buffer, sizeof(one_block_buffer));
        zeroize_secret(&state, sizeof(state));
    }

    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10;

    k0 = _mm_loadu_si128(((__m128i*)k) + 0);
    k1 = _mm_loadu_si128(((__m128i*)k) + 1);
    k2 = _mm_loadu_si128(((__m128i*)k) + 2);
    k3 = _mm_loadu_si128(((__m128i*)k) + 3);
    k4 = _mm_loadu_si128(((__m128i*)k) + 4);
    k5 = _mm_loadu_si128(((__m128i*)k) + 5);
    k6 = _mm_loadu_si128(((__m128i*)k) + 6);
    k7 = _mm_loadu_si128(((__m128i*)k) + 7);
    k8 = _mm_loadu_si128(((__m128i*)k) + 8);
    k9 = _mm_loadu_si128(((__m128i*)k) + 9);
    k10 = _mm_loadu_si128(((__m128i*)k) + 10);

    // Finalize the universal hash
    size_t hlen_bits = (blen - BLOCKSIZE_BYTES) * BITS_IN_BYTE;
    uint8_t hlen[BLOCKSIZE_BYTES] = { 0 };
    memcpy(hlen, &hlen_bits, sizeof(hlen_bits));
    hval = _mm_xor_si128(_mm_loadu_si128((__m128i*)hlen), hval);
    hval = polyval_dot(hval, hk);

    hval = _mm_xor_si128(hval, ((__m128i*)m)[0]);
    _mm_storeu_si128((__m128i*)c, hval);

    // First PRF
    mask1 = _mm_xor_si128(hval, mask1);
    mask1 = _mm_xor_si128(mask1, k0);
    mask1 = _mm_aesenc_si128(mask1, k1);
    mask1 = _mm_aesenc_si128(mask1, k2);
    mask1 = _mm_aesenc_si128(mask1, k3);
    mask1 = _mm_aesenc_si128(mask1, k4);
    mask1 = _mm_aesenc_si128(mask1, k5);
    mask1 = _mm_aesenc_si128(mask1, k6);
    mask1 = _mm_aesenc_si128(mask1, k7);
    mask1 = _mm_aesenc_si128(mask1, k8);
    mask1 = _mm_aesenc_si128(mask1, k9);
    mask1 = _mm_aesenclast_si128(mask1, k10);

    hval = _mm_loadu_si128((__m128i*)(m + blen - BLOCKSIZE_BYTES));
    hval = _mm_xor_si128(hval, mask1);
    _mm_storeu_si128((__m128i*)(c + blen - BLOCKSIZE_BYTES), hval);

    // Second PRF
    __m128i input = hval;
    hval = _mm_xor_si128(hval, hval);
    for (uint32_t i = 0; i < blen_full_8_blocks - BLOCKSIZE_BYTES; i += (8 * BLOCKSIZE_BYTES)) {
        // Load state
        __m128i state1, state2, state3, state4, state5, state6, state7, state8;
        __m128i wmask1, wmask2, wmask3, wmask4, wmask5, wmask6, wmask7, wmask8;
        if (i != 0) {
            state1 = _mm_loadu_si128((__m128i*)(m + i));
        } else {
            state1 = _mm_loadu_si128((__m128i*)(c));
        }

        state2 = _mm_loadu_si128((__m128i*)(m + i + BLOCKSIZE_BYTES));
        state3 = _mm_loadu_si128((__m128i*)(m + i + (2 * BLOCKSIZE_BYTES)));
        state4 = _mm_loadu_si128((__m128i*)(m + i + (3 * BLOCKSIZE_BYTES)));

        // Prepare masks
        wmask1 = _mm_loadu_si128((__m128i*)(buffer + i));
        wmask2 = _mm_loadu_si128((__m128i*)(buffer + i + BLOCKSIZE_BYTES));
        wmask3 = _mm_loadu_si128((__m128i*)(buffer + i + (2 * BLOCKSIZE_BYTES)));
        wmask4 = _mm_loadu_si128((__m128i*)(buffer + i + (3 * BLOCKSIZE_BYTES)));
        wmask1 = _mm_xor_si128(wmask1, input);
        wmask2 = _mm_xor_si128(wmask2, input);
        wmask3 = _mm_xor_si128(wmask3, input);
        wmask4 = _mm_xor_si128(wmask4, input);

        wmask1 = _mm_xor_si128(wmask1, ((__m128i*)k)[0]);
        wmask2 = _mm_xor_si128(wmask2, ((__m128i*)k)[0]);
        wmask3 = _mm_xor_si128(wmask3, ((__m128i*)k)[0]);
        wmask4 = _mm_xor_si128(wmask4, ((__m128i*)k)[0]);
        for (uint32_t j = 1; j < 10; j++) {
            wmask1 = _mm_aesenc_si128(wmask1, ((__m128i*)k)[j]);
            wmask2 = _mm_aesenc_si128(wmask2, ((__m128i*)k)[j]);
            wmask3 = _mm_aesenc_si128(wmask3, ((__m128i*)k)[j]);
            wmask4 = _mm_aesenc_si128(wmask4, ((__m128i*)k)[j]);
        }
        wmask1 = _mm_aesenclast_si128(wmask1, ((__m128i*)k)[10]);
        wmask2 = _mm_aesenclast_si128(wmask2, ((__m128i*)k)[10]);
        wmask3 = _mm_aesenclast_si128(wmask3, ((__m128i*)k)[10]);
        wmask4 = _mm_aesenclast_si128(wmask4, ((__m128i*)k)[10]);

        wmask1 = _mm_xor_si128(wmask1, state1);
        wmask2 = _mm_xor_si128(wmask2, state2);
        wmask3 = _mm_xor_si128(wmask3, state3);
        wmask4 = _mm_xor_si128(wmask4, state4);

        _mm_storeu_si128((__m128i*)(c + i), wmask1);
        _mm_storeu_si128((__m128i*)(c + i + BLOCKSIZE_BYTES), wmask2);
        _mm_storeu_si128((__m128i*)(c + i + (2 * BLOCKSIZE_BYTES)), wmask3);
        _mm_storeu_si128((__m128i*)(c + i + (3 * BLOCKSIZE_BYTES)), wmask4);
        // Second universal hash
        polyval_x4(&hval, wmask1, wmask2, wmask3, wmask4, hk, hk1, hk2, hk3);

        state5 = _mm_loadu_si128((__m128i*)(m + i + (4 * BLOCKSIZE_BYTES)));
        state6 = _mm_loadu_si128((__m128i*)(m + i + (5 * BLOCKSIZE_BYTES)));
        state7 = _mm_loadu_si128((__m128i*)(m + i + (6 * BLOCKSIZE_BYTES)));
        state8 = _mm_loadu_si128((__m128i*)(m + i + (7 * BLOCKSIZE_BYTES)));

        // Prepare masks
        wmask5 = _mm_loadu_si128((__m128i*)(buffer + i + (4 * BLOCKSIZE_BYTES)));
        wmask6 = _mm_loadu_si128((__m128i*)(buffer + i + (5 * BLOCKSIZE_BYTES)));
        wmask7 = _mm_loadu_si128((__m128i*)(buffer + i + (6 * BLOCKSIZE_BYTES)));
        wmask8 = _mm_loadu_si128((__m128i*)(buffer + i + (7 * BLOCKSIZE_BYTES)));
        wmask5 = _mm_xor_si128(wmask5, input);
        wmask6 = _mm_xor_si128(wmask6, input);
        wmask7 = _mm_xor_si128(wmask7, input);
        wmask8 = _mm_xor_si128(wmask8, input);

        wmask5 = _mm_xor_si128(wmask5, ((__m128i*)k)[0]);
        wmask6 = _mm_xor_si128(wmask6, ((__m128i*)k)[0]);
        wmask7 = _mm_xor_si128(wmask7, ((__m128i*)k)[0]);
        wmask8 = _mm_xor_si128(wmask8, ((__m128i*)k)[0]);
        for (uint32_t j = 1; j < 10; j++) {
            wmask5 = _mm_aesenc_si128(wmask5, ((__m128i*)k)[j]);
            wmask6 = _mm_aesenc_si128(wmask6, ((__m128i*)k)[j]);
            wmask7 = _mm_aesenc_si128(wmask7, ((__m128i*)k)[j]);
            wmask8 = _mm_aesenc_si128(wmask8, ((__m128i*)k)[j]);
        }
        wmask5 = _mm_aesenclast_si128(wmask5, ((__m128i*)k)[10]);
        wmask6 = _mm_aesenclast_si128(wmask6, ((__m128i*)k)[10]);
        wmask7 = _mm_aesenclast_si128(wmask7, ((__m128i*)k)[10]);
        wmask8 = _mm_aesenclast_si128(wmask8, ((__m128i*)k)[10]);

        wmask5 = _mm_xor_si128(wmask5, state5);
        wmask6 = _mm_xor_si128(wmask6, state6);
        wmask7 = _mm_xor_si128(wmask7, state7);
        wmask8 = _mm_xor_si128(wmask8, state8);

        _mm_storeu_si128((__m128i*)(c + i + (4 * BLOCKSIZE_BYTES)), wmask5);
        _mm_storeu_si128((__m128i*)(c + i + (5 * BLOCKSIZE_BYTES)), wmask6);
        _mm_storeu_si128((__m128i*)(c + i + (6 * BLOCKSIZE_BYTES)), wmask7);
        _mm_storeu_si128((__m128i*)(c + i + (7 * BLOCKSIZE_BYTES)), wmask8);
        // Second universal hash
        polyval_x4(&hval, wmask5, wmask6, wmask7, wmask8, hk, hk1, hk2, hk3);

        zeroize_secret(&state1, sizeof(state1));
        zeroize_secret(&state2, sizeof(state2));
        zeroize_secret(&state3, sizeof(state3));
        zeroize_secret(&state4, sizeof(state4));
        zeroize_secret(&state5, sizeof(state5));
        zeroize_secret(&state6, sizeof(state6));
        zeroize_secret(&state7, sizeof(state7));
        zeroize_secret(&state8, sizeof(state8));

        zeroize_secret(&wmask1, sizeof(wmask1));
        zeroize_secret(&wmask2, sizeof(wmask2));
        zeroize_secret(&wmask3, sizeof(wmask3));
        zeroize_secret(&wmask4, sizeof(wmask4));
        zeroize_secret(&wmask5, sizeof(wmask5));
        zeroize_secret(&wmask6, sizeof(wmask6));
        zeroize_secret(&wmask7, sizeof(wmask7));
        zeroize_secret(&wmask8, sizeof(wmask8));
    }
    for (uint32_t i = blen_full_8_blocks - BLOCKSIZE_BYTES; i < blen_full_4_blocks - BLOCKSIZE_BYTES;
         i += (4 * BLOCKSIZE_BYTES)) {
        // Load state
        __m128i state1, state2, state3, state4;
        if (i != 0) {
            state1 = _mm_loadu_si128((__m128i*)(m + i));
        } else {
            state1 = _mm_loadu_si128((__m128i*)(c));
        }

        state2 = _mm_loadu_si128((__m128i*)(m + i + BLOCKSIZE_BYTES));
        state3 = _mm_loadu_si128((__m128i*)(m + i + (2 * BLOCKSIZE_BYTES)));
        state4 = _mm_loadu_si128((__m128i*)(m + i + (3 * BLOCKSIZE_BYTES)));

        // Prepare masks
        __m128i wmask1 = _mm_loadu_si128((__m128i*)(buffer + i));
        __m128i bmask2 = _mm_loadu_si128((__m128i*)(buffer + i + BLOCKSIZE_BYTES));
        __m128i wmask3 = _mm_loadu_si128((__m128i*)(buffer + i + (2 * BLOCKSIZE_BYTES)));
        __m128i wmask4 = _mm_loadu_si128((__m128i*)(buffer + i + (3 * BLOCKSIZE_BYTES)));
        wmask1 = _mm_xor_si128(wmask1, input);
        bmask2 = _mm_xor_si128(bmask2, input);
        wmask3 = _mm_xor_si128(wmask3, input);
        wmask4 = _mm_xor_si128(wmask4, input);

        wmask1 = _mm_xor_si128(wmask1, ((__m128i*)k)[0]);
        bmask2 = _mm_xor_si128(bmask2, ((__m128i*)k)[0]);
        wmask3 = _mm_xor_si128(wmask3, ((__m128i*)k)[0]);
        wmask4 = _mm_xor_si128(wmask4, ((__m128i*)k)[0]);
        for (uint32_t j = 1; j < 10; j++) {
            wmask1 = _mm_aesenc_si128(wmask1, ((__m128i*)k)[j]);
            bmask2 = _mm_aesenc_si128(bmask2, ((__m128i*)k)[j]);
            wmask3 = _mm_aesenc_si128(wmask3, ((__m128i*)k)[j]);
            wmask4 = _mm_aesenc_si128(wmask4, ((__m128i*)k)[j]);
        }
        wmask1 = _mm_aesenclast_si128(wmask1, ((__m128i*)k)[10]);
        bmask2 = _mm_aesenclast_si128(bmask2, ((__m128i*)k)[10]);
        wmask3 = _mm_aesenclast_si128(wmask3, ((__m128i*)k)[10]);
        wmask4 = _mm_aesenclast_si128(wmask4, ((__m128i*)k)[10]);

        wmask1 = _mm_xor_si128(wmask1, state1);
        bmask2 = _mm_xor_si128(bmask2, state2);
        wmask3 = _mm_xor_si128(wmask3, state3);
        wmask4 = _mm_xor_si128(wmask4, state4);

        _mm_storeu_si128((__m128i*)(c + i), wmask1);
        _mm_storeu_si128((__m128i*)(c + i + BLOCKSIZE_BYTES), bmask2);
        _mm_storeu_si128((__m128i*)(c + i + (2 * BLOCKSIZE_BYTES)), wmask3);
        _mm_storeu_si128((__m128i*)(c + i + (3 * BLOCKSIZE_BYTES)), wmask4);
        // Second universal hash
        polyval_x4(&hval, wmask1, bmask2, wmask3, wmask4, hk, hk1, hk2, hk3);

        zeroize_secret(&state1, sizeof(state1));
        zeroize_secret(&state2, sizeof(state2));
        zeroize_secret(&state3, sizeof(state3));
        zeroize_secret(&state4, sizeof(state4));

        zeroize_secret(&wmask1, sizeof(wmask1));
        zeroize_secret(&bmask2, sizeof(bmask2));
        zeroize_secret(&wmask3, sizeof(wmask3));
        zeroize_secret(&wmask4, sizeof(wmask4));
    }
    for (uint32_t i = blen_full_4_blocks - BLOCKSIZE_BYTES; i < blen_full_blocks - BLOCKSIZE_BYTES;
         i += BLOCKSIZE_BYTES) {
        // Load state
        __m128i state;
        if (i != 0) {
            state = _mm_loadu_si128((__m128i*)(m + i));
        } else {
            state = _mm_loadu_si128((__m128i*)(c));
        }

        // Prepare masks
        __m128i wmask1 = _mm_loadu_si128((__m128i*)(buffer + i));
        wmask1 = _mm_xor_si128(wmask1, input);

        wmask1 = _mm_xor_si128(wmask1, ((__m128i*)k)[0]);
        for (uint32_t j = 1; j < 10; j++) {
            wmask1 = _mm_aesenc_si128(wmask1, ((__m128i*)k)[j]);
        }
        wmask1 = _mm_aesenclast_si128(wmask1, ((__m128i*)k)[10]);

        wmask1 = _mm_xor_si128(wmask1, state);

        _mm_storeu_si128((__m128i*)(c + i), wmask1);
        // Second universal hash
        hval = _mm_xor_si128(hval, wmask1);
        hval = polyval_dot(hval, hk);

        zeroize_secret(&state, sizeof(state));
        zeroize_secret(&wmask1, sizeof(wmask1));
    }
    if (blen_full_blocks != blen) {
        // Load state
        __m128i state;

        state = _mm_loadu_si128((__m128i*)(m + blen_full_blocks - BLOCKSIZE_BYTES));

        // Prepare masks
        __m128i wmask1 = _mm_loadu_si128((__m128i*)(buffer + blen_full_blocks - BLOCKSIZE_BYTES));
        wmask1 = _mm_xor_si128(wmask1, input);

        wmask1 = _mm_xor_si128(wmask1, ((__m128i*)k)[0]);
        for (uint32_t j = 1; j < 10; j++) {
            wmask1 = _mm_aesenc_si128(wmask1, ((__m128i*)k)[j]);
        }
        wmask1 = _mm_aesenclast_si128(wmask1, ((__m128i*)k)[10]);

        wmask1 = _mm_xor_si128(wmask1, state);

        uint8_t ALIGN128 one_block_buffer[BLOCKSIZE_BYTES] = { 0 };
        _mm_storeu_si128((__m128i*)one_block_buffer, wmask1);
        uint32_t j = 0;
        for (uint32_t i = blen_full_blocks - BLOCKSIZE_BYTES; i < blen - BLOCKSIZE_BYTES; i++) {
            c[i] = one_block_buffer[j++];
        }

        zeroize_secret(&state, sizeof(state));
        zeroize_secret(&wmask1, sizeof(wmask1));
        zeroize_secret(one_block_buffer, sizeof(one_block_buffer));
    }

    // Second universal hash
    if (blen_full_blocks != blen) {
        uint8_t ALIGN128 one_block_buffer[BLOCKSIZE_BYTES] = { 0 };
        uint32_t j = 0;
        for (uint32_t i = blen_full_blocks - BLOCKSIZE_BYTES; i < blen - BLOCKSIZE_BYTES; i++) {
            one_block_buffer[j++] = c[i];
        }
        __m128i state = _mm_loadu_si128((__m128i*)one_block_buffer);

        // Second universal hash
        hval = _mm_xor_si128(hval, state);
        hval = polyval_dot(hval, hk);

        zeroize_secret(one_block_buffer, sizeof(one_block_buffer));
        zeroize_secret(&state, sizeof(state));
    }

    hval = _mm_xor_si128(_mm_loadu_si128((__m128i*)hlen), hval);
    hval = polyval_dot(hval, hk);

    uint8_t ALIGN128 one_block_buffer[BLOCKSIZE_BYTES];
    _mm_storeu_si128((__m128i*)one_block_buffer, hval);
    for (uint32_t i = 0; i < BLOCKSIZE_BYTES; i++) {
        c[blen - BLOCKSIZE_BYTES + i] ^= one_block_buffer[i];
    }
    zeroize_secret(one_block_buffer, sizeof(one_block_buffer));

    zeroize_secret(buffer, sizeof(buffer));

    zeroize_secret(&mask1, sizeof(mask1));
    zeroize_secret(&mask2, sizeof(mask2));

    zeroize_secret(&bmask2, sizeof(bmask2));

    zeroize_secret(&hk, sizeof(hk));
    zeroize_secret(&hk1, sizeof(hk1));
    zeroize_secret(&hk2, sizeof(hk2));
    zeroize_secret(&hk3, sizeof(hk3));

    zeroize_secret(&hval, sizeof(hval));

    zeroize_secret(&k0, sizeof(k0));
    zeroize_secret(&k1, sizeof(k1));
    zeroize_secret(&k2, sizeof(k2));
    zeroize_secret(&k3, sizeof(k3));
    zeroize_secret(&k4, sizeof(k4));
    zeroize_secret(&k5, sizeof(k5));
    zeroize_secret(&k6, sizeof(k6));
    zeroize_secret(&k7, sizeof(k7));
    zeroize_secret(&k8, sizeof(k8));
    zeroize_secret(&k9, sizeof(k9));
    zeroize_secret(&k10, sizeof(k10));

    zeroize_secret(&input, sizeof(input));

    return 0;
}

/// @brief DDD-AES decryption function core implementation.
/// @param[in] c Ciphertext (input).
/// @param[out] m Plaintext (output). The result of DDD-AES decryption function application to @p c.
/// @param[in] blen Ciphertext length (in bytes).
/// @param[in] k DDD-AES key (expanded form).
/// @param[in] t Tweak.
/// @return 0 on success, error code < 0 on error.
static int decrypt_with_precomputed_aes_key(const uint8_t* const c,
                                            uint8_t* m,
                                            const uint32_t blen,
                                            const uint8_t* const k,
                                            const uint8_t* const t)
{
    uint32_t blen_full_blocks = (blen / BLOCKSIZE_BYTES) * BLOCKSIZE_BYTES;

    // We allocate for the worst case, that's suboptimal but we want to avoid dynamic data allocation and corresponding
    // performance hit.
    uint8_t ALIGN128 buffer[MAX_PERF_TEST_DATA_BLEN] = { 0 };

    // Prepare masks and keys
    uint64_t ALIGN128 help[2] = { 0ULL, 0ULL };
    for (size_t i = 0; i < 8; ++i) {
        help[0] |= (uint64_t)t[i] << (8 * i);
    }
    // Shift left to make space for B and fill in B
    help[0] = (help[0] << 4) | (0x1 & 0x0F);
    for (size_t i = 0; i < 8; ++i) {
        help[1] |= (uint64_t)t[8 + i] << (8 * i);
    }
    help[1] = help[1] << 4;
    // Move 4 MSB of t[7] to the second quadword of tweak
    help[1] |= ((t[7]) & 0xF0) >> 4;
    __m128i mask1 = _mm_loadu_si128((__m128i*)help);
    help[0] &= ~0x0FULL;
    help[0] |= 0x2;
    __m128i mask2 = _mm_loadu_si128((__m128i*)help);

    mask1 = _mm_xor_si128(mask1, ((__m128i*)k)[0]);
    mask2 = _mm_xor_si128(mask2, ((__m128i*)k)[0]);
    for (uint32_t j = 1; j < 10; j++) {
        mask1 = _mm_aesenc_si128(mask1, ((__m128i*)k)[j]);
        mask2 = _mm_aesenc_si128(mask2, ((__m128i*)k)[j]);
    }
    mask1 = _mm_aesenclast_si128(mask1, ((__m128i*)k)[10]);
    mask2 = _mm_aesenclast_si128(mask2, ((__m128i*)k)[10]);

    uint64_t ALIGN128 bmask2[2];
    _mm_storeu_si128((__m128i*)(bmask2), mask2);

    __m128i hk = _mm_loadu_si128((__m128i*)(k + ((176))));

    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10;

    k0 = _mm_loadu_si128(((__m128i*)k) + 0);
    k1 = _mm_loadu_si128(((__m128i*)k) + 1);
    k2 = _mm_loadu_si128(((__m128i*)k) + 2);
    k3 = _mm_loadu_si128(((__m128i*)k) + 3);
    k4 = _mm_loadu_si128(((__m128i*)k) + 4);
    k5 = _mm_loadu_si128(((__m128i*)k) + 5);
    k6 = _mm_loadu_si128(((__m128i*)k) + 6);
    k7 = _mm_loadu_si128(((__m128i*)k) + 7);
    k8 = _mm_loadu_si128(((__m128i*)k) + 8);
    k9 = _mm_loadu_si128(((__m128i*)k) + 9);
    k10 = _mm_loadu_si128(((__m128i*)k) + 10);

    __m128i hval = _mm_set1_epi16(0);
    size_t hlen_bits = (blen - BLOCKSIZE_BYTES) * BITS_IN_BYTE;
    uint8_t hlen[BLOCKSIZE_BYTES] = { 0 };
    memcpy(hlen, &hlen_bits, sizeof(hlen_bits));

    for (uint32_t i = 0; i < blen_full_blocks - BLOCKSIZE_BYTES; i += BLOCKSIZE_BYTES) {
        // Load state
        __m128i state = _mm_loadu_si128((__m128i*)(c + i));

        // Prepare masks for the second PRF
        memcpy((buffer + i), bmask2, BLOCKSIZE_BYTES);
        times_2(bmask2);
        // second universal hash
        hval = _mm_xor_si128(hval, state);
        hval = polyval_dot(hval, hk);
    }
    if (blen_full_blocks != blen) {
        // Load state
        uint8_t ALIGN128 one_block_buffer[BLOCKSIZE_BYTES] = { 0 };
        uint32_t j = 0;
        for (uint32_t i = blen_full_blocks - BLOCKSIZE_BYTES; i < blen - BLOCKSIZE_BYTES; i++) {
            one_block_buffer[j++] = c[i];
        }
        __m128i state = _mm_loadu_si128((__m128i*)one_block_buffer);

        // Prepare masks for the second PRF
        memcpy((buffer + blen_full_blocks - BLOCKSIZE_BYTES), bmask2, BLOCKSIZE_BYTES);
        // second universal hash
        hval = _mm_xor_si128(hval, state);
        hval = polyval_dot(hval, hk);
    }

    // Finalize the second universal hash
    hval = _mm_xor_si128(_mm_loadu_si128((__m128i*)hlen), hval);
    hval = polyval_dot(hval, hk);
    hval = _mm_xor_si128(hval, _mm_loadu_si128((__m128i*)(c + blen - BLOCKSIZE_BYTES)));
    _mm_storeu_si128((__m128i*)(m + blen - BLOCKSIZE_BYTES), hval);

    for (uint32_t i = 0; i < blen_full_blocks - BLOCKSIZE_BYTES; i += BLOCKSIZE_BYTES) {
        // Load state
        __m128i state;
        state = _mm_loadu_si128((__m128i*)(c + i));

        // Prepare masks
        __m128i wmask1 = _mm_loadu_si128((__m128i*)(buffer + i));
        wmask1 = _mm_xor_si128(wmask1, hval);

        wmask1 = _mm_xor_si128(wmask1, k0);
        wmask1 = _mm_aesenc_si128(wmask1, k1);
        wmask1 = _mm_aesenc_si128(wmask1, k2);
        wmask1 = _mm_aesenc_si128(wmask1, k3);
        wmask1 = _mm_aesenc_si128(wmask1, k4);
        wmask1 = _mm_aesenc_si128(wmask1, k5);
        wmask1 = _mm_aesenc_si128(wmask1, k6);
        wmask1 = _mm_aesenc_si128(wmask1, k7);
        wmask1 = _mm_aesenc_si128(wmask1, k8);
        wmask1 = _mm_aesenc_si128(wmask1, k9);
        wmask1 = _mm_aesenclast_si128(wmask1, k10);

        wmask1 = _mm_xor_si128(wmask1, state);

        _mm_storeu_si128((__m128i*)(m + i), wmask1);

        zeroize_secret(&wmask1, sizeof(wmask1));
    }
    if (blen_full_blocks != blen) {
        // Load state
        __m128i state;

        state = _mm_loadu_si128((__m128i*)(c + blen_full_blocks - BLOCKSIZE_BYTES));

        // Prepare masks
        __m128i wmask1 = _mm_loadu_si128((__m128i*)(buffer + blen_full_blocks - BLOCKSIZE_BYTES));
        wmask1 = _mm_xor_si128(wmask1, hval);

        wmask1 = _mm_xor_si128(wmask1, k0);
        wmask1 = _mm_aesenc_si128(wmask1, k1);
        wmask1 = _mm_aesenc_si128(wmask1, k2);
        wmask1 = _mm_aesenc_si128(wmask1, k3);
        wmask1 = _mm_aesenc_si128(wmask1, k4);
        wmask1 = _mm_aesenc_si128(wmask1, k5);
        wmask1 = _mm_aesenc_si128(wmask1, k6);
        wmask1 = _mm_aesenc_si128(wmask1, k7);
        wmask1 = _mm_aesenc_si128(wmask1, k8);
        wmask1 = _mm_aesenc_si128(wmask1, k9);
        wmask1 = _mm_aesenclast_si128(wmask1, k10);

        wmask1 = _mm_xor_si128(wmask1, state);

        uint8_t ALIGN128 one_block_buffer[BLOCKSIZE_BYTES] = { 0 };
        _mm_storeu_si128((__m128i*)one_block_buffer, wmask1);
        uint32_t j = 0;
        for (uint32_t i = blen_full_blocks - BLOCKSIZE_BYTES; i < blen - BLOCKSIZE_BYTES; i++) {
            m[i] = one_block_buffer[j++];
        }

        zeroize_secret(&wmask1, sizeof(wmask1));
        zeroize_secret(one_block_buffer, sizeof(one_block_buffer));
    }

    // First PRF
    hval = _mm_loadu_si128((__m128i*)(m));
    __m128i mask1_1 = _mm_xor_si128(hval, mask1);

    mask1_1 = _mm_xor_si128(mask1_1, k0);
    mask1_1 = _mm_aesenc_si128(mask1_1, k1);
    mask1_1 = _mm_aesenc_si128(mask1_1, k2);
    mask1_1 = _mm_aesenc_si128(mask1_1, k3);
    mask1_1 = _mm_aesenc_si128(mask1_1, k4);
    mask1_1 = _mm_aesenc_si128(mask1_1, k5);
    mask1_1 = _mm_aesenc_si128(mask1_1, k6);
    mask1_1 = _mm_aesenc_si128(mask1_1, k7);
    mask1_1 = _mm_aesenc_si128(mask1_1, k8);
    mask1_1 = _mm_aesenc_si128(mask1_1, k9);
    mask1_1 = _mm_aesenclast_si128(mask1_1, k10);

    hval = _mm_loadu_si128((__m128i*)(m + blen - BLOCKSIZE_BYTES));
    hval = _mm_xor_si128(hval, mask1_1);
    _mm_storeu_si128((__m128i*)(m + blen - BLOCKSIZE_BYTES), hval);

    // First universal hash
    hval = _mm_xor_si128(hval, hval);
    for (uint32_t i = BLOCKSIZE_BYTES; i < blen_full_blocks; i += BLOCKSIZE_BYTES) {
        __m128i state = _mm_loadu_si128((__m128i*)(m + i));
        hval = _mm_xor_si128(hval, state);
        hval = polyval_dot(hval, hk);

        zeroize_secret(&state, sizeof(state));
    }
    if (blen_full_blocks != blen) {
        uint8_t ALIGN128 one_block_buffer[BLOCKSIZE_BYTES] = { 0 };
        uint32_t j = 0;
        for (uint32_t i = blen_full_blocks; i < blen; i++) {
            one_block_buffer[j++] = m[i];
        }
        __m128i state = _mm_loadu_si128((__m128i*)one_block_buffer);

        // First universal hash
        hval = _mm_xor_si128(hval, state);
        hval = polyval_dot(hval, hk);

        zeroize_secret(one_block_buffer, sizeof(one_block_buffer));
        zeroize_secret(&state, sizeof(state));
    }

    hval = _mm_xor_si128(_mm_loadu_si128((__m128i*)hlen), hval);
    hval = polyval_dot(hval, hk);

    uint8_t ALIGN128 one_block_buffer[BLOCKSIZE_BYTES];
    _mm_storeu_si128((__m128i*)one_block_buffer, hval);
    for (uint32_t i = 0; i < BLOCKSIZE_BYTES; i++) {
        m[i] ^= one_block_buffer[i];
    }
    zeroize_secret(one_block_buffer, sizeof(one_block_buffer));

    zeroize_secret(buffer, sizeof(buffer));

    zeroize_secret(&mask1, sizeof(mask1));
    zeroize_secret(&mask2, sizeof(mask2));

    zeroize_secret(&bmask2, sizeof(bmask2));

    zeroize_secret(&hk, sizeof(hk));

    zeroize_secret(&k0, sizeof(k0));
    zeroize_secret(&k1, sizeof(k1));
    zeroize_secret(&k2, sizeof(k2));
    zeroize_secret(&k3, sizeof(k3));
    zeroize_secret(&k4, sizeof(k4));
    zeroize_secret(&k5, sizeof(k5));
    zeroize_secret(&k6, sizeof(k6));
    zeroize_secret(&k7, sizeof(k7));
    zeroize_secret(&k8, sizeof(k8));
    zeroize_secret(&k9, sizeof(k9));
    zeroize_secret(&k10, sizeof(k10));

    zeroize_secret(&hval, sizeof(hval));

    zeroize_secret(&mask1_1, sizeof(mask1_1));

    return 0;
}

int ddd_aes_ref_perf_encrypt(uint8_t* cipher,
                             const uint8_t* const plain,
                             const uint32_t len,
                             const uint8_t* const expanded_key,
                             const uint8_t* const tweak,
                             const uint32_t tweak_len)
{
    // Basic input validation
    if (plain == NULL || cipher == NULL || expanded_key == NULL || tweak == NULL) {
        return -1;
    }

    if (len > MAX_PERF_TEST_DATA_BLEN || len < (2 * BLOCKSIZE_BYTES)) {
        return -1;
    }

    if (tweak_len != TWEAKSIZE_BYTES) {
        return -1;
    }

    return encrypt_with_precomputed_aes_key(plain, cipher, len, expanded_key, tweak);
}

int ddd_aes_ref_perf_decrypt(uint8_t* plain,
                             const uint8_t* const cipher,
                             const uint32_t len,
                             const uint8_t* const expanded_key,
                             const uint8_t* const tweak,
                             const uint32_t tweak_len)
{
    // Basic input validation
    if (plain == NULL || cipher == NULL || expanded_key == NULL || tweak == NULL) {
        return -1;
    }

    if (len > MAX_PERF_TEST_DATA_BLEN || len < (2 * BLOCKSIZE_BYTES)) {
        return -1;
    }

    if (tweak_len != TWEAKSIZE_BYTES) {
        return -1;
    }

    return decrypt_with_precomputed_aes_key(cipher, plain, len, expanded_key, tweak);
}
