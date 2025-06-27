/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#include "aes.h"

/// @brief AES-128 key scheduling helper function that based on the result of aeskeygenassist call in @p temp2
/// @brief and the previous round key in @p temp1 generates the next round key.
static inline __m128i aes128_keygen_step(__m128i temp1, __m128i temp2)
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

void aes_key_sched(uint8_t rnd_keys[RNDKEYSIZE_BYTES], const uint8_t key[KEYSIZE_BYTES])
{
    __m128i temp1, temp2;
    temp1 = _mm_loadu_si128((__m128i*)key);
    // Round key 0
    _mm_storeu_si128((__m128i*)rnd_keys, temp1);
    // Generate round key 1
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x01);
    temp1 = aes128_keygen_step(temp1, temp2);
    _mm_storeu_si128((__m128i*)(rnd_keys + 1 * BLOCKSIZE_BYTES), temp1);
    // Generate round key 2
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x02);
    temp1 = aes128_keygen_step(temp1, temp2);
    _mm_storeu_si128((__m128i*)(rnd_keys + 2 * BLOCKSIZE_BYTES), temp1);
    // Generate round key 3
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x04);
    temp1 = aes128_keygen_step(temp1, temp2);
    _mm_storeu_si128((__m128i*)(rnd_keys + 3 * BLOCKSIZE_BYTES), temp1);
    // generate round key 4
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x08);
    temp1 = aes128_keygen_step(temp1, temp2);
    _mm_storeu_si128((__m128i*)(rnd_keys + 4 * BLOCKSIZE_BYTES), temp1);
    // Generate round key 5
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
    temp1 = aes128_keygen_step(temp1, temp2);
    _mm_storeu_si128((__m128i*)(rnd_keys + 5 * BLOCKSIZE_BYTES), temp1);
    // Generate round key 6
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
    temp1 = aes128_keygen_step(temp1, temp2);
    _mm_storeu_si128((__m128i*)(rnd_keys + 6 * BLOCKSIZE_BYTES), temp1);
    // Generate round key 7
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
    temp1 = aes128_keygen_step(temp1, temp2);
    _mm_storeu_si128((__m128i*)(rnd_keys + 7 * BLOCKSIZE_BYTES), temp1);
    // Generate round key 8
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
    temp1 = aes128_keygen_step(temp1, temp2);
    _mm_storeu_si128((__m128i*)(rnd_keys + 8 * BLOCKSIZE_BYTES), temp1);
    // Generate round key 9
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1B);
    temp1 = aes128_keygen_step(temp1, temp2);
    _mm_storeu_si128((__m128i*)(rnd_keys + 9 * BLOCKSIZE_BYTES), temp1);
    // Generate round key 10
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
    temp1 = aes128_keygen_step(temp1, temp2);
    _mm_storeu_si128((__m128i*)(rnd_keys + 10 * BLOCKSIZE_BYTES), temp1);

    zeroize_secret(&temp1, sizeof(temp1));
    zeroize_secret(&temp2, sizeof(temp2));
}

__m128i aes_enc(const __m128i in, const uint8_t rnd_keys[RNDKEYSIZE_BYTES])
{
    const __m128i* r_keys = (__m128i*)rnd_keys;
    __m128i temp = _mm_xor_si128(in, _mm_load_si128(r_keys));
    temp = _mm_aesenc_si128(temp, _mm_load_si128(r_keys + 1));
    temp = _mm_aesenc_si128(temp, _mm_load_si128(r_keys + 2));
    temp = _mm_aesenc_si128(temp, _mm_load_si128(r_keys + 3));
    temp = _mm_aesenc_si128(temp, _mm_load_si128(r_keys + 4));
    temp = _mm_aesenc_si128(temp, _mm_load_si128(r_keys + 5));
    temp = _mm_aesenc_si128(temp, _mm_load_si128(r_keys + 6));
    temp = _mm_aesenc_si128(temp, _mm_load_si128(r_keys + 7));
    temp = _mm_aesenc_si128(temp, _mm_load_si128(r_keys + 8));
    temp = _mm_aesenc_si128(temp, _mm_load_si128(r_keys + 9));
    temp = _mm_aesenclast_si128(temp, _mm_load_si128(r_keys + 10));
    return temp;
}
