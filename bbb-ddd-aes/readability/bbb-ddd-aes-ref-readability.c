/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#include "bbb-ddd-aes-ref-readability.h"

/// @brief BBB-DDD-AES H_L() function implementation.
/// @param[out] out Output data. The result of H_L() evaluation on input data is XORed into this buffer.
/// @param[in] in Input data.
/// @param[in] len Input data length (in bytes).
/// @param[in] key H_L() function key. Precondition: the key is 128-bit-long.
/// @return 0 on success, error code < 0 on error.
int xor_h(uint8_t* out, const uint8_t* const in, const size_t len, const uint8_t* const key)
{
    uint8_t tag[POLYVAL_TAG_LEN_BYTES] = { 0 };

    // How many incoming bytes beyond the whole multiple of a block size we have (may be 0)
    const size_t leftover_bytes = len % POLYVAL_BLOCK_LEN_BYTES;

    // Process the data up to the whole multiple of POLYVAL_BLOCK_LEN_BYTES
    int status = polyval(tag, in, len - leftover_bytes, key, false);
    if (status < 0) {
        printf("ERROR: polyval() failed, status: %d\n", status);
        return status;
    }

    uint8_t tmp_buf[POLYVAL_BLOCK_LEN_BYTES] = { 0 };
    // Create and process a padded extra block if necessary
    if (leftover_bytes != 0) {
        memcpy(tmp_buf, in + len - leftover_bytes, leftover_bytes);
        status = polyval(tag, tmp_buf, sizeof(tmp_buf), key, true);
        // Zeroize the tmp buffer to prepare it for future use
        memset(tmp_buf, 0, sizeof(tmp_buf));
        if (status < 0) {
            printf("ERROR: polyval() failed, status: %d\n", status);
            return status;
        }
    }

    // Create and process the final block with incoming data size in bits stored as block-sized value
    // The spec doesn't define this [yet]. The below uses little-endian.
    const size_t len_bits = len * 8;
    memcpy(tmp_buf, &len_bits, sizeof(len_bits));
    status = polyval(tag, tmp_buf, sizeof(tmp_buf), key, true);
    if (status < 0) {
        printf("ERROR: polyval() failed, status: %d\n", status);
        return status;
    }

    for (size_t i = 0; i < POLYVAL_TAG_LEN_BYTES; ++i) {
        out[i] ^= tag[i];
    }

    zeroize_secret(tag, sizeof(tag));
    zeroize_secret(tmp_buf, sizeof(tmp_buf));

    return 0;
}

/// @brief BBB-DDD-AES F_K() function implementation. XORs to the existing value of @p out the result of the PRF
/// @brief evaluation on @p in.
/// @param[out] out Output data. The result of F_K() evaluation on input data is XORed into this buffer.
/// @param[in] outlen Size of the output in bytes.
/// @param[in] in Input data block.
/// @param[in] key_k 256-bit F_K() function key.
/// @param[in] b Domain separator value B.
/// @param[in] tweak Tweak value W.
void xor_f(uint8_t* out,
           const size_t outlen,
           const uint8_t in[BLOCKSIZE_BYTES],
           const uint8_t* const key_k,
           const uint8_t b,
           const uint8_t tweak[TWEAKSIZE_BYTES])
{
    const size_t num_full_blocks = outlen / BLOCKSIZE_BYTES; // Number of full AES blocks
    const size_t last_block_len = outlen - num_full_blocks * BLOCKSIZE_BYTES;

    // Prepare expanded keys for both halves of the key K = K1||K2
    const uint8_t* k1 = key_k;
    const uint8_t* k2 = key_k + KEYSIZE_BYTES;
    uint8_t rnd_keys_1[RNDKEYSIZE_BYTES];
    uint8_t rnd_keys_2[RNDKEYSIZE_BYTES];
    aes_key_sched(rnd_keys_1, k1);
    aes_key_sched(rnd_keys_2, k2);

    // Prepare the W||B value:
    uint64_t w_b[2] = { 0ULL, 0ULL };
    // Load tweak value
    for (size_t i = 0; i < 8; ++i) {
        w_b[0] |= (uint64_t)tweak[i] << (8 * i);
    }
    // Shift left to make space for B and fill in B
    w_b[0] = (w_b[0] << 4) | (b & 0x0F);
    for (size_t i = 0; i < 4; ++i) {
        w_b[1] |= (uint64_t)tweak[8 + i] << (8 * i);
    }
    w_b[1] = w_b[1] << 4;
    // Move 4 MSB of tweak[7] to the second quadword of tweak
    w_b[1] |= ((tweak[7]) & 0xF0) >> 4;

    // We currently assume |c| = 0 and use 28 bits for the counter j, so we can encrypt up to 2**28 - 1 blocks
    const uint64_t counter_one[2] = { 0ULL, 1ULL << 36 };
    __m128i inc_j = _mm_loadu_si128((__m128i*)counter_one); // Counter j will be incremented by this

    __m128i mask = _mm_loadu_si128((__m128i*)w_b);
    __m128i s_0 = aes_enc(mask, rnd_keys_2);
    __m128i i = _mm_loadu_si128((__m128i*)in);

    __m128i e_0 = aes_enc(_mm_xor_si128(i, s_0), rnd_keys_1);
    __m128i s_j = s_0;
    __m128i e_j;
    __m128i z_j;
    uint8_t* memory_block = out;
    for (size_t idx = 0; idx < num_full_blocks; ++idx) {
        mask = _mm_add_epi64(mask, inc_j);
        s_j = aes_enc(mask, rnd_keys_2);
        e_j = aes_enc(_mm_xor_si128(i, s_j), rnd_keys_1);
        z_j = _mm_xor_si128(e_0, e_j);
        _mm_storeu_si128((__m128i*)memory_block, _mm_xor_si128(z_j, _mm_loadu_si128((__m128i*)memory_block)));
        memory_block += BLOCKSIZE_BYTES;
    }

    // Handle the possible last incomplete block
    if (last_block_len != 0) {
        uint8_t last_z[BLOCKSIZE_BYTES];
        mask = _mm_add_epi64(mask, inc_j);
        s_j = aes_enc(mask, rnd_keys_2);
        e_j = aes_enc(_mm_xor_si128(i, s_j), rnd_keys_1);
        z_j = _mm_xor_si128(e_0, e_j);
        _mm_storeu_si128((__m128i*)last_z, z_j);
        for (size_t i = 0; i < last_block_len; ++i) {
            *memory_block++ ^= last_z[i];
        }

        zeroize_secret(last_z, sizeof(last_z));
    }

    zeroize_secret(rnd_keys_1, sizeof(rnd_keys_1));
    zeroize_secret(rnd_keys_2, sizeof(rnd_keys_2));

    zeroize_secret(&s_0, sizeof(s_0));
    zeroize_secret(&i, sizeof(i));
    zeroize_secret(&e_0, sizeof(e_0));
    zeroize_secret(&s_j, sizeof(s_j));
    zeroize_secret(&e_j, sizeof(e_j));
    zeroize_secret(&z_j, sizeof(z_j));
}

int bbb_ddd_aes_ref_read_encrypt(uint8_t* cipher,
                                 const uint8_t* const plain,
                                 const size_t len,
                                 const uint8_t* const key_k,
                                 const uint8_t* const key_l,
                                 const uint8_t* const tweak,
                                 const size_t tweak_len)
{
    // Basic input validation
    if (plain == NULL || cipher == NULL || key_k == NULL || key_l == NULL || tweak == NULL) {
        return -1;
    }

    // Plaintext length must be at least two blocks and at most the number of blocks supported by the scheme.
    if (len > (MAXENCRYPTBLOCKS - 1) * (size_t)BLOCKSIZE_BYTES || len < 2 * BLOCKSIZE_BYTES) {
        return -1;
    }

    // Tweak length must be TWEAKSIZE
    if (tweak_len != TWEAKSIZE_BYTES) {
        return -1;
    }

    memcpy(cipher, plain, len);

    uint8_t* t = cipher;
    uint8_t* u = cipher + BLOCKSIZE_BYTES;
    uint8_t* v = cipher + len - BLOCKSIZE_BYTES;

    int status = xor_h(t, u, len - BLOCKSIZE_BYTES, key_l);
    if (status < 0) {
        printf("ERROR: xor_h() failed, status: %d\n", status);
        return status;
    }

    xor_f(v, BLOCKSIZE_BYTES, t, key_k, 0x1, tweak);
    xor_f(t, len - BLOCKSIZE_BYTES, v, key_k, 0x2, tweak);

    status = xor_h(v, t, len - BLOCKSIZE_BYTES, key_l);
    if (status < 0) {
        printf("ERROR: xor_h() failed, status: %d\n", status);
        return status;
    }

    return 0;
}

int bbb_ddd_aes_ref_read_decrypt(uint8_t* plain,
                                 const uint8_t* const cipher,
                                 const size_t len,
                                 const uint8_t* const key_k,
                                 const uint8_t* const key_l,
                                 const uint8_t* const tweak,
                                 const size_t tweak_len)
{
    // Basic input validation
    if (plain == NULL || cipher == NULL || key_k == NULL || key_l == NULL || tweak == NULL) {
        return -1;
    }

    // Ciphertext length must be at least two blocks and at most the number of blocks supported by the scheme.
    if (len > (MAXENCRYPTBLOCKS - 1) * (size_t)BLOCKSIZE_BYTES || len < 2 * BLOCKSIZE_BYTES) {
        return -1;
    }

    // Tweak length must be TWEAKSIZE
    if (tweak_len != TWEAKSIZE_BYTES) {
        return -1;
    }

    memcpy(plain, cipher, len);

    uint8_t* t = plain;
    uint8_t* u = plain + BLOCKSIZE_BYTES;
    uint8_t* v = plain + len - BLOCKSIZE_BYTES;

    int status = xor_h(v, t, len - BLOCKSIZE_BYTES, key_l);
    if (status < 0) {
        printf("ERROR: xor_h() failed, status: %d\n", status);
        return status;
    }

    xor_f(t, len - BLOCKSIZE_BYTES, v, key_k, 0x2, tweak);
    xor_f(v, BLOCKSIZE_BYTES, t, key_k, 0x1, tweak);

    status = xor_h(t, u, len - BLOCKSIZE_BYTES, key_l);
    if (status < 0) {
        printf("ERROR: xor_h() failed, status: %d\n", status);
        return status;
    }

    return 0;
}
