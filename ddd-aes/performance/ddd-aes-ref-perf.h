/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#ifndef DDD_AES_REF_PERF_H_
#define DDD_AES_REF_PERF_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wmmintrin.h>
#include <immintrin.h>
#include <smmintrin.h>

#include "zeroize.h"

// Tweak size in bytes
#define TWEAKSIZE_BYTES 16

#define CRYPTO_KEYBYTES 48
#define CRYPTO_EXPANDED_KEYBYTES 240

#define BITS_IN_BYTE 8

#define BLOCKSIZE_BYTES 16       // Size of the AES and POLYVAL block in bytes
#define AES_KEYSIZE_BYTES 16     // Size of AES-128 key in bytes
#define POLYVAL_KEYSIZE_BYTES 16 // Size of the POLYVAL key in bytes

// Maximum test input data size (in bytes) we expect.
// Limited to avoid memory management, that is not the point of this implementation.
#define MAX_PERF_TEST_DATA_BLEN (1 << 11)

#ifdef _WIN32
#define ALIGN128 _Alignas(128)
#else
// For simplicity we assume that anything that's not MSVC is GCC or compatible
#define ALIGN128 __attribute__((aligned(128)))
#endif

#ifdef _WIN32
#define FORCE_INLINE __forceinline
#else
// For simplicity we assume that anything that's not MSVC is GCC or compatible
#define FORCE_INLINE __attribute__((__always_inline__))
#endif

/// @brief DDD-AES encryption function implementation.
/// @param[out] cipher Ciphertext (output). The result of DDD-AES encryption function application to @p plain.
/// @param[in] plain Plaintext (input).
/// @param[in] len Plaintext length (in bytes).
/// @param[in] expanded_key DDD-AES key (expanded form).
/// @param[in] tweak Tweak.
/// @param[in] tweak_len Tweak length (in bytes).
/// @return 0 on success, error code < 0 on error.
int ddd_aes_ref_perf_encrypt(uint8_t* cipher,
                             const uint8_t* const plain,
                             const uint32_t len,
                             const uint8_t* const expanded_key,
                             const uint8_t* const tweak,
                             const uint32_t tweak_len);

/// @brief DDD-AES decryption function implementation.
/// @param[out] plain Plaintext (output). The result of DDD-AES decryption function application to @p cipher.
/// @param[in] cipher Ciphertext (input).
/// @param[in] len Ciphertext length (in bytes).
/// @param[in] expanded_key DDD-AES key (expanded form).
/// @param[in] tweak Tweak.
/// @param[in] tweak_len Tweak length (in bytes).
/// @return 0 on success, error code < 0 on error.
int ddd_aes_ref_perf_decrypt(uint8_t* plain,
                             const uint8_t* const cipher,
                             const uint32_t len,
                             const uint8_t* const expanded_key,
                             const uint8_t* const tweak,
                             const uint32_t tweak_len);

/// @brief Helper function. Precomputes AES and POLYVAL keys based on the incoming DDD-AES key.
/// @param[in] key DDD-AES key (input).
/// @param[out] expanded_key Precomputed output key (expanded form).
void precompute_key(const uint8_t* const key, uint8_t* expanded_key);

#endif /* DDD_AES_REF_PERF_H_ */
