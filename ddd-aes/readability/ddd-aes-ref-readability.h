/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#ifndef DDD_AES_REF_READABILITY_H_
#define DDD_AES_REF_READABILITY_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "polyval.h"
#include "aes.h"
#include "zeroize.h"

// In the default version, we assume |c|=0 and use 28 bits for the counter j, so we can encrypt up to 2**28 - 1 blocks
#define MAXENCRYPTBLOCKS (1 << 28)

// Tweak size in bytes
#define TWEAKSIZE_BYTES 16

#ifdef _WIN32
#define ALIGN128 _Alignas(128)
#else
// For simplicity we assume that anything that's not MSVC is GCC or compatible
#define ALIGN128 __attribute__((aligned(128)))
#endif

#ifdef TEST_INTERNAL_FN_ACCESS
int xor_h(uint8_t* out, const uint8_t* const in, const size_t len, const uint8_t* const key);
#endif

/// @brief DDD-AES encryption implementation.
/// @param[out] cipher Ciphertext (output). The result of DDD-AES encryption function application to @p plain.
/// @param[in] plain Plaintext (input).
/// @param[in] len Plaintext length (in bytes).
/// @param[in] key_k F_K() function key. Precondition: the key is 128-bit-long.
/// @param[in] key_l H_L() function key. Precondition: the key is 128-bit-long.
/// @param[in] tweak Tweak.
/// @param[in] tweak_len Tweak length (in bytes).
/// @return 0 on success, error code < 0 on error.
int ddd_aes_ref_read_encrypt(uint8_t* cipher,
                             const uint8_t* const plain,
                             const size_t len,
                             const uint8_t* const key_k,
                             const uint8_t* const key_l,
                             const uint8_t* const tweak,
                             const size_t tweak_len);

/// @brief DDD-AES decryption implementation.
/// @param[out] plain Plaintext (output). The result of DDD-AES decryption function application to @p cipher.
/// @param[in] cipher Ciphertext (input).
/// @param[in] len Ciphertext length (in bytes).
/// @param[in] key_k F_K() function key. Precondition: the key is 128-bit-long.
/// @param[in] key_l H_L() function key. Precondition: the key is 128-bit-long.
/// @param[in] tweak Tweak.
/// @param[in] tweak_len Tweak length (in bytes).
/// @return 0 on success, error code < 0 on error.
int ddd_aes_ref_read_decrypt(uint8_t* plain,
                             const uint8_t* const cipher,
                             const size_t len,
                             const uint8_t* const key_k,
                             const uint8_t* const key_l,
                             const uint8_t* const tweak,
                             const size_t tweak_len);

#endif /* DDD_AES_REF_READABILITY_H_ */
