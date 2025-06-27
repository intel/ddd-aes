/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#ifndef AES_H_
#define AES_H_

#include <stdint.h>
#include <stdbool.h>
#include <immintrin.h>

#include "zeroize.h"

#define BLOCKSIZE_BYTES 16 // Size of the AES block in bytes
#define KEYSIZE_BYTES 16   // Size of AES-128 key in bytes
// Total size of round keys material for AES-128 (10 rounds -> 11 round keys)
#define RNDKEYSIZE_BYTES (BLOCKSIZE_BYTES * 11)

/// @brief AES-128 key scheduling algorithm. Produces rounds keys from the input key.
/// @param[out] rnd_keys Output data. Round keys.
/// @param[in] key Input data. Key.
void aes_key_sched(uint8_t rnd_keys[RNDKEYSIZE_BYTES], const uint8_t key[KEYSIZE_BYTES]);

/// @brief AES-128 single block encryption implementation.
/// @param[in] in Input data block contained in XMM register.
/// @param[in] rnd_keys Round keys.
/// @return Encrypted block.
__m128i aes_enc(const __m128i in, const uint8_t rnd_keys[RNDKEYSIZE_BYTES]);

#endif /* AES_H_ */
