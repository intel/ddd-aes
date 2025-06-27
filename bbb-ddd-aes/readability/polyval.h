/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#ifndef POLYVAL_H_
#define POLYVAL_H_

#include <stdint.h>
#include <stdbool.h>
#include <immintrin.h>

#include "zeroize.h"

#define POLYVAL_TAG_LEN_BYTES 16
#define POLYVAL_BLOCK_LEN_BYTES 16
#define POLYVAL_KEY_LEN_BYTES 16

/// @brief Calculate POLYVAL tag for a message.
/// @param[in,out] tag Calculated POLYVAL tag of POLYVAL_TAG_LEN_BYTES.
/// @param[in] msg Message.
/// @param[in] msg_len Message length (in bytes). Precondition: must be a whole multiple of POLYVAL_BLOCK_LEN_BYTES.
/// @param[in] key POLYVAL key (H).
/// @param[in] update If true runs the function in "update" mode, where the @p tag is expected to be non-empty and the
/// data is supposed to be a continuation of a stream.
/// @return 0 on success, error code < 0 on error.
int polyval(uint8_t tag[POLYVAL_TAG_LEN_BYTES],
            const uint8_t* msg,
            const size_t msg_len,
            const uint8_t key[POLYVAL_KEY_LEN_BYTES],
            const bool update);

#endif /* POLYVAL_H_ */
