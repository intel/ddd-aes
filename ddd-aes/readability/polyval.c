/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#include "polyval.h"

/// @brief Calculate POLYVAL dot() operation result for two values.
/// @param[in] a Left operand.
/// @param[in] b Right operand.
/// @return dot(a, b) = (a * b * x^-128) mod (x^128 + x^127 + x^126 + x^121 + 1) (see RFC 8452).
static inline __m128i polyval_dot(const __m128i a, const __m128i b)
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

int polyval(uint8_t tag[POLYVAL_TAG_LEN_BYTES],
            const uint8_t* msg,
            const size_t msg_len,
            const uint8_t key[POLYVAL_KEY_LEN_BYTES],
            const bool update)
{
    if ( // Only full blocks (per Polyval definition)
      msg_len % POLYVAL_BLOCK_LEN_BYTES != 0
      // ...and with valid message length
      || msg_len == 0) {
        return -1;
    }

    __m128i S;
    if (update) {
        S = _mm_loadu_si128((__m128i*)tag);
    } else {
        S = _mm_setzero_si128();
    }

    __m128i H = _mm_loadu_si128((__m128i*)key);
    for (size_t i = 0; i < msg_len; i += POLYVAL_BLOCK_LEN_BYTES) {
        // Load next chunk (X_j in RFC 8452) from the message
        __m128i buf = _mm_loadu_si128((__m128i*)(msg + i));
        // S_{j-1} + X_j
        buf = _mm_xor_si128(S, buf);
        // S_j = dot(S_{j-1} + X_j, H)
        S = polyval_dot(buf, H);

        zeroize_secret(&buf, sizeof(buf));
    }
    _mm_storeu_si128((__m128i*)tag, S);

    zeroize_secret(&S, sizeof(S));
    zeroize_secret(&H, sizeof(H));

    return 0;
}
