/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "polyval.h"
#include "aes.h"
#include "bbb-ddd-aes-ref-readability.h"

#define MAXTESTSIZE 24 * 16
#define TESTINCREMENT 1

/*********************** Generate Testvectors ********************************************/

/// @brief Utility function. Prints incoming array of uint8_t as a line of hex values with some text embellishments.
/// @param[in] name Text label for the array.
/// @param[in] arr Array to print.
/// @param[in] arr_len Array length (in bytes).
static void print_array_hex(const char* name, const uint8_t* arr, const size_t arr_len)
{
    printf("%s[%zu]=", name, arr_len);
    for (size_t i = 0; i < arr_len; ++i) {
        printf("%02x", arr[i]);
    }
    printf("\n");
}

/// End of test utilities

int main(int argc, char* argv[])
{
    // We don't use these, make this explicit
    (void)argc;
    (void)argv;

    uint8_t plaintext[MAXTESTSIZE] = { 0 };
    uint8_t ciphertext[MAXTESTSIZE];
    uint8_t decrypted[MAXTESTSIZE];
    uint8_t tweak[TWEAKSIZE_BYTES] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    uint8_t key_k[2 * KEYSIZE_BYTES] = { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0,
                                         0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x0F, 0x1F, 0x2F, 0x3F, 0x4F, 0x5F,
                                         0x6F, 0x7F, 0x8F, 0x9F, 0xAF, 0xBF, 0xCF, 0xDF, 0xEF, 0xFF };
    uint8_t key_l[KEYSIZE_BYTES] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                     0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    for (uint32_t i = 2 * BLOCKSIZE_BYTES; i <= MAXTESTSIZE; i += TESTINCREMENT) {

        for (uint32_t j = 0; j < i; j++) {
            plaintext[j] += (uint8_t)j;
        }

        int status = bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, i, key_k, key_l, tweak, TWEAKSIZE_BYTES);
        if (status < 0) {
            printf("ERROR: bbb_ddd_aes_ref_read_encrypt() failed, status: %d\n", status);
            return 1;
        }

        status = bbb_ddd_aes_ref_read_decrypt(decrypted, ciphertext, i, key_k, key_l, tweak, TWEAKSIZE_BYTES);
        if (status < 0) {
            printf("ERROR: bbb_ddd_aes_ref_read_decrypt() failed, status: %d\n", status);
            return 1;
        }

        print_array_hex("PT", plaintext, i);
        print_array_hex("CT", ciphertext, i);
        print_array_hex("DT", decrypted, i);

        if (memcmp(plaintext, decrypted, i) == 0) {
            printf("Test Passed\n");
        } else {
            printf("Test Failed\n");
            return 1;
        }
    }

    return 0;
}
