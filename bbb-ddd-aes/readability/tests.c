/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bbb-ddd-aes-ref-readability.h"

/*********************** TESTS ********************************************/

// clang-format off: these are small aux macros and standard formatting just makes them ugly
/// Test utilities

#define TEST_START { printf("*** Starting %s\n", __func__); }
#define TEST_PASSED { printf("*** %s PASSED\n\n", __func__); }
#define TEST_FAILED { printf("*** %s FAILED\n\n", __func__); }
// clang-format on

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

/// @brief Utility function. Prints incoming array of uint8_t as a line of char values with some text embellishments.
/// @param[in] name Text label for the array.
/// @param[in] arr Array to print.
/// @param[in] arr_len Array length (in bytes).
static void print_array_char(const char* name, const uint8_t* arr, const size_t arr_len)
{
    printf("%s[%zu]=", name, arr_len);
    for (size_t i = 0; i < arr_len; ++i) {
        printf("%c", arr[i]);
    }
    printf("\n");
}

/// End of test utilities

/// Full-cycle encryption/decryption tests

static void test_enc_dec_2blocks()
{
    uint8_t plaintext[2 * BLOCKSIZE_BYTES] = "ABCDEFGHIJKLMNOP0123456701234567";
    uint8_t ciphertext[2 * BLOCKSIZE_BYTES];
    uint8_t decrypted[2 * BLOCKSIZE_BYTES];
    uint8_t tweak[TWEAKSIZE_BYTES] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    uint8_t key_k[2 * KEYSIZE_BYTES] = { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0,
                                         0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x0F, 0x1F, 0x2F, 0x3F, 0x4F, 0x5F,
                                         0x6F, 0x7F, 0x8F, 0x9F, 0xAF, 0xBF, 0xCF, 0xDF, 0xEF, 0xFF };
    uint8_t key_l[KEYSIZE_BYTES] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                     0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    TEST_START

    int status =
      bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, 2 * BLOCKSIZE_BYTES, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status < 0) {
        printf("ERROR: bbb_ddd_aes_ref_read_encrypt() failed, status: %d\n", status);
        exit(1);
    }

    status =
      bbb_ddd_aes_ref_read_decrypt(decrypted, ciphertext, 2 * BLOCKSIZE_BYTES, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status < 0) {
        printf("ERROR: bbb_ddd_aes_ref_read_decrypt() failed, status: %d\n", status);
        exit(1);
    }

    if (memcmp(plaintext, decrypted, 2 * BLOCKSIZE_BYTES) != 0) {
        TEST_FAILED
        exit(1);
    }

    TEST_PASSED
}

static void test_enc_dec_3blocks()
{
    uint8_t plaintext[3 * BLOCKSIZE_BYTES] = "ABCDEFGHIJKLMNOPabcdefghijklmnop0123456701234567";
    uint8_t ciphertext[3 * BLOCKSIZE_BYTES];
    uint8_t decrypted[3 * BLOCKSIZE_BYTES];
    uint8_t tweak[TWEAKSIZE_BYTES] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    uint8_t key_k[2 * KEYSIZE_BYTES] = { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0,
                                         0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x0F, 0x1F, 0x2F, 0x3F, 0x4F, 0x5F,
                                         0x6F, 0x7F, 0x8F, 0x9F, 0xAF, 0xBF, 0xCF, 0xDF, 0xEF, 0xFF };
    uint8_t key_l[KEYSIZE_BYTES] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                     0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    TEST_START

    int status =
      bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, 3 * BLOCKSIZE_BYTES, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status < 0) {
        printf("ERROR: bbb_ddd_aes_ref_read_encrypt() failed, status: %d\n", status);
        exit(1);
    }

    status =
      bbb_ddd_aes_ref_read_decrypt(decrypted, ciphertext, 3 * BLOCKSIZE_BYTES, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status < 0) {
        printf("ERROR: bbb_ddd_aes_ref_read_decrypt() failed, status: %d\n", status);
        exit(1);
    }

    if (memcmp(plaintext, decrypted, 3 * BLOCKSIZE_BYTES) != 0) {
        TEST_FAILED
        exit(1);
    }

    TEST_PASSED
}

static void test_enc_dec_2blocks_andone()
{
    uint8_t plaintext[2 * BLOCKSIZE_BYTES + 1] = "ABCDEFGHIJKLMNOPX0123456701234567";
    uint8_t ciphertext[2 * BLOCKSIZE_BYTES + 1];
    uint8_t decrypted[2 * BLOCKSIZE_BYTES + 1];
    uint8_t tweak[TWEAKSIZE_BYTES] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    uint8_t key_k[2 * KEYSIZE_BYTES] = { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0,
                                         0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x0F, 0x1F, 0x2F, 0x3F, 0x4F, 0x5F,
                                         0x6F, 0x7F, 0x8F, 0x9F, 0xAF, 0xBF, 0xCF, 0xDF, 0xEF, 0xFF };
    uint8_t key_l[KEYSIZE_BYTES] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                     0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    TEST_START

    print_array_char("plaintext", plaintext, sizeof(plaintext));
    int status = bbb_ddd_aes_ref_read_encrypt(
      ciphertext, plaintext, 2 * BLOCKSIZE_BYTES + 1, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status < 0) {
        printf("ERROR: bbb_ddd_aes_ref_read_encrypt() failed, status: %d\n", status);
        exit(1);
    }

    print_array_hex("ciphertext", ciphertext, sizeof(ciphertext));
    status = bbb_ddd_aes_ref_read_decrypt(
      decrypted, ciphertext, 2 * BLOCKSIZE_BYTES + 1, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status < 0) {
        printf("ERROR: bbb_ddd_aes_ref_read_decrypt() failed, status: %d\n", status);
        exit(1);
    }

    print_array_char("decrypted", decrypted, sizeof(decrypted));

    if (memcmp(plaintext, decrypted, 2 * BLOCKSIZE_BYTES + 1) != 0) {
        TEST_FAILED
        exit(1);
    }

    TEST_PASSED
}

/// End of full-cycle encryption/decryption tests

/// Basic negative input validation tests

/// @brief Test incorrect inputs to bbb_ddd_aes_ref_read_encrypt()
static void test_neg_input_enc()
{
    uint8_t plaintext[2 * BLOCKSIZE_BYTES + 1] = "ABCDEFGHIJKLMNOPX0123456701234567";
    uint8_t ciphertext[2 * BLOCKSIZE_BYTES + 1];
    uint8_t tweak[TWEAKSIZE_BYTES] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    uint8_t key_k[2 * KEYSIZE_BYTES] = { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0,
                                         0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x0F, 0x1F, 0x2F, 0x3F, 0x4F, 0x5F,
                                         0x6F, 0x7F, 0x8F, 0x9F, 0xAF, 0xBF, 0xCF, 0xDF, 0xEF, 0xFF };
    uint8_t key_l[KEYSIZE_BYTES] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                     0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    TEST_START

    // NULL pointer for ciphertext
    int status = bbb_ddd_aes_ref_read_encrypt(NULL, plaintext, sizeof(plaintext), key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null ciphertext): bbb_ddd_aes_ref_read_encrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for plaintext
    status = bbb_ddd_aes_ref_read_encrypt(ciphertext, NULL, sizeof(plaintext), key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null plaintext): bbb_ddd_aes_ref_read_encrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for key_k
    status =
      bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, sizeof(plaintext), NULL, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null key_k): bbb_ddd_aes_ref_read_encrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for key_l
    status =
      bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, sizeof(plaintext), key_k, NULL, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null key_l): bbb_ddd_aes_ref_read_encrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for tweak
    status =
      bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, sizeof(plaintext), key_k, key_l, NULL, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null tweak): bbb_ddd_aes_ref_read_encrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // Zero plaintext length
    status = bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, 0, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf(
          "TEST FAILED (zero plaintext length): bbb_ddd_aes_ref_read_encrypt() should have errored out, status: %d\n",
          status);
        exit(1);
    }

    // Too small plaintext length
    status =
      bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, 1 * BLOCKSIZE_BYTES, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too small plaintext length): bbb_ddd_aes_ref_read_encrypt() should have errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big plaintext length (MAXENCRYPTBLOCKS)
    status = bbb_ddd_aes_ref_read_encrypt(
      ciphertext, plaintext, MAXENCRYPTBLOCKS * (size_t)BLOCKSIZE_BYTES, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too big plaintext length - MAXENCRYPTBLOCKS): bbb_ddd_aes_ref_read_encrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big plaintext length (SIZE_MAX)
    status = bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, SIZE_MAX, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too big plaintext length - SIZE_MAX): bbb_ddd_aes_ref_read_encrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Zero tweak length
    status = bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, sizeof(plaintext), key_k, key_l, tweak, 0);
    if (status >= 0) {
        printf("TEST FAILED (zero tweak length): bbb_ddd_aes_ref_read_encrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // Too small tweak length
    status =
      bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, sizeof(plaintext), key_k, key_l, tweak, TWEAKSIZE_BYTES - 1);
    if (status >= 0) {
        printf("TEST FAILED (too small tweak length): bbb_ddd_aes_ref_read_encrypt() should have errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big tweak length (TWEAKSIZE_BYTES + 1)
    status =
      bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, sizeof(plaintext), key_k, key_l, tweak, TWEAKSIZE_BYTES + 1);
    if (status >= 0) {
        printf("TEST FAILED (too big tweak length - TWEAKSIZE_BYTES + 1): bbb_ddd_aes_ref_read_encrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big tweak length (SIZE_MAX)
    status = bbb_ddd_aes_ref_read_encrypt(ciphertext, plaintext, sizeof(plaintext), key_k, key_l, tweak, SIZE_MAX);
    if (status >= 0) {
        printf("TEST FAILED (too big tweak length - SIZE_MAX): bbb_ddd_aes_ref_read_encrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    TEST_PASSED
}

/// @brief Test incorrect inputs to bbb_ddd_aes_ref_read_decrypt()
static void test_neg_input_dec()
{
    uint8_t ciphertext[2 * BLOCKSIZE_BYTES + 1] = "ABCDEFGHIJKLMNOPX0123456701234567";
    uint8_t plaintext[2 * BLOCKSIZE_BYTES + 1];
    uint8_t tweak[TWEAKSIZE_BYTES] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    uint8_t key_k[2 * KEYSIZE_BYTES] = { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0,
                                         0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x0F, 0x1F, 0x2F, 0x3F, 0x4F, 0x5F,
                                         0x6F, 0x7F, 0x8F, 0x9F, 0xAF, 0xBF, 0xCF, 0xDF, 0xEF, 0xFF };
    uint8_t key_l[KEYSIZE_BYTES] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                     0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    TEST_START

    // NULL pointer for ciphertext
    int status =
      bbb_ddd_aes_ref_read_decrypt(plaintext, NULL, sizeof(ciphertext), key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null ciphertext): bbb_ddd_aes_ref_read_decrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for plaintext
    status = bbb_ddd_aes_ref_read_decrypt(NULL, ciphertext, sizeof(ciphertext), key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null plaintext): bbb_ddd_aes_ref_read_decrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for key_k
    status =
      bbb_ddd_aes_ref_read_decrypt(plaintext, ciphertext, sizeof(ciphertext), NULL, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null key_k): bbb_ddd_aes_ref_read_decrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for key_l
    status =
      bbb_ddd_aes_ref_read_decrypt(plaintext, ciphertext, sizeof(ciphertext), key_k, NULL, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null key_l): bbb_ddd_aes_ref_read_decrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for tweak
    status =
      bbb_ddd_aes_ref_read_decrypt(plaintext, ciphertext, sizeof(ciphertext), key_k, key_l, NULL, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null tweak): bbb_ddd_aes_ref_read_decrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // Zero ciphertext length
    status = bbb_ddd_aes_ref_read_decrypt(plaintext, ciphertext, 0, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf(
          "TEST FAILED (zero ciphertext length): bbb_ddd_aes_ref_read_decrypt() should have errored out, status: %d\n",
          status);
        exit(1);
    }

    // Too small ciphertext length
    status =
      bbb_ddd_aes_ref_read_decrypt(plaintext, ciphertext, 1 * BLOCKSIZE_BYTES, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too small ciphertext length): bbb_ddd_aes_ref_read_decrypt() should have errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big ciphertext length (MAXENCRYPTBLOCKS)
    status = bbb_ddd_aes_ref_read_decrypt(
      plaintext, ciphertext, MAXENCRYPTBLOCKS * (size_t)BLOCKSIZE_BYTES, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too big ciphertext length - MAXENCRYPTBLOCKS): bbb_ddd_aes_ref_read_decrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big ciphertext length (SIZE_MAX)
    status = bbb_ddd_aes_ref_read_decrypt(plaintext, ciphertext, SIZE_MAX, key_k, key_l, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too big ciphertext length - SIZE_MAX): bbb_ddd_aes_ref_read_decrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Zero tweak length
    status = bbb_ddd_aes_ref_read_decrypt(plaintext, ciphertext, sizeof(ciphertext), key_k, key_l, tweak, 0);
    if (status >= 0) {
        printf("TEST FAILED (zero tweak length): bbb_ddd_aes_ref_read_decrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // Too small tweak length
    status =
      bbb_ddd_aes_ref_read_decrypt(plaintext, ciphertext, sizeof(ciphertext), key_k, key_l, tweak, TWEAKSIZE_BYTES - 1);
    if (status >= 0) {
        printf("TEST FAILED (too small tweak length): bbb_ddd_aes_ref_read_decrypt() should have errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big tweak length (TWEAKSIZE_BYTES + 1)
    status =
      bbb_ddd_aes_ref_read_decrypt(plaintext, ciphertext, sizeof(ciphertext), key_k, key_l, tweak, TWEAKSIZE_BYTES + 1);
    if (status >= 0) {
        printf("TEST FAILED (too big tweak length - TWEAKSIZE_BYTES + 1): bbb_ddd_aes_ref_read_decrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big tweak length (SIZE_MAX)
    status = bbb_ddd_aes_ref_read_decrypt(plaintext, ciphertext, sizeof(ciphertext), key_k, key_l, tweak, SIZE_MAX);
    if (status >= 0) {
        printf("TEST FAILED (too big tweak length - SIZE_MAX): bbb_ddd_aes_ref_read_decrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    TEST_PASSED
}

/// End of basic negative input validation tests

#ifdef TEST_INTERNAL_FN_ACCESS
/// xor_h() tests

/// @brief Tests xor_h() using a POLYVAL test vector from RFC 8452 Section 8 with a static non-zero initial value.
static void test_xor_h_testvector_1()
{
    uint8_t ALIGN128 key[] = { 0x31, 0x07, 0x28, 0xd9, 0x91, 0x1f, 0x1f, 0x38,
                               0x37, 0xb2, 0x43, 0x16, 0xc3, 0xfa, 0xb9, 0xa0 };

    uint8_t ALIGN128 ref_tag[] = { 0x32, 0x37, 0xfa, 0xf5, 0xbe, 0xe8, 0xdf, 0xc8,
                                   0x4a, 0xd9, 0x9d, 0x5c, 0xd2, 0xca, 0x3d, 0x3b };

    // To test xor_h() (as opposed to just POLYVAL), we initialize this to an arbitrary non-zero value 0xAE
    uint8_t ALIGN128 tag[POLYVAL_TAG_LEN_BYTES];
    memset(tag, 0xAE, sizeof(tag));

    // clang-format off: 8/16-byte-aligned strings are more convenient in this context
    uint8_t ALIGN128 msg[] = { 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f,
                               0x72, 0x6c, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    // clang-format on

    TEST_START

    // Basic correctness checks
    assert(sizeof(key) == POLYVAL_KEY_LEN_BYTES);
    assert(sizeof(ref_tag) == POLYVAL_TAG_LEN_BYTES);
    assert(sizeof(tag) == POLYVAL_KEY_LEN_BYTES);

    print_array_hex("key", key, sizeof(key));
    print_array_hex("msg", msg, sizeof(msg));
    print_array_hex("xor_h_in", tag, sizeof(tag));

    int status = xor_h(tag, msg, sizeof(msg), key);
    if (status < 0) {
        printf("ERROR: xor_h() failed, status: %d\n", status);
        exit(1);
    }

    print_array_hex("xor_h_out", tag, sizeof(tag));
    print_array_hex("xor_h_ref", ref_tag, sizeof(ref_tag));

    if (memcmp(ref_tag, tag, POLYVAL_TAG_LEN_BYTES) != 0) {
        TEST_FAILED
        exit(1);
    }

    TEST_PASSED
}

/// @brief Tests xor_h() using a POLYVAL test vector from RFC 8452 Appendix A
/// @brief (+an intermediate value from the Go POLYVAL implementation) with a static non-zero initial value.
static void test_xor_h_testvector_2()
{
    uint8_t ALIGN128 key[] = { 0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76,
                               0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b, 0x75, 0x7b };

    // xor_h(<...>, X_1)
    uint8_t ALIGN128 ref_tag_msg_short[] = { 0xc6, 0x73, 0xbd, 0x20, 0x5c, 0xb3, 0x2d, 0x54,
                                             0x34, 0x86, 0x45, 0x91, 0x72, 0x38, 0x3c, 0xf9 };

    // xor_h(<...>, X_1||X_2)
    uint8_t ALIGN128 ref_tag_msg_long[] = { 0xca, 0xcf, 0x64, 0xf7, 0x60, 0x10, 0x03, 0x1b,
                                            0xc5, 0x6b, 0xd1, 0x41, 0x2c, 0x16, 0xe1, 0x85 };

    uint8_t ALIGN128 tag[POLYVAL_TAG_LEN_BYTES];
    memset(tag, 0x5A, sizeof(tag));

    uint8_t ALIGN128 msg[] = { 0x4f, 0x4f, 0x95, 0x66, 0x8c, 0x83, 0xdf, 0xb6, // X_1
                               0x40, 0x17, 0x62, 0xbb, 0x2d, 0x01, 0xa2, 0x62,
                               0xd1, 0xa2, 0x4d, 0xdd, 0x27, 0x21, 0xd0, 0x06, // X_2
                               0xbb, 0xe4, 0x5f, 0x20, 0xd3, 0xc9, 0xf3, 0x62 };

    TEST_START

    // Basic correctness checks
    assert(sizeof(key) == POLYVAL_KEY_LEN_BYTES);
    assert(sizeof(ref_tag_msg_short) == POLYVAL_TAG_LEN_BYTES);
    assert(sizeof(ref_tag_msg_long) == POLYVAL_TAG_LEN_BYTES);
    assert(sizeof(tag) == POLYVAL_KEY_LEN_BYTES);

    // Test the short message (just the first block of msg[])
    print_array_hex("key", key, sizeof(key));
    print_array_hex("xor_h_in_short", msg, POLYVAL_BLOCK_LEN_BYTES);

    int status = xor_h(tag, msg, POLYVAL_BLOCK_LEN_BYTES, key);
    if (status < 0) {
        printf("ERROR: xor_h() failed, status: %d\n", status);
        exit(1);
    }

    print_array_hex("xor_h_out_short", tag, sizeof(tag));
    print_array_hex("xor_h_out_short_ref", ref_tag_msg_short, sizeof(ref_tag_msg_short));
    printf("\n");

    if (memcmp(ref_tag_msg_short, tag, POLYVAL_TAG_LEN_BYTES) != 0) {
        TEST_FAILED
        exit(1);
    }
    // End of short message test

    // Test the full (long) message
    // Reset the incoming tag value
    memset(tag, 0x5A, sizeof(tag));
    print_array_hex("key", key, sizeof(key));
    print_array_hex("xor_h_in_long", msg, sizeof(msg));

    status = xor_h(tag, msg, sizeof(msg), key);
    if (status < 0) {
        printf("ERROR: xor_h() failed, status: %d\n", status);
        exit(1);
    }

    print_array_hex("xor_h_out_long", tag, sizeof(tag));
    print_array_hex("xor_h_out_long_ref", ref_tag_msg_long, sizeof(ref_tag_msg_long));

    if (memcmp(ref_tag_msg_long, tag, POLYVAL_TAG_LEN_BYTES) != 0) {
        TEST_FAILED
        exit(1);
    }

    TEST_PASSED
}

/// End of xor_h() tests
#endif

int main(int argc, char* argv[])
{
    // We don't use these, make this explicit
    (void)argc;
    (void)argv;

#ifdef TEST_INTERNAL_FN_ACCESS
    test_xor_h_testvector_1();
    test_xor_h_testvector_2();
#endif

    test_enc_dec_2blocks();
    test_enc_dec_3blocks();
    test_enc_dec_2blocks_andone();

    test_neg_input_enc();
    test_neg_input_dec();

    printf("All tests PASSED\n");

    return 0;
}
