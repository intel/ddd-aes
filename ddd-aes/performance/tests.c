/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "ddd-aes-ref-perf.h"

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
    printf("\n\n");
}

/// End of test utilities

#define TEST_DATA_BLEN 1066

/// @brief Full-cycle encryption/decryption test
static void test_enc_dec()
{
    uint8_t ALIGN128 k[CRYPTO_KEYBYTES];
    uint8_t ALIGN128 ek[CRYPTO_EXPANDED_KEYBYTES];
    uint8_t ALIGN128 m[TEST_DATA_BLEN];
    uint8_t ALIGN128 m2[TEST_DATA_BLEN];
    uint8_t ALIGN128 c[TEST_DATA_BLEN];
    uint8_t ALIGN128 t[TWEAKSIZE_BYTES];

    TEST_START

    // IMPORTANT: libc rand() is insecure for production workloads, it is not a cryptographically-secure random number
    // generator. Used here only because for performance testing we do not care about the quality of the randomness used
    // and using rand() we can avoid bringing in additional libraries.
    for (uint32_t i = 0; i < CRYPTO_KEYBYTES; ++i) {
        k[i] = (uint8_t)rand();
    }
    for (uint32_t i = 0; i < TEST_DATA_BLEN; ++i) {
        m[i] = (uint8_t)rand();
    }
    for (uint32_t i = 0; i < TWEAKSIZE_BYTES; ++i) {
        t[i] = (uint8_t)rand();
    }

    precompute_key(k, ek);

    print_array_hex("k", k, CRYPTO_KEYBYTES);

    print_array_hex("ek", ek, CRYPTO_EXPANDED_KEYBYTES);

    print_array_hex("z", t, TWEAKSIZE_BYTES);

    print_array_hex("m", m, TEST_DATA_BLEN);

    int status = ddd_aes_ref_perf_encrypt(c, m, TEST_DATA_BLEN, ek, t, TWEAKSIZE_BYTES);
    if (status < 0) {
        printf("ERROR: ddd_aes_ref_perf_encrypt() failed, status: %d\n", status);
        exit(1);
    }

    print_array_hex("c", c, TEST_DATA_BLEN);

    status = ddd_aes_ref_perf_decrypt(m2, c, TEST_DATA_BLEN, ek, t, TWEAKSIZE_BYTES);
    if (status < 0) {
        printf("ERROR: ddd_aes_ref_perf_decrypt() failed, status: %d\n", status);
        exit(1);
    }

    print_array_hex("m", m2, TEST_DATA_BLEN);

    if (memcmp(m, m2, TEST_DATA_BLEN) != 0) {
        TEST_FAILED
        exit(1);
    }

    TEST_PASSED
}

/// Basic negative input validation tests

/// @brief Test incorrect inputs to ddd_aes_ref_perf_encrypt()
static void test_neg_input_enc()
{
    uint8_t ALIGN128 k[CRYPTO_KEYBYTES];
    uint8_t ALIGN128 ek[CRYPTO_EXPANDED_KEYBYTES];
    uint8_t ALIGN128 plaintext[TEST_DATA_BLEN];
    uint8_t ALIGN128 ciphertext[TEST_DATA_BLEN];
    uint8_t ALIGN128 tweak[TWEAKSIZE_BYTES];

    TEST_START

    // IMPORTANT: libc rand() is insecure for production workloads, it is not a cryptographically-secure random number
    // generator. Used here only because for performance testing we do not care about the quality of the randomness used
    // and using rand() we can avoid bringing in additional libraries.
    for (uint32_t i = 0; i < CRYPTO_KEYBYTES; ++i) {
        k[i] = (uint8_t)rand();
    }
    for (uint32_t i = 0; i < TEST_DATA_BLEN; ++i) {
        plaintext[i] = (uint8_t)rand();
    }
    for (uint32_t i = 0; i < TWEAKSIZE_BYTES; ++i) {
        tweak[i] = (uint8_t)rand();
    }

    precompute_key(k, ek);

    // NULL pointer for plaintext
    int status = ddd_aes_ref_perf_encrypt(ciphertext, NULL, sizeof(plaintext), ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null plaintext): ddd_aes_ref_perf_encrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for ciphertext
    status = ddd_aes_ref_perf_encrypt(NULL, plaintext, sizeof(plaintext), ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null ciphertext): ddd_aes_ref_perf_encrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for key
    status = ddd_aes_ref_perf_encrypt(ciphertext, plaintext, sizeof(plaintext), NULL, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null key): ddd_aes_ref_perf_encrypt() should have errored out, status: %d\n", status);
        exit(1);
    }

    // NULL pointer for tweak
    status = ddd_aes_ref_perf_encrypt(ciphertext, plaintext, sizeof(plaintext), ek, NULL, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null tweak): ddd_aes_ref_perf_encrypt() should have errored out, status: %d\n", status);
        exit(1);
    }

    // Zero plaintext length
    status = ddd_aes_ref_perf_encrypt(ciphertext, plaintext, 0, ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (zero plaintext length): ddd_aes_ref_perf_encrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // Too small plaintext length
    status = ddd_aes_ref_perf_encrypt(ciphertext, plaintext, 1 * BLOCKSIZE_BYTES, ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too small plaintext length): ddd_aes_ref_perf_encrypt() should have errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big plaintext length (MAX_PERF_TEST_DATA_BLEN + 1)
    status = ddd_aes_ref_perf_encrypt(ciphertext, plaintext, MAX_PERF_TEST_DATA_BLEN + 1, ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too big plaintext length - MAX_PERF_TEST_DATA_BLEN + 1): ddd_aes_ref_perf_encrypt() "
               "should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big plaintext length (UINT32_MAX)
    status = ddd_aes_ref_perf_encrypt(ciphertext, plaintext, UINT32_MAX, ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too big plaintext length - UINT32_MAX): ddd_aes_ref_perf_encrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Zero tweak length
    status = ddd_aes_ref_perf_encrypt(ciphertext, plaintext, sizeof(plaintext), ek, tweak, 0);
    if (status >= 0) {
        printf("TEST FAILED (zero tweak length): ddd_aes_ref_perf_encrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // Too small tweak length
    status = ddd_aes_ref_perf_encrypt(ciphertext, plaintext, sizeof(plaintext), ek, tweak, TWEAKSIZE_BYTES - 1);
    if (status >= 0) {
        printf("TEST FAILED (too small tweak length): ddd_aes_ref_perf_encrypt() should have errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big tweak length (TWEAKSIZE_BYTES + 1)
    status = ddd_aes_ref_perf_encrypt(ciphertext, plaintext, sizeof(plaintext), ek, tweak, TWEAKSIZE_BYTES + 1);
    if (status >= 0) {
        printf("TEST FAILED (too big tweak length - TWEAKSIZE_BYTES + 1): ddd_aes_ref_perf_encrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big tweak length (UINT32_MAX)
    status = ddd_aes_ref_perf_encrypt(ciphertext, plaintext, sizeof(plaintext), ek, tweak, UINT32_MAX);
    if (status >= 0) {
        printf("TEST FAILED (too big tweak length - UINT32_MAX): ddd_aes_ref_perf_encrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    TEST_PASSED
}

/// @brief Test incorrect inputs to ddd_aes_ref_perf_decrypt()
static void test_neg_input_dec()
{
    uint8_t ALIGN128 k[CRYPTO_KEYBYTES];
    uint8_t ALIGN128 ek[CRYPTO_EXPANDED_KEYBYTES];
    uint8_t ALIGN128 plaintext[TEST_DATA_BLEN];
    uint8_t ALIGN128 ciphertext[TEST_DATA_BLEN];
    uint8_t ALIGN128 tweak[TWEAKSIZE_BYTES];

    TEST_START

    // IMPORTANT: libc rand() is insecure for production workloads, it is not a cryptographically-secure random number
    // generator. Used here only because for performance testing we do not care about the quality of the randomness used
    // and using rand() we can avoid bringing in additional libraries.
    for (uint32_t i = 0; i < CRYPTO_KEYBYTES; ++i) {
        k[i] = (uint8_t)rand();
    }
    for (uint32_t i = 0; i < TEST_DATA_BLEN; ++i) {
        ciphertext[i] = (uint8_t)rand();
    }
    for (uint32_t i = 0; i < TWEAKSIZE_BYTES; ++i) {
        tweak[i] = (uint8_t)rand();
    }

    precompute_key(k, ek);

    // NULL pointer for plaintext
    int status = ddd_aes_ref_perf_decrypt(NULL, ciphertext, sizeof(ciphertext), ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null plaintext): ddd_aes_ref_perf_decrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for ciphertext
    status = ddd_aes_ref_perf_decrypt(plaintext, NULL, sizeof(ciphertext), ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null ciphertext): ddd_aes_ref_perf_decrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // NULL pointer for key
    status = ddd_aes_ref_perf_decrypt(plaintext, ciphertext, sizeof(ciphertext), NULL, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null key): ddd_aes_ref_perf_decrypt() should have errored out, status: %d\n", status);
        exit(1);
    }

    // NULL pointer for tweak
    status = ddd_aes_ref_perf_decrypt(plaintext, ciphertext, sizeof(ciphertext), ek, NULL, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (null tweak): ddd_aes_ref_perf_decrypt() should have errored out, status: %d\n", status);
        exit(1);
    }

    // Zero ciphertext length
    status = ddd_aes_ref_perf_decrypt(plaintext, ciphertext, 0, ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (zero ciphertext length): ddd_aes_ref_perf_decrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // Too small ciphertext length
    status = ddd_aes_ref_perf_decrypt(plaintext, ciphertext, 1 * BLOCKSIZE_BYTES, ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too small ciphertext length): ddd_aes_ref_perf_decrypt() should have errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big ciphertext length (MAX_PERF_TEST_DATA_BLEN + 1)
    status = ddd_aes_ref_perf_decrypt(plaintext, ciphertext, MAX_PERF_TEST_DATA_BLEN + 1, ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too big ciphertext length - MAX_PERF_TEST_DATA_BLEN + 1): ddd_aes_ref_perf_decrypt() "
               "should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big ciphertext length (UINT32_MAX)
    status = ddd_aes_ref_perf_decrypt(plaintext, ciphertext, UINT32_MAX, ek, tweak, TWEAKSIZE_BYTES);
    if (status >= 0) {
        printf("TEST FAILED (too big ciphertext length - UINT32_MAX): ddd_aes_ref_perf_decrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Zero tweak length
    status = ddd_aes_ref_perf_decrypt(plaintext, ciphertext, sizeof(ciphertext), ek, tweak, 0);
    if (status >= 0) {
        printf("TEST FAILED (zero tweak length): ddd_aes_ref_perf_decrypt() should have errored out, status: %d\n",
               status);
        exit(1);
    }

    // Too small tweak length
    status = ddd_aes_ref_perf_decrypt(plaintext, ciphertext, sizeof(ciphertext), ek, tweak, TWEAKSIZE_BYTES - 1);
    if (status >= 0) {
        printf("TEST FAILED (too small tweak length): ddd_aes_ref_perf_decrypt() should have errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big tweak length (TWEAKSIZE_BYTES + 1)
    status = ddd_aes_ref_perf_decrypt(plaintext, ciphertext, sizeof(ciphertext), ek, tweak, TWEAKSIZE_BYTES + 1);
    if (status >= 0) {
        printf("TEST FAILED (too big tweak length - TWEAKSIZE_BYTES + 1): ddd_aes_ref_perf_decrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    // Too big tweak length (UINT32_MAX)
    status = ddd_aes_ref_perf_decrypt(plaintext, ciphertext, sizeof(ciphertext), ek, tweak, UINT32_MAX);
    if (status >= 0) {
        printf("TEST FAILED (too big tweak length - UINT32_MAX): ddd_aes_ref_perf_decrypt() should have "
               "errored out, "
               "status: %d\n",
               status);
        exit(1);
    }

    TEST_PASSED
}

/// End of basic negative input validation tests

int main(int argc, char* argv[])
{
    // We don't use these, make this explicit
    (void)argc;
    (void)argv;

    test_enc_dec();

    test_neg_input_enc();
    test_neg_input_dec();

    return 0;
}
