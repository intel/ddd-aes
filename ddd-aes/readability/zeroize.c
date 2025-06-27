/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT
*/

#include "zeroize.h"

void zeroize_secret(void* secret, size_t slen)
{
#ifdef ZEROIZE_SECRETS
#ifdef _WIN32
    SecureZeroMemory(secret, slen);
#else
    explicit_bzero(secret, slen);
#endif
#endif
}
