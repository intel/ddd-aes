# MIT license
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.21)

# Required for the VERSION option in project()
cmake_policy(SET CMP0048 NEW)

project(ddd-aes-ref VERSION 0.1.0 LANGUAGES C)

# Switch to control access to implementation's internal functions (need to opt them in explicitly in the respective headers).
# For example, this enables access to xor_h() implementation to be tested against the official POLYVAL test vectors.
option(TEST_INTERNAL_FN_ACCESS "Allow the test program to access primitive-internal functions like xor_h()" ON)
if(TEST_INTERNAL_FN_ACCESS)
    add_compile_definitions(TEST_INTERNAL_FN_ACCESS)
endif()

# Enable code for zeroizing sensitive data. This comes at the performance/size cost,
# especially for the performance-oriented implementation. We aim to be "secure by default", so this is default-enabled.
option(ZEROIZE_SECRETS "Enable secret zeroization" ON)
if (ZEROIZE_SECRETS)
    add_compile_definitions(ZEROIZE_SECRETS)
endif()

# Set various compiler options. Again, we strive for "secure by default", even at the cost of performance.
# Verify that values match your desired use/test case to make sure you get the right results.
set(COMPILE_OPTIONS_COMMON "\
-Wall;\
-Wextra;\
-Wformat-security;\
-Wconversion;\
-march=native;\
-fcf-protection=full;\
-fPIC;\
-fPIE;\
-pie;\
-fstack-protector-strong;\
-fno-delete-null-pointer-checks"
)

set(COMPILE_OPTIONS_RELEASE "\
-O3;\
-fomit-frame-pointer;\
-frename-registers;\
-funroll-loops;\
-Werror;\
-Wl,-z,noexecstack,-z,relro,-z,now,-z,nodlopen;\
-fstack-clash-protection;\
-D_FORTIFY_SOURCE=3"
)

# Enable generation for IDEs to properly highlight the ifdef'ed sections
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(bbb-ddd-aes/performance)
add_subdirectory(bbb-ddd-aes/readability)

add_subdirectory(ddd-aes/performance)
add_subdirectory(ddd-aes/readability)
