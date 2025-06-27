# MIT license
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT

add_executable(ddd-aes-ref-readability zeroize.h zeroize.c polyval.h polyval.c aes.h aes.c ddd-aes-ref-readability.h ddd-aes-ref-readability.c tests.c)
add_executable(ddd-aes-ref-read-gen-testvectors zeroize.h zeroize.c polyval.h polyval.c aes.h aes.c ddd-aes-ref-readability.h ddd-aes-ref-readability.c gen-testvectors.c)

target_compile_features(ddd-aes-ref-readability PUBLIC c_std_17)
target_compile_features(ddd-aes-ref-read-gen-testvectors PUBLIC c_std_17)

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    # Set these for all build types
    target_compile_options(ddd-aes-ref-readability PRIVATE ${COMPILE_OPTIONS_COMMON})
    target_compile_options(ddd-aes-ref-read-gen-testvectors PRIVATE ${COMPILE_OPTIONS_COMMON})
    # Set these for Release build type only
    target_compile_options(ddd-aes-ref-readability PRIVATE
        $<$<CONFIG:Release>:${COMPILE_OPTIONS_RELEASE}>
    )
    target_compile_options(ddd-aes-ref-read-gen-testvectors PRIVATE
        $<$<CONFIG:Release>:${COMPILE_OPTIONS_RELEASE}>
    )
endif()
