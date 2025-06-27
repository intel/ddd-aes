# MIT license
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT

add_executable(ddd-aes-ref-perf zeroize.h zeroize.c ddd-aes-ref-perf.h ddd-aes-ref-perf.c tests.c)
add_executable(ddd-aes-ref-perf-gen-testvectors zeroize.h zeroize.c ddd-aes-ref-perf.h ddd-aes-ref-perf.c gen-testvectors.c)

target_compile_features(ddd-aes-ref-perf PUBLIC c_std_17)
target_compile_features(ddd-aes-ref-perf-gen-testvectors PUBLIC c_std_17)

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    # Set these for all build types
    target_compile_options(ddd-aes-ref-perf PRIVATE ${COMPILE_OPTIONS_COMMON})
    target_compile_options(ddd-aes-ref-perf-gen-testvectors PRIVATE ${COMPILE_OPTIONS_COMMON})
    # Set these for Release build type only
    target_compile_options(ddd-aes-ref-perf PRIVATE
        $<$<CONFIG:Release>:${COMPILE_OPTIONS_RELEASE}>
    )
    target_compile_options(ddd-aes-ref-perf-gen-testvectors PRIVATE
        $<$<CONFIG:Release>:${COMPILE_OPTIONS_RELEASE}>
    )
endif()
