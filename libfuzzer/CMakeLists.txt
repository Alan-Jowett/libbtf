# Copyright (c) 2023 Microsoft Corporation.
# SPDX-License-Identifier: MIT

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang)

add_executable(libbtf_fuzzer libfuzz_harness.cpp)

target_compile_options(libbtf_fuzzer
            PRIVATE $<$<C_COMPILER_ID:Clang>:-g -O1 -fsanitize=fuzzer>
            )

target_link_libraries(libbtf_fuzzer
            PRIVATE $<$<C_COMPILER_ID:Clang>:-fsanitize=fuzzer>
            )