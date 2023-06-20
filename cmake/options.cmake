# Copyright (c) 2023 Microsoft Corporation.
# SPDX-License-Identifier: MIT

if(PLATFORM_LINUX OR PLATFORM_MACOS)
  option(BTF_ENABLE_COVERAGE "Set to true to enable coverage flags")
  option(BTF_ENABLE_SANITIZERS "Set to true to enable the address and undefined sanitizers")
endif()

option(BTF_ENABLE_TESTS "Set to true to enable tests")
option(BTF_INSTALL_GIT_HOOKS "Set to true to install git hooks" ON)
option(BTF_ENABLE_FUZZING "Set to true to enable fuzzing")
option(BTF_DUMP "Set to true to build the dump tool")

# Note that the compile_commands.json file is only exporter when
# using the Ninja or Makefile generator
set(CMAKE_EXPORT_COMPILE_COMMANDS true CACHE BOOL "Set to true to generate the compile_commands.json file (forced on)" FORCE)

set(CMAKE_CXX_STANDARD 20)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(COMMON_FLAGS -Wall -Wfatal-errors -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8)

  set(RELEASE_FLAGS -O2 -flto -ffat-lto-objects)

  set(DEBUG_FLAGS -O0 -g3 -fno-omit-frame-pointer)

  set(SANITIZE_FLAGS -fsanitize=address -O1 -fno-omit-frame-pointer)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++20 /W4 /WX")
endif ()