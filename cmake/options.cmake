# Copyright (c) 2023 Microsoft Corporation.
# SPDX-License-Identifier: MIT

if(PLATFORM_LINUX OR PLATFORM_MACOS)
  option(BTF_ENABLE_COVERAGE "Set to true to enable coverage flags")
  option(BTF_ENABLE_SANITIZERS "Set to true to enable the address and undefined sanitizers")
endif()

option(BTF_ENABLE_TESTS "Set to true to enable tests")
option(BTF_INSTALL_GIT_HOOKS "Set to true to install git hooks" ON)

# Note that the compile_commands.json file is only exporter when
# using the Ninja or Makefile generator
set(CMAKE_EXPORT_COMPILE_COMMANDS true CACHE BOOL "Set to true to generate the compile_commands.json file (forced on)" FORCE)

set(CMAKE_CXX_STANDARD 20)
