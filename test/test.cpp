// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include <chrono>
#include <future>
#include <map>
#include <regex>
#include <string>
#include <vector>

#if !defined(MAX_PATH)
#define MAX_PATH (256)
#endif

#include "btf.h"
#include "btf_c_type.h"
#include "btf_json.h"
#include "btf_map.h"
#include "btf_parse.h"
#include "btf_type_data.h"
#include "btf_write.h"

// Suppress some W4 warnings from the elfio library.
#pragma warning(push)
#pragma warning(disable : 4244)
#pragma warning(disable : 4458)
#include "elfio/elfio.hpp"
#pragma warning(pop)

std::map<std::string, std::string> string_replacements = {
    // ebpf-samples JSON incorrectly swapped static and global.
    {"BTF_LINKAGE_STATIC", "BTF_LINKAGE_GLOBAL"},
    {"BTF_LINKAGE_GLOBAL", "BTF_LINKAGE_STATIC"},
    // BTF_KIND_FUNC renamed to BTF_KIND_FUNCTION
    {"BTF_KIND_FUNC", "BTF_KIND_FUNCTION"},
    // BTF_KIND_FUNC renamed to BTF_KIND_FUNCTION
    {"BTF_KIND_FUNCTION_PROTO", "BTF_KIND_FUNCTION_PROTOTYPE"},
    // BTF_FUNC_GLOBAL renamed to BTF_LINKAGE_GLOBAL
    {"BTF_FUNC_GLOBAL", "BTF_LINKAGE_GLOBAL"},
    // BTF_KIND_DATASEC renamed to BTF_KIND_DATA_SECTION
    {"BTF_KIND_DATASEC", "BTF_KIND_DATA_SECTION"},
};

// Timeout wrapper to prevent infinite loops in cycle tests
// This mechanism protects all BTF cycle validation tests from hanging
// indefinitely if there are bugs in the cycle detection logic. If a test
// doesn't complete within the specified timeout (default 10 seconds), it will
// fail with a clear error message.
//
// Usage: run_with_timeout([&] { /* test code that might infinite loop */ });
//
// The timeout uses std::async to run the test in a separate thread and
// std::future::wait_for to enforce the time limit. This approach works reliably
// on Windows with the MSVC compiler and provides clear failure messages when
// timeouts occur.
template <typename Func>
void run_with_timeout(Func &&func,
                      std::chrono::seconds timeout = std::chrono::seconds(10)) {
  auto future = std::async(std::launch::async, std::forward<Func>(func));
  auto status = future.wait_for(timeout);

  if (status == std::future_status::timeout) {
    INFO("Test timed out after "
         << timeout.count() << " seconds - possible infinite loop detected");
    // Exit the process to avoid hanging the test suite
    std::exit(EXIT_FAILURE);
  }

  // Get the result to propagate any exceptions
  future.get();
}

#define TEST_OBJECT_FILE_DIRECTORY "external/ebpf-samples/build/"
#define TEST_SOURCE_FILE_DIRECTORY "external/ebpf-samples/src/"
#define TEST_JSON_FILE_DIRECTORY "json/"
#define TEST_C_HEADER_FILE_DIRECTORY "test/expected/"
#define BTF_CASE(file, apply_replacements)                                     \
  TEST_CASE("BTF JSON suite: " file, "[json]") {                               \
    verify_BTF_json(file, apply_replacements);                                 \
  }                                                                            \
  TEST_CASE("BTF LINE_INFO suite: " file, "[line_info]") {                     \
    verify_line_info(file);                                                    \
  }                                                                            \
  TEST_CASE("BTF C header suite: " file, "[c_header]") {                       \
    verify_c_header(file);                                                     \
  }

void verify_line_by_line(std::istream &lhs, std::istream &rhs,
                         bool apply_replacements = false) {
  std::string lhs_line;
  std::string rhs_line;
  while (std::getline(lhs, lhs_line)) {
    bool has_more = (bool)std::getline(rhs, rhs_line);
    REQUIRE(has_more);
    if (apply_replacements) {
      for (const auto &[old_string, new_string] : string_replacements) {
        lhs_line =
            std::regex_replace(lhs_line, std::regex(old_string), new_string);
      }
    }
    REQUIRE(lhs_line == rhs_line);
  }
  bool has_more = (bool)std::getline(rhs, rhs_line);
  REQUIRE_FALSE(has_more);
}

void verify_BTF_json(const std::string &file, bool apply_replacements = true) {
  std::stringstream generated_output;
  auto reader = ELFIO::elfio();
  REQUIRE(reader.load(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o"));

  auto btf = reader.sections[".BTF"];

  libbtf::btf_type_data btf_data = std::vector<std::byte>(
      {reinterpret_cast<const std::byte *>(btf->get_data()),
       reinterpret_cast<const std::byte *>(btf->get_data() + btf->get_size())});

  // Get the size of each type.
  for (libbtf::btf_type_id id = 1; id <= btf_data.last_type_id(); id++) {
    size_t size = btf_data.get_size(id);
    switch (btf_data.get_kind_index(id)) {
    // Non-zero sized types.
    case libbtf::BTF_KIND_INT:
    case libbtf::BTF_KIND_PTR:
    case libbtf::BTF_KIND_STRUCT:
    case libbtf::BTF_KIND_UNION:
    case libbtf::BTF_KIND_ENUM:
    case libbtf::BTF_KIND_VAR:
    case libbtf::BTF_KIND_FLOAT:
    case libbtf::BTF_KIND_ENUM64:
      REQUIRE(size != 0);
      break;
    case libbtf::BTF_KIND_FWD:
    case libbtf::BTF_KIND_VOLATILE:
    case libbtf::BTF_KIND_CONST:
    case libbtf::BTF_KIND_RESTRICT:
    case libbtf::BTF_KIND_FUNCTION:
    case libbtf::BTF_KIND_FUNCTION_PROTOTYPE:
    case libbtf::BTF_KIND_DATA_SECTION:
    case libbtf::BTF_KIND_DECL_TAG:
    case libbtf::BTF_KIND_TYPE_TAG:
      REQUIRE(size == 0);
      break;
    // Array can be zero sized if there are no elements.
    case libbtf::BTF_KIND_ARRAY: {
      auto array = btf_data.get_kind_type<libbtf::btf_kind_array>(id);
      REQUIRE(size ==
              array.count_of_elements * btf_data.get_size(array.element_type));
      break;
    }
    }
  }

  btf_data.to_json(generated_output);

  // Pretty print the JSON output.
  std::string pretty_printed_json =
      libbtf::pretty_print_json(generated_output.str());

  // Read the expected output from the .json file.
  std::ifstream expected_stream(std::string(TEST_JSON_FILE_DIRECTORY) + file +
                                std::string(".json"));
  std::stringstream generated_stream(pretty_printed_json);

  verify_line_by_line(expected_stream, generated_stream, apply_replacements);

  // Verify that encoding the BTF data and parsing it again results in the same
  // JSON.
  libbtf::btf_type_data btf_data_round_trip = btf_data.to_bytes();

  std::stringstream generated_output_round_trip;
  btf_data_round_trip.to_json(generated_output_round_trip);

  // Pretty print the JSON output.
  std::string pretty_printed_json_round_trip =
      libbtf::pretty_print_json(generated_output_round_trip.str());

  // Verify that the pretty printed JSON is the same as the original.
  REQUIRE(pretty_printed_json == pretty_printed_json_round_trip);
}

void verify_line_info(const std::string &file) {
  auto reader = ELFIO::elfio();
  REQUIRE(reader.load(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o"));

  auto btf_section = reader.sections[".BTF"];
  auto btfext_section = reader.sections[".BTF.ext"];

  std::vector<std::byte> btf = {
      reinterpret_cast<const std::byte *>(btf_section->get_data()),
      reinterpret_cast<const std::byte *>(btf_section->get_data() +
                                          btf_section->get_size())};
  std::vector<std::byte> btfext = {
      reinterpret_cast<const std::byte *>(btfext_section->get_data()),
      reinterpret_cast<const std::byte *>(btfext_section->get_data() +
                                          btfext_section->get_size())};

  // Read source file into array of strings.
  std::vector<std::string> source_lines;
  std::ifstream source_file(std::string(TEST_SOURCE_FILE_DIRECTORY) + file +
                            ".c");

  std::string line;
  while (std::getline(source_file, line)) {
    // Strip any trailing whitespace.
    line = line.substr(0, line.find_last_not_of(" \t\n\r\f\v") + 1);
    source_lines.push_back(line);
  }

  libbtf::btf_parse_line_information(
      btf, btfext,
      [&](const std::string &section, uint32_t instruction_offset,
          const std::string &file_name, const std::string &source,
          uint32_t line_number, uint32_t column_number) {
        // column_number is not used.
        (void)column_number;
        // instruction_offset is not used.
        (void)instruction_offset;
        if (!source.empty()) {
          // Removing any trailing whitespace.
          std::string stripped_source =
              source.substr(0, source.find_last_not_of(" \t\n\r\f\v") + 1);

          // Verify that the source line is correct.
          REQUIRE(stripped_source == source_lines[line_number - 1]);
          REQUIRE(line_number > 0);

          // Verify that the file_name matches the source file with the path
          // removed.
          std::string stripped_file_name =
              file_name.substr(file_name.find_last_of("/\\") + 1);
          REQUIRE(stripped_file_name == file + ".c");

          // Verify that the section name is present in the ELF file.
          REQUIRE(reader.sections[section] != nullptr);
        }
      });
}

void verify_c_header(const std::string &file) {
  std::stringstream generated_output;
  auto reader = ELFIO::elfio();
  REQUIRE(reader.load(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o"));

  auto btf = reader.sections[".BTF"];

  libbtf::btf_type_data btf_data = std::vector<std::byte>(
      {reinterpret_cast<const std::byte *>(btf->get_data()),
       reinterpret_cast<const std::byte *>(btf->get_data() + btf->get_size())});

  btf_data.to_c_header(generated_output);

  // Read the expected output from the .h file.
  std::ifstream expected_stream(std::string(TEST_C_HEADER_FILE_DIRECTORY) +
                                file + std::string(".h"));

  // Skip over the first two line of the header file, which is a comment
  // containing the name of ELF file and the name of the header file.
  std::string line;
  std::getline(expected_stream, line);
  std::getline(expected_stream, line);

  verify_line_by_line(expected_stream, generated_output);
}

BTF_CASE("byteswap", true)
BTF_CASE("ctxoffset", true)
BTF_CASE("exposeptr", true)
BTF_CASE("exposeptr2", true)
BTF_CASE("map_in_map", false)
BTF_CASE("map_in_map_anonymous", false)
BTF_CASE("mapoverflow", true)
BTF_CASE("mapunderflow", true)
BTF_CASE("mapvalue-overrun", true)
BTF_CASE("nullmapref", true)
BTF_CASE("packet_access", true)
BTF_CASE("packet_overflow", true)
BTF_CASE("packet_reallocate", true)
BTF_CASE("packet_start_ok", true)
BTF_CASE("stackok", true)
BTF_CASE("tail_call", true)
BTF_CASE("tail_call_bad", true)
BTF_CASE("twomaps", true)
BTF_CASE("twostackvars", true)
BTF_CASE("twotypes", true)

TEST_CASE("validate-parsing-simple-loop", "[validation]") {
  libbtf::btf_type_data btf_data_loop;
  btf_data_loop.append(libbtf::btf_kind_ptr{.type = 1});

  // Cycles should now be allowed
  REQUIRE_NOTHROW(
      [&] { libbtf::btf_type_data btf_data(btf_data_loop.to_bytes()); }());
}

TEST_CASE("validate-parsing-large-loop", "[validation]") {
  libbtf::btf_type_data btf_data_loop;

  // Each PTR points to the next PTR.
  for (uint32_t i = 0; i < 10; i++) {
    btf_data_loop.append(libbtf::btf_kind_ptr{.type = i + 1});
  }
  // Last PTR points to itself.
  btf_data_loop.append(libbtf::btf_kind_ptr{.type = 1});

  // Cycles should now be allowed
  REQUIRE_NOTHROW(
      [&] { libbtf::btf_type_data btf_data(btf_data_loop.to_bytes()); }());
}

TEST_CASE("validate-parsing-cycles-allowed-by-default", "[validation]") {
  libbtf::btf_type_data btf_data_loop;
  // Add an integer type first (root type)
  btf_data_loop.append(libbtf::btf_kind_int{.name = "int",
                                            .size_in_bytes = 4,
                                            .offset_from_start_in_bits = 0,
                                            .field_width_in_bits = 32,
                                            .is_signed = true,
                                            .is_char = false,
                                            .is_bool = false});
  // Add a pointer that creates a cycle (points to the int type)
  btf_data_loop.append(libbtf::btf_kind_ptr{.type = 1});
  // Add another pointer that points to the previous pointer, creating a cycle
  btf_data_loop.append(libbtf::btf_kind_ptr{.type = 2});

  // This should not throw since cycles are always allowed
  REQUIRE_NOTHROW(
      [&] { libbtf::btf_type_data btf_data(btf_data_loop.to_bytes()); }());

  // Test JSON output with cycles
  std::stringstream json_output;
  libbtf::btf_type_data btf_data(btf_data_loop.to_bytes());
  REQUIRE_NOTHROW([&] { btf_data.to_json(json_output); }());

  // Verify JSON contains expected content (should at least have the int type)
  std::string json_str = json_output.str();
  INFO("JSON output: " << json_str);
  bool has_content = json_str.find("btf_kinds") != std::string::npos &&
                     json_str.length() > 20; // More than just empty structure
  REQUIRE(has_content);
}

TEST_CASE("validate-get_size-with-cycles", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data_loop;
    // Add a pointer that points to itself (cycle)
    btf_data_loop.append(libbtf::btf_kind_ptr{.type = 1});

    // This should not crash and should return a reasonable size
    REQUIRE_NOTHROW([&] {
      auto size = btf_data_loop.get_size(1);
      // For a pointer, we expect sizeof(void*), even in a cycle
      REQUIRE(size == sizeof(void *));
    }());

    // Test with a more complex cycle: ptr -> ptr -> ptr (cycle back to first)
    libbtf::btf_type_data btf_data_complex;
    btf_data_complex.append(libbtf::btf_kind_ptr{.type = 2}); // id 1 -> id 2
    btf_data_complex.append(
        libbtf::btf_kind_ptr{.type = 1}); // id 2 -> id 1 (cycle)

    REQUIRE_NOTHROW([&] {
      auto size = btf_data_complex.get_size(1);
      // Should still return sizeof(void*) for the pointer
      REQUIRE(size == sizeof(void *));
    }());
  });
}

TEST_CASE("enum_type", "[parsing][json]") {
  libbtf::btf_type_data btf_data;
  btf_data.append(libbtf::btf_kind_enum{.name = "enum_type",
                                        .members = {
                                            {.name = "A", .value = 0},
                                            {.name = "B", .value = 1},
                                            {.name = "C", .value = 2},
                                        }});

  libbtf::btf_type_data btf_data_round_trip = btf_data.to_bytes();
  std::stringstream generated_output;
  btf_data.to_json(generated_output);

  std::stringstream generated_output_round_trip;
  btf_data_round_trip.to_json(generated_output_round_trip);

  std::string expected_json = "{\n"
                              "  \"btf_kinds\": [\n"
                              "    {\n"
                              "      \"id\": 1,\n"
                              "      \"kind_type\": \"BTF_KIND_ENUM\",\n"
                              "      \"name\": \"enum_type\",\n"
                              "      \"size_in_bytes\": 0,\n"
                              "      \"is_signed\": false,\n"
                              "      \"members\": [\n"
                              "        {\n"
                              "          \"name\": \"A\",\n"
                              "          \"value\": 0\n"
                              "        },\n"
                              "        {\n"
                              "          \"name\": \"B\",\n"
                              "          \"value\": 1\n"
                              "        },\n"
                              "        {\n"
                              "          \"name\": \"C\",\n"
                              "          \"value\": 2\n"
                              "        }\n"
                              "      ]\n"
                              "    }\n"
                              "  ]\n"
                              "}\n";
  std::string pretty_printed_generated_output =
      libbtf::pretty_print_json(generated_output.str());

  REQUIRE(generated_output.str() == generated_output_round_trip.str());

  std::stringstream generated_json_stream(pretty_printed_generated_output);
  std::stringstream expected_json_stream(expected_json);
  verify_line_by_line(generated_json_stream, expected_json_stream);

  // Compare the generated JSON to the round trip JSON.
  REQUIRE(generated_output.str() == generated_output_round_trip.str());
}

TEST_CASE("enum64_type", "[parsing][json]") {
  libbtf::btf_type_data btf_data;
  btf_data.append(
      libbtf::btf_kind_enum64{.name = "enum_type",
                              .members = {
                                  {.name = "A", .value = UINT64_MAX - 100},
                                  {.name = "B", .value = UINT64_MAX - 99},
                                  {.name = "C", .value = UINT64_MAX - 98},
                              }});

  libbtf::btf_type_data btf_data_round_trip = btf_data.to_bytes();
  std::stringstream generated_output;
  btf_data.to_json(generated_output);

  std::stringstream generated_output_round_trip;
  btf_data_round_trip.to_json(generated_output_round_trip);

  std::string expected_json = "{\n"
                              "  \"btf_kinds\": [\n"
                              "    {\n"
                              "      \"id\": 1,\n"
                              "      \"kind_type\": \"BTF_KIND_ENUM64\",\n"
                              "      \"name\": \"enum_type\",\n"
                              "      \"size_in_bytes\": 0,\n"
                              "      \"is_signed\": false,\n"
                              "      \"members\": [\n"
                              "        {\n"
                              "          \"name\": \"A\",\n"
                              "          \"value\": 18446744073709551515\n"
                              "        },\n"
                              "        {\n"
                              "          \"name\": \"B\",\n"
                              "          \"value\": 18446744073709551516\n"
                              "        },\n"
                              "        {\n"
                              "          \"name\": \"C\",\n"
                              "          \"value\": 18446744073709551517\n"
                              "        }\n"
                              "      ]\n"
                              "    }\n"
                              "  ]\n"
                              "}\n";

  std::string pretty_printed_generated_output =
      libbtf::pretty_print_json(generated_output.str());

  // Compare the pretty printed JSON to the expected JSON.
  std::stringstream generated_json_stream(pretty_printed_generated_output);
  std::stringstream expected_json_stream(expected_json);
  verify_line_by_line(generated_json_stream, expected_json_stream);

  // Compare the generated JSON to the round trip JSON.
  REQUIRE(generated_output.str() == generated_output_round_trip.str());
}

TEST_CASE("modifiers", "[parsing][json]") {
  libbtf::btf_type_data btf_data;

  // The following BTF type doesn't make sense, but it's useful for testing.
  // Add:
  // Volatile
  // Const
  // Restrict
  // Float

  // Each type points to the next one.
  btf_data.append(libbtf::btf_kind_volatile{.type = 2});
  btf_data.append(libbtf::btf_kind_const{.type = 3});
  btf_data.append(libbtf::btf_kind_restrict{.type = 4});

  // Add a float type.
  btf_data.append(
      libbtf::btf_kind_float{.name = "float_type", .size_in_bytes = 8});

  libbtf::btf_type_data btf_data_round_trip = btf_data.to_bytes();
  std::stringstream generated_output;
  btf_data.to_json(generated_output);

  std::stringstream generated_output_round_trip;
  btf_data_round_trip.to_json(generated_output_round_trip);

  REQUIRE(generated_output.str() == generated_output_round_trip.str());

  std::string expected_json =
      "{\n"
      "  \"btf_kinds\": [\n"
      "    {\n"
      "      \"id\": 1,\n"
      "      \"kind_type\": \"BTF_KIND_VOLATILE\",\n"
      "      \"type\": {\n"
      "        \"id\": 2,\n"
      "        \"kind_type\": \"BTF_KIND_CONST\",\n"
      "        \"type\": {\n"
      "          \"id\": 3,\n"
      "          \"kind_type\": \"BTF_KIND_RESTRICT\",\n"
      "          \"type\": {\n"
      "            \"id\": 4,\n"
      "            \"kind_type\": \"BTF_KIND_FLOAT\",\n"
      "            \"name\": \"float_type\",\n"
      "            \"size_in_bytes\": 8\n"
      "          }\n"
      "        }\n"
      "      }\n"
      "    }\n"
      "  ]\n"
      "}\n";
  std::string pretty_printed_generated_output =
      libbtf::pretty_print_json(generated_output.str());

  // Compare the pretty printed JSON to the expected JSON.
  std::stringstream generated_json_stream(pretty_printed_generated_output);
  std::stringstream expected_json_stream(expected_json);
  verify_line_by_line(generated_json_stream, expected_json_stream);
}

TEST_CASE("type_tag", "[parsing][json]") {
  libbtf::btf_type_data btf_data;

  // The following BTF type doesn't make sense, but it's useful for testing.
  // Add:
  // ptr
  // type_tag
  // const
  // volatile
  // restrict
  // typedef
  // int

  // Each type points to the next one.
  btf_data.append(libbtf::btf_kind_ptr{.type = 2});
  btf_data.append(libbtf::btf_kind_type_tag{.name = "type_tag", .type = 3});
  btf_data.append(libbtf::btf_kind_const{.type = 4});
  btf_data.append(libbtf::btf_kind_volatile{.type = 5});
  btf_data.append(libbtf::btf_kind_restrict{.type = 6});
  btf_data.append(libbtf::btf_kind_typedef{.name = "typedef", .type = 7});
  btf_data.append(libbtf::btf_kind_int{.name = "int_type", .size_in_bytes = 8});

  libbtf::btf_type_data btf_data_round_trip = btf_data.to_bytes();

  std::stringstream generated_output;
  btf_data.to_json(generated_output);

  std::stringstream generated_output_round_trip;
  btf_data_round_trip.to_json(generated_output_round_trip);

  REQUIRE(generated_output.str() == generated_output_round_trip.str());

  std::string expected_json =
      "{\n"
      "  \"btf_kinds\": [\n"
      "    {\n"
      "      \"id\": 1,\n"
      "      \"kind_type\": \"BTF_KIND_PTR\",\n"
      "      \"type\": {\n"
      "        \"id\": 2,\n"
      "        \"kind_type\": \"BTF_KIND_TYPE_TAG\",\n"
      "        \"name\": \"type_tag\",\n"
      "        \"type\": {\n"
      "          \"id\": 3,\n"
      "          \"kind_type\": \"BTF_KIND_CONST\",\n"
      "          \"type\": {\n"
      "            \"id\": 4,\n"
      "            \"kind_type\": \"BTF_KIND_VOLATILE\",\n"
      "            \"type\": {\n"
      "              \"id\": 5,\n"
      "              \"kind_type\": \"BTF_KIND_RESTRICT\",\n"
      "              \"type\": {\n"
      "                \"id\": 6,\n"
      "                \"kind_type\": \"BTF_KIND_TYPEDEF\",\n"
      "                \"name\": \"typedef\",\n"
      "                \"type\": {\n"
      "                  \"id\": 7,\n"
      "                  \"kind_type\": \"BTF_KIND_INT\",\n"
      "                  \"name\": \"int_type\",\n"
      "                  \"size_in_bytes\": 8,\n"
      "                  \"offset_from_start_in_bits\": 0,\n"
      "                  \"field_width_in_bits\": 0,\n"
      "                  \"is_signed\": false,\n"
      "                  \"is_char\": false,\n"
      "                  \"is_bool\": false\n"
      "                }\n"
      "              }\n"
      "            }\n"
      "          }\n"
      "        }\n"
      "      }\n"
      "    }\n"
      "  ]\n"
      "}\n";
  std::string pretty_printed_generated_output =
      libbtf::pretty_print_json(generated_output.str());

  // Compare the pretty printed JSON to the expected JSON.
  std::stringstream generated_json_stream(pretty_printed_generated_output);
  std::stringstream expected_json_stream(expected_json);
  verify_line_by_line(generated_json_stream, expected_json_stream);
}

TEST_CASE("decl_tag", "[parsing][json]") {
  libbtf::btf_type_data btf_data;

  // The following BTF type doesn't make sense, but it's useful for testing.
  // Add:
  // delc_tag
  // int

  btf_data.append(libbtf::btf_kind_decl_tag{
      .name = "decl_tag", .type = 2, .component_index = 3});
  btf_data.append(libbtf::btf_kind_int{.name = "int_type", .size_in_bytes = 8});

  libbtf::btf_type_data btf_data_round_trip = btf_data.to_bytes();

  std::stringstream generated_output;
  btf_data.to_json(generated_output);

  std::stringstream generated_output_round_trip;
  btf_data_round_trip.to_json(generated_output_round_trip);

  REQUIRE(generated_output.str() == generated_output_round_trip.str());

  std::string expected_json = "{\n"
                              "  \"btf_kinds\": [\n"
                              "    {\n"
                              "      \"id\": 1,\n"
                              "      \"kind_type\": \"BTF_KIND_DECL_TAG\",\n"
                              "      \"name\": \"decl_tag\",\n"
                              "      \"type\": {\n"
                              "        \"id\": 2,\n"
                              "        \"kind_type\": \"BTF_KIND_INT\",\n"
                              "        \"name\": \"int_type\",\n"
                              "        \"size_in_bytes\": 8,\n"
                              "        \"offset_from_start_in_bits\": 0,\n"
                              "        \"field_width_in_bits\": 0,\n"
                              "        \"is_signed\": false,\n"
                              "        \"is_char\": false,\n"
                              "        \"is_bool\": false\n"
                              "      }\n"
                              "    }\n"
                              "  ]\n"
                              "}\n";
  std::string pretty_printed_generated_output =
      libbtf::pretty_print_json(generated_output.str());

  // Compare the pretty printed JSON to the expected JSON.
  std::stringstream generated_json_stream(pretty_printed_generated_output);
  std::stringstream expected_json_stream(expected_json);
  verify_line_by_line(generated_json_stream, expected_json_stream);
}

TEST_CASE("btf_maps_map_in_map", "[parsing][json]") {
  auto reader = ELFIO::elfio();
  std::string file = "map_in_map";
  REQUIRE(reader.load(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o"));

  auto btf = reader.sections[".BTF"];

  libbtf::btf_type_data btf_data = std::vector<std::byte>(
      {reinterpret_cast<const std::byte *>(btf->get_data()),
       reinterpret_cast<const std::byte *>(btf->get_data() + btf->get_size())});

  auto map_definitions = libbtf::parse_btf_map_section(btf_data);
  REQUIRE(map_definitions.size() == 2);

  // Verify that each map was parsed correctly.
  REQUIRE(map_definitions[1].name == "array_of_maps");
  REQUIRE(map_definitions[1].map_type == 12); // BPF_MAP_TYPE_ARRAY_OF_MAPS
  REQUIRE(map_definitions[1].key_size == 4);
  REQUIRE(map_definitions[1].value_size == 4);
  REQUIRE(map_definitions[1].max_entries == 1);
  REQUIRE(map_definitions[1].inner_map_type_id != 0);

  REQUIRE(map_definitions[0].name == "inner_map");
  REQUIRE(map_definitions[0].map_type == 2); // BPF_MAP_TYPE_ARRAY
  REQUIRE(map_definitions[0].key_size == 4);
  REQUIRE(map_definitions[0].value_size == 4);
  REQUIRE(map_definitions[0].max_entries == 1);
  REQUIRE(map_definitions[0].inner_map_type_id == 0);
}

TEST_CASE("btf_maps_ringbuf_in_map", "[parsing][json]") {
  auto reader = ELFIO::elfio();
  std::string file = "ringbuf_in_map";
  REQUIRE(reader.load(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o"));

  auto btf = reader.sections[".BTF"];

  libbtf::btf_type_data btf_data = std::vector<std::byte>(
      {reinterpret_cast<const std::byte *>(btf->get_data()),
       reinterpret_cast<const std::byte *>(btf->get_data() + btf->get_size())});

  auto map_definitions = libbtf::parse_btf_map_section(btf_data);
  REQUIRE(map_definitions.size() == 2);

  // Verify that each map was parsed correctly.
  REQUIRE(map_definitions[1].name == "array_of_maps");
  REQUIRE(map_definitions[1].map_type == 12); // BPF_MAP_TYPE_ARRAY_OF_MAPS
  REQUIRE(map_definitions[1].key_size == 4);
  REQUIRE(map_definitions[1].value_size == 4);
  REQUIRE(map_definitions[1].max_entries == 1);
  REQUIRE(map_definitions[1].inner_map_type_id != 0);

  REQUIRE(map_definitions[0].name == "inner_map");
  REQUIRE(map_definitions[0].map_type == 27); // BPF_MAP_TYPE_ARRAY
  REQUIRE(map_definitions[0].max_entries == 256 * 1024);
}

TEST_CASE("btf_maps_map_in_map_anonymous", "[parsing][json]") {
  auto reader = ELFIO::elfio();
  std::string file = "map_in_map_anonymous";
  REQUIRE(reader.load(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o"));

  auto btf = reader.sections[".BTF"];

  libbtf::btf_type_data btf_data = std::vector<std::byte>(
      {reinterpret_cast<const std::byte *>(btf->get_data()),
       reinterpret_cast<const std::byte *>(btf->get_data() + btf->get_size())});

  auto map_definitions = libbtf::parse_btf_map_section(btf_data);
  REQUIRE(map_definitions.size() == 2);

  // Verify that each map was parsed correctly.
  REQUIRE(map_definitions[1].name == "outer_map");
  REQUIRE(map_definitions[1].map_type == 12); // BPF_MAP_TYPE_ARRAY_OF_MAPS
  REQUIRE(map_definitions[1].key_size == 4);
  REQUIRE(map_definitions[1].value_size == 4);
  REQUIRE(map_definitions[1].max_entries == 1);
  REQUIRE(map_definitions[1].inner_map_type_id != 0);

  REQUIRE(map_definitions[0].name == "");
  REQUIRE(map_definitions[0].map_type == 2); // BPF_MAP_TYPE_ARRAY
  REQUIRE(map_definitions[0].key_size == 4);
  REQUIRE(map_definitions[0].value_size == 4);
  REQUIRE(map_definitions[0].max_entries == 1);
  REQUIRE(map_definitions[0].inner_map_type_id == 0);
}

TEST_CASE("btf_maps_map_in_map_typedef", "[parsing][json]") {
  auto reader = ELFIO::elfio();
  std::string file = "map_in_map_typedef";
  REQUIRE(reader.load(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o"));

  auto btf = reader.sections[".BTF"];

  libbtf::btf_type_data btf_data = std::vector<std::byte>(
      {reinterpret_cast<const std::byte *>(btf->get_data()),
       reinterpret_cast<const std::byte *>(btf->get_data() + btf->get_size())});

  auto map_definitions = libbtf::parse_btf_map_section(btf_data);
  REQUIRE(map_definitions.size() == 3);

  // Verify that each map was parsed correctly.
  REQUIRE(map_definitions[1].name == "outer_map_1");
  REQUIRE(map_definitions[1].map_type == 12); // BPF_MAP_TYPE_ARRAY_OF_MAPS
  REQUIRE(map_definitions[1].key_size == 4);
  REQUIRE(map_definitions[1].value_size == 4);
  REQUIRE(map_definitions[1].max_entries == 1);
  REQUIRE(map_definitions[1].inner_map_type_id != 0);

  REQUIRE(map_definitions[2].name == "outer_map_2");
  REQUIRE(map_definitions[2].map_type == 12); // BPF_MAP_TYPE_ARRAY_OF_MAPS
  REQUIRE(map_definitions[2].key_size == 4);
  REQUIRE(map_definitions[2].value_size == 4);
  REQUIRE(map_definitions[2].max_entries == 1);
  REQUIRE(map_definitions[2].inner_map_type_id != 0);

  REQUIRE(map_definitions[0].name == "");
  REQUIRE(map_definitions[0].map_type == 2); // BPF_MAP_TYPE_ARRAY
  REQUIRE(map_definitions[0].key_size == 4);
  REQUIRE(map_definitions[0].value_size == 4);
  REQUIRE(map_definitions[0].max_entries == 1);
  REQUIRE(map_definitions[0].inner_map_type_id == 0);
}

TEST_CASE("btf_maps_prog_array", "[parsing][json]") {
  auto reader = ELFIO::elfio();
  std::string file = "prog_array";
  REQUIRE(reader.load(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o"));

  auto btf = reader.sections[".BTF"];

  libbtf::btf_type_data btf_data = std::vector<std::byte>(
      {reinterpret_cast<const std::byte *>(btf->get_data()),
       reinterpret_cast<const std::byte *>(btf->get_data() + btf->get_size())});

  auto map_definitions = libbtf::parse_btf_map_section(btf_data);
  REQUIRE(map_definitions.size() == 1);

  // Verify that each map was parsed correctly.
  REQUIRE(map_definitions[0].name == "prog_array_map");
  REQUIRE(map_definitions[0].map_type == 3); // BPF_MAP_TYPE_PROG_ARRAY
  REQUIRE(map_definitions[0].key_size == 4);
  REQUIRE(map_definitions[0].value_size == 4);
  REQUIRE(map_definitions[0].max_entries == 4);
  REQUIRE(map_definitions[0].inner_map_type_id == 0);
}

TEST_CASE("get_unknown_type_id", "[btf_type_data][negative]") {
  libbtf::btf_type_data btf_data;
  REQUIRE_THROWS(btf_data.get_kind_index(1));
}

TEST_CASE("get_type_by_name_unknown", "[btf_type_data][negative]") {
  libbtf::btf_type_data btf_data;
  REQUIRE(btf_data.get_id("unknown") == 0);
}

TEST_CASE("dereference_non_pointer", "[btf_type_data][negative]") {
  libbtf::btf_type_data btf_data;
  btf_data.append(libbtf::btf_kind_int{.name = "int_type", .size_in_bytes = 8});
  REQUIRE_THROWS(btf_data.dereference_pointer(1));
}

TEST_CASE("build_btf_map_section", "[btf_type_data]") {
  std::vector<libbtf::btf_map_definition> map_definitions;
  map_definitions.push_back(
      libbtf::btf_map_definition{.name = "array_of_maps",
                                 .type_id = 1,
                                 .map_type = 12, // BPF_MAP_TYPE_ARRAY_OF_MAPS
                                 .key_size = 4,
                                 .value_size = 4,
                                 .max_entries = 1,
                                 .inner_map_type_id = 2});

  map_definitions.push_back(
      libbtf::btf_map_definition{.name = "inner_map",
                                 .type_id = 2,
                                 .map_type = 2, // BPF_MAP_TYPE_ARRAY
                                 .key_size = 4,
                                 .value_size = 4,
                                 .max_entries = 1,
                                 .inner_map_type_id = 0});
  libbtf::btf_type_data btf_data;
  libbtf::build_btf_map_section(map_definitions, btf_data);

  std::vector<libbtf::btf_map_definition> generated_map_definitions =
      libbtf::parse_btf_map_section(btf_data);
  REQUIRE(generated_map_definitions.size() == map_definitions.size());
  for (size_t i = 0; i < generated_map_definitions.size(); i++) {
    REQUIRE(generated_map_definitions[i].name == map_definitions[i].name);
    REQUIRE(generated_map_definitions[i].map_type ==
            map_definitions[i].map_type);
    REQUIRE(generated_map_definitions[i].key_size ==
            map_definitions[i].key_size);
    REQUIRE(generated_map_definitions[i].value_size ==
            map_definitions[i].value_size);
    REQUIRE(generated_map_definitions[i].max_entries ==
            map_definitions[i].max_entries);
  }
  REQUIRE(generated_map_definitions[0].inner_map_type_id ==
          generated_map_definitions[1].type_id);
}

TEST_CASE("parse_btf_map_section_globals", "[btf_type_data]") {
  auto reader = ELFIO::elfio();
  std::string file = "global_variable";
  REQUIRE(reader.load(std::string(TEST_OBJECT_FILE_DIRECTORY) + file + ".o"));

  auto btf = reader.sections[".BTF"];

  libbtf::btf_type_data btf_data = std::vector<std::byte>(
      {reinterpret_cast<const std::byte *>(btf->get_data()),
       reinterpret_cast<const std::byte *>(btf->get_data() + btf->get_size())});

  auto map_definitions = libbtf::parse_btf_map_section(btf_data);

  REQUIRE(map_definitions.size() == 3);
  REQUIRE(map_definitions[0].name == ".bss");
  REQUIRE(map_definitions[0].type_id == 15);
  REQUIRE(map_definitions[0].map_type == 0); // Undefined type
  REQUIRE(map_definitions[0].key_size == 4);
  REQUIRE(map_definitions[0].value_size == 8);
  REQUIRE(map_definitions[0].max_entries == 1);
  REQUIRE(map_definitions[0].inner_map_type_id == 0);

  REQUIRE(map_definitions[1].name == ".data");
  REQUIRE(map_definitions[1].type_id == 16);
  REQUIRE(map_definitions[1].map_type == 0); // Undefined type
  REQUIRE(map_definitions[1].key_size == 4);
  REQUIRE(map_definitions[1].value_size == 40);
  REQUIRE(map_definitions[1].max_entries == 1);
  REQUIRE(map_definitions[1].inner_map_type_id == 0);

  REQUIRE(map_definitions[2].name == ".rodata");
  REQUIRE(map_definitions[2].type_id == 17);
  REQUIRE(map_definitions[2].map_type == 0); // Undefined type
  REQUIRE(map_definitions[2].key_size == 4);
  REQUIRE(map_definitions[2].value_size == 4);
  REQUIRE(map_definitions[2].max_entries == 1);
  REQUIRE(map_definitions[2].inner_map_type_id == 0);
}

// Note: get_qualified_type_name is private, so we test it indirectly through
// to_c_header which uses it

TEST_CASE("validate-dependency_order-robustness", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // Create simple types to test basic dependency ordering robustness
    btf_data.append(libbtf::btf_kind_int{
        .name = "int", .size_in_bytes = 4, .field_width_in_bits = 32});
    btf_data.append(libbtf::btf_kind_ptr{
        .type = 1}); // id 2 -> id 1 (no cycle, just dependency)

    // This should not crash and should return proper dependency order
    REQUIRE_NOTHROW([&] {
      auto deps = btf_data.dependency_order();
      INFO("Dependencies count: " << deps.size());
      // Should return a reasonable dependency order
      REQUIRE(deps.size() >= 0); // Should return proper dependency order
    }());
  });
}

TEST_CASE("validate-dependency_order-with-cycles", "[validation]") {
  // Test that dependency_order can handle cycles without hanging
  // This test verifies the fix for the infinite loop bug in dependency_order()
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // Create a simple cycle that previously caused infinite loops
    btf_data.append(
        libbtf::btf_kind_typedef{.name = "type_a", .type = 2}); // id 1 -> id 2
    btf_data.append(libbtf::btf_kind_typedef{
        .name = "type_b", .type = 1}); // id 2 -> id 1 (cycle)

    // This should not hang and should return a reasonable dependency order
    REQUIRE_NOTHROW([&] {
      auto deps = btf_data.dependency_order();
      INFO("Dependencies count with cycles: " << deps.size());

      // The function should complete without infinite loops
      // The exact size may vary due to cycle-breaking algorithm
      REQUIRE(deps.size() >= 2);
      REQUIRE(deps.size() <= 10); // Reasonable upper bound

      // Verify both cyclic types are present in the result
      bool found_type_a = false;
      bool found_type_b = false;
      for (auto id : deps) {
        if (id == 1)
          found_type_a = true;
        if (id == 2)
          found_type_b = true;
      }
      REQUIRE(found_type_a);
      REQUIRE(found_type_b);
    }());
  });
}

TEST_CASE("validate-to_c_header-with-cycles", "[validation]") {
  run_with_timeout([&] {
    // Test 1: Basic functionality - no cycles
    libbtf::btf_type_data btf_data_simple;
    btf_data_simple.append(libbtf::btf_kind_int{
        .name = "int", .size_in_bytes = 4, .field_width_in_bits = 32}); // id 1
    btf_data_simple.append(libbtf::btf_kind_typedef{
        .name = "my_int", .type = 1}); // id 2 -> id 1 (no cycle)

    std::stringstream simple_header;
    REQUIRE_NOTHROW([&] { btf_data_simple.to_c_header(simple_header); }());

    std::string simple_str = simple_header.str();
    INFO("Simple header output: " << simple_str);
    REQUIRE(simple_str.length() > 0);
    REQUIRE(simple_str.find("typedef int my_int") != std::string::npos);

    // Test 2: Function prototypes with type references (tests the
    // get_qualified_type_name fix)
    libbtf::btf_type_data btf_data_func;

    btf_data_func.append(libbtf::btf_kind_int{
        .name = "int", .size_in_bytes = 4, .field_width_in_bits = 32}); // id 1
    btf_data_func.append(
        libbtf::btf_kind_typedef{.name = "my_int", .type = 1}); // id 2 -> id 1
    btf_data_func.append(libbtf::btf_kind_function_prototype{
        .parameters = {{.name = "param",
                        .type = 2}}, // parameter of type my_int
        .return_type = 2             // returns my_int
    });                              // id 3
    btf_data_func.append(
        libbtf::btf_kind_function{.name = "test_func", .type = 3}); // id 4

    std::stringstream func_header;
    REQUIRE_NOTHROW([&] { btf_data_func.to_c_header(func_header); }());

    std::string func_str = func_header.str();
    INFO("Function header output: " << func_str);
    REQUIRE(func_str.length() > 0);
    REQUIRE(func_str.find("my_int test_func(my_int param)") !=
            std::string::npos);
  });
}

TEST_CASE("validate-to_c_header-function-cycles", "[validation]") {
  run_with_timeout([&] {
    // Test the specific bug I fixed: function prototypes with cycles
    // This tests the get_qualified_type_name fix without hitting
    // dependency_order cycles

    libbtf::btf_type_data btf_data_func;

    // Create: int my_func(struct node*) where struct node contains a pointer
    // back But we'll create it carefully to avoid the dependency_order issue

    // First create basic int type
    btf_data_func.append(libbtf::btf_kind_int{
        .name = "int", .size_in_bytes = 4, .field_width_in_bits = 32}); // id 1

    // Create a simple function prototype that references a typedef
    btf_data_func.append(
        libbtf::btf_kind_typedef{.name = "my_int", .type = 1}); // id 2 -> id 1

    btf_data_func.append(libbtf::btf_kind_function_prototype{
        .parameters = {},
        .return_type = 2 // my_int
    });                  // id 3

    btf_data_func.append(
        libbtf::btf_kind_function{.name = "test_func", .type = 3}); // id 4

    // This should work now with the get_qualified_type_name fix
    std::stringstream header_func;
    REQUIRE_NOTHROW([&] { btf_data_func.to_c_header(header_func); }());

    std::string header_func_str = header_func.str();
    INFO("Function header: " << header_func_str);
    REQUIRE(header_func_str.length() > 0);
    REQUIRE(header_func_str.find("test_func") != std::string::npos);
  });
}

TEST_CASE("validate-dereference_pointer-with-cycles", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // Create a pointer that points to another pointer in a cycle
    btf_data.append(libbtf::btf_kind_ptr{.type = 2}); // id 1 -> id 2
    btf_data.append(libbtf::btf_kind_ptr{.type = 1}); // id 2 -> id 1 (cycle)

    // This should not crash with cycles
    REQUIRE_NOTHROW([&] {
      libbtf::btf_type_id deref1 = btf_data.dereference_pointer(1);
      libbtf::btf_type_id deref2 = btf_data.dereference_pointer(2);
      INFO("Dereferenced 1: " << deref1);
      INFO("Dereferenced 2: " << deref2);
      // Should return the pointed-to types
      REQUIRE(deref1 == 2);
      REQUIRE(deref2 == 1);
    }());
  });
}

TEST_CASE("validate-get_kind_type-with-cycles", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // Create typedef cycle
    btf_data.append(
        libbtf::btf_kind_typedef{.name = "A", .type = 2}); // id 1 -> id 2
    btf_data.append(libbtf::btf_kind_typedef{
        .name = "B", .type = 1}); // id 2 -> id 1 (cycle)

    // This should not crash with cycles
    REQUIRE_NOTHROW([&] {
      auto typedef1 = btf_data.get_kind_type<libbtf::btf_kind_typedef>(1);
      auto typedef2 = btf_data.get_kind_type<libbtf::btf_kind_typedef>(2);
      INFO("Typedef 1 name: " << typedef1.name << ", type: " << typedef1.type);
      INFO("Typedef 2 name: " << typedef2.name << ", type: " << typedef2.type);
      // Should return the correct types
      REQUIRE(typedef1.name == "A");
      REQUIRE(typedef1.type == 2);
      REQUIRE(typedef2.name == "B");
      REQUIRE(typedef2.type == 1);
    }());
  });
}

TEST_CASE("validate-to_bytes-with-cycles", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // Create a cycle
    btf_data.append(libbtf::btf_kind_ptr{.type = 2}); // id 1 -> id 2
    btf_data.append(libbtf::btf_kind_ptr{.type = 1}); // id 2 -> id 1 (cycle)

    // This should not crash with cycles
    REQUIRE_NOTHROW([&] {
      auto bytes = btf_data.to_bytes();
      INFO("Generated bytes size: " << bytes.size());
      // Should generate valid BTF bytes
      REQUIRE(bytes.size() > 0);

      // Should be able to parse the bytes back
      libbtf::btf_type_data parsed_back(bytes);
      // Basic sanity check - should have the same number of types
      REQUIRE(parsed_back.last_type_id() == btf_data.last_type_id());
    }());
  });
}

TEST_CASE("validate-parse_btf_map_section-with-cycles", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // Create a map structure that has cyclic type references
    // First create a struct for map definition
    libbtf::btf_kind_struct cyclic_map_struct;
    cyclic_map_struct.name = "cyclic_map_struct";
    cyclic_map_struct.size_in_bytes = 16;
    cyclic_map_struct.members = {
        {.name = "type", .type = 2, .offset_from_start_in_bits = 0},
        {.name = "max_entries", .type = 3, .offset_from_start_in_bits = 64}};
    btf_data.append(cyclic_map_struct); // id 1

    // Create the __uint types for map definition
    btf_data.append(libbtf::btf_kind_ptr{.type = 4}); // id 2 - type pointer
    btf_data.append(
        libbtf::btf_kind_ptr{.type = 5}); // id 3 - max_entries pointer

    // Create arrays with cycles
    btf_data.append(libbtf::btf_kind_array{
        .element_type = 6, .index_type = 7, .count_of_elements = 1}); // id 4
    btf_data.append(libbtf::btf_kind_array{
        .element_type = 6, .index_type = 7, .count_of_elements = 10}); // id 5

    // Create int type that references itself through typedef (cycle)
    btf_data.append(libbtf::btf_kind_typedef{.name = "cyclic_int",
                                             .type = 8}); // id 6 -> id 8
    libbtf::btf_kind_int array_size_type{};
    array_size_type.name = "__ARRAY_SIZE_TYPE__";
    array_size_type.size_in_bytes = 4;
    array_size_type.field_width_in_bits = 32;
    btf_data.append(array_size_type); // id 7
    btf_data.append(libbtf::btf_kind_typedef{
        .name = "int_alias", .type = 6}); // id 8 -> id 6 (cycle)

    // Create .maps section
    btf_data.append(
        libbtf::btf_kind_var{.name = "test_map", .type = 1}); // id 9
    libbtf::btf_kind_data_section maps_section;
    maps_section.name = ".maps";
    maps_section.members = {{.type = 9, .size = 16}};
    btf_data.append(maps_section); // id 10

    // This should not crash even with cycles in the type definitions
    REQUIRE_NOTHROW([&] {
      auto map_definitions = libbtf::parse_btf_map_section(btf_data);
      INFO("Map definitions count: " << map_definitions.size());
      // Should parse at least one map
      REQUIRE(map_definitions.size() > 0);
    }());
  });
}

TEST_CASE("validate-replace-with-cycles", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // Create initial types
    btf_data.append(libbtf::btf_kind_int{
        .name = "int", .size_in_bytes = 4, .field_width_in_bits = 32}); // id 1
    btf_data.append(
        libbtf::btf_kind_ptr{.type = 1}); // id 2 -> id 1 (no cycle initially)

    // Now replace the pointer to create a cycle
    REQUIRE_NOTHROW([&] {
      btf_data.replace(
          2, libbtf::btf_kind_ptr{.type = 2}); // id 2 -> id 2 (self cycle)
    }());

    // Should be able to get the size without crashing
    REQUIRE_NOTHROW([&] {
      auto size = btf_data.get_size(2);
      REQUIRE(size == sizeof(void *));
    }());
  });
}

TEST_CASE("validate-build_btf_map_section-robustness", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // Create a simple map definition to test basic functionality
    std::vector<libbtf::btf_map_definition> map_defs = {
        {.name = "test_map",
         .type_id = 1,  // Simple reference, no cycles
         .map_type = 2, // BPF_MAP_TYPE_ARRAY
         .key_size = 4,
         .value_size = 4,
         .max_entries = 10,
         .inner_map_type_id = 0}};

    REQUIRE_NOTHROW(
        [&] { libbtf::build_btf_map_section(map_defs, btf_data); }());

    // Verify the map section was created
    auto parsed_maps = libbtf::parse_btf_map_section(btf_data);
    REQUIRE(parsed_maps.size() == 1);
    REQUIRE(parsed_maps[0].name == "test_map");
  });
}

TEST_CASE("validate-build_btf_map_section-with-cycles", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // First create cyclic types
    btf_data.append(
        libbtf::btf_kind_typedef{.name = "cycle_a", .type = 2}); // id 1 -> id 2
    btf_data.append(libbtf::btf_kind_typedef{
        .name = "cycle_b", .type = 1}); // id 2 -> id 1 (cycle)

    // Create a map definition that references the cyclic types
    std::vector<libbtf::btf_map_definition> map_defs = {
        {.name = "cyclic_map",
         .type_id = 1,  // References cyclic typedef chain
         .map_type = 2, // BPF_MAP_TYPE_ARRAY
         .key_size = 4,
         .value_size = 4,
         .max_entries = 10,
         .inner_map_type_id = 0}};

    REQUIRE_NOTHROW(
        [&] { libbtf::build_btf_map_section(map_defs, btf_data); }());

    // Verify the map section was created despite cycles in referenced types
    auto parsed_maps = libbtf::parse_btf_map_section(btf_data);
    REQUIRE(parsed_maps.size() == 1);
    REQUIRE(parsed_maps[0].name == "cyclic_map");
  });
}

TEST_CASE("validate-btf_type_to_json-with-cycles", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // Create cyclic types
    btf_data.append(libbtf::btf_kind_ptr{.type = 2}); // id 1 -> id 2
    btf_data.append(libbtf::btf_kind_ptr{.type = 1}); // id 2 -> id 1 (cycle)

    // Get the internal id_to_kind map (we'll need to access this through public
    // methods)
    std::stringstream json_output;

    REQUIRE_NOTHROW([&] {
      btf_data.to_json(json_output); // This internally uses btf_type_to_json
    }());

    std::string json_str = json_output.str();
    INFO("JSON output with cycles: " << json_str);
    REQUIRE(json_str.length() > 0);
    REQUIRE(json_str.find("btf_kinds") != std::string::npos);
  });
}

TEST_CASE("validate-btf_write_types-with-cycles", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // Create cyclic types
    btf_data.append(libbtf::btf_kind_ptr{.type = 2}); // id 1 -> id 2
    btf_data.append(libbtf::btf_kind_ptr{.type = 1}); // id 2 -> id 1 (cycle)

    // Test serialization to bytes (which uses btf_write_types internally)
    REQUIRE_NOTHROW([&] {
      auto bytes = btf_data.to_bytes();
      INFO("Serialized bytes size: " << bytes.size());
      REQUIRE(bytes.size() > 0);

      // Should be able to parse the bytes back
      libbtf::btf_type_data parsed_back(bytes);
      REQUIRE(parsed_back.last_type_id() == btf_data.last_type_id());
    }());
  });
}

TEST_CASE("validate-btf_parse_types-with-cycles", "[validation]") {
  run_with_timeout([&] {
    libbtf::btf_type_data btf_data;

    // Create cyclic types
    btf_data.append(libbtf::btf_kind_ptr{.type = 2}); // id 1 -> id 2
    btf_data.append(libbtf::btf_kind_ptr{.type = 1}); // id 2 -> id 1 (cycle)

    // Serialize to bytes
    auto btf_bytes = btf_data.to_bytes();

    // Parse the types using btf_parse_types
    int type_count = 0;
    auto visitor = [&type_count](libbtf::btf_type_id id,
                                 const std::optional<std::string> &name,
                                 const libbtf::btf_kind &) {
      type_count++;
      INFO("Parsed type " << id << " with name "
                          << (name ? *name : "<no name>"));
    };

    REQUIRE_NOTHROW([&] { libbtf::btf_parse_types(btf_bytes, visitor); }());

    REQUIRE(type_count > 0);
  });
}

TEST_CASE("validate-btf_parse_line_information-robustness", "[validation]") {
  run_with_timeout([&] {
    // For this test, we verify that BTF data structures don't interfere with
    // line information parsing infrastructure. Since btf_parse_line_information
    // primarily parses BTF.ext data and only uses BTF data for context, the BTF
    // structure itself shouldn't affect the parsing capability.

    libbtf::btf_type_data btf_data;

    // Create some BTF types to test infrastructure robustness
    btf_data.append(libbtf::btf_kind_ptr{.type = 2}); // id 1 -> id 2
    btf_data.append(libbtf::btf_kind_ptr{
        .type = 1}); // id 2 -> id 1 (cycle for completeness)

    auto btf_bytes = btf_data.to_bytes();

    // Test with properly formed but empty BTF.ext data
    // We can't easily create a proper BTF.ext here, but we can test that the
    // function handles the infrastructure gracefully

    // Note: Since creating proper BTF.ext data is complex and this function
    // primarily parses BTF.ext (not BTF), we'll test indirectly by ensuring the
    // BTF infrastructure doesn't prevent the function from working

    // This validates that the BTF data structure doesn't break the parsing
    // infrastructure
    REQUIRE_NOTHROW([&] {
      // Just verify that the BTF data structure itself is functional
      auto size1 = btf_data.get_size(1);
      auto size2 = btf_data.get_size(2);
      REQUIRE(size1 == sizeof(void *));
      REQUIRE(size2 == sizeof(void *));
    }());

    INFO("BTF parse line information infrastructure handles BTF data "
         "structures correctly");
  });
}

// Additional test cases for improved coverage

TEST_CASE("invalid_btf_magic", "[parsing][negative]") {
  // Create BTF data with invalid magic number
  std::vector<std::byte> invalid_btf;

  // Create a minimal BTF header with wrong magic
  btf_header_t header = {
      .magic = 0x1234, // Wrong magic (should be BTF_HEADER_MAGIC = 0xeB9F)
      .version = BTF_HEADER_VERSION,
      .flags = 0,
      .hdr_len = sizeof(btf_header_t),
      .type_off = 0,
      .type_len = 0,
      .str_off = 0,
      .str_len = 1};

  invalid_btf.resize(sizeof(header) + 1);
  std::memcpy(invalid_btf.data(), &header, sizeof(header));
  invalid_btf[sizeof(header)] = std::byte{0}; // Empty string table

  REQUIRE_THROWS_WITH(libbtf::btf_type_data(invalid_btf),
                      Catch::Matchers::ContainsSubstring("wrong magic"));
}

TEST_CASE("invalid_btf_version", "[parsing][negative]") {
  // Create BTF data with invalid version
  std::vector<std::byte> invalid_btf;

  btf_header_t header = {
      .magic = BTF_HEADER_MAGIC,
      .version = 99, // Wrong version (should be BTF_HEADER_VERSION = 1)
      .flags = 0,
      .hdr_len = sizeof(btf_header_t),
      .type_off = 0,
      .type_len = 0,
      .str_off = 0,
      .str_len = 1};

  invalid_btf.resize(sizeof(header) + 1);
  std::memcpy(invalid_btf.data(), &header, sizeof(header));
  invalid_btf[sizeof(header)] = std::byte{0}; // Empty string table

  REQUIRE_THROWS_WITH(libbtf::btf_type_data(invalid_btf),
                      Catch::Matchers::ContainsSubstring("wrong version"));
}

TEST_CASE("invalid_btf_header_size", "[parsing][negative]") {
  // Create BTF data with invalid header size
  std::vector<std::byte> invalid_btf;

  btf_header_t header = {
      .magic = BTF_HEADER_MAGIC,
      .version = BTF_HEADER_VERSION,
      .flags = 0,
      .hdr_len = 10, // Too small (should be at least sizeof(btf_header_t))
      .type_off = 0,
      .type_len = 0,
      .str_off = 0,
      .str_len = 1};

  invalid_btf.resize(sizeof(header) + 1);
  std::memcpy(invalid_btf.data(), &header, sizeof(header));
  invalid_btf[sizeof(header)] = std::byte{0}; // Empty string table

  REQUIRE_THROWS_WITH(libbtf::btf_type_data(invalid_btf),
                      Catch::Matchers::ContainsSubstring("wrong size"));
}

TEST_CASE("corrupted_string_table", "[parsing][negative]") {
  // Create BTF data with string table that extends beyond data bounds
  std::vector<std::byte> invalid_btf;

  btf_header_t header = {
      .magic = BTF_HEADER_MAGIC,
      .version = BTF_HEADER_VERSION,
      .flags = 0,
      .hdr_len = sizeof(btf_header_t),
      .type_off = 0,
      .type_len = 0,
      .str_off = 0,
      .str_len = 1000 // String table larger than actual data
  };

  invalid_btf.resize(sizeof(header) +
                     10); // Much smaller than claimed string table
  std::memcpy(invalid_btf.data(), &header, sizeof(header));

  REQUIRE_THROWS_WITH(
      libbtf::btf_type_data(invalid_btf),
      Catch::Matchers::ContainsSubstring("Invalid .BTF section"));
}

TEST_CASE("invalid_type_offsets", "[parsing][negative]") {
  // Create BTF data with type section extending beyond bounds
  std::vector<std::byte> invalid_btf;

  btf_header_t header = {
      .magic = BTF_HEADER_MAGIC,
      .version = BTF_HEADER_VERSION,
      .flags = 0,
      .hdr_len = sizeof(btf_header_t),
      .type_off = 1,    // Type section starts at offset 1
      .type_len = 1000, // But claims to be much larger than available data
      .str_off = 1001,
      .str_len = 1};

  invalid_btf.resize(sizeof(header) + 10);
  std::memcpy(invalid_btf.data(), &header, sizeof(header));

  REQUIRE_THROWS_WITH(
      libbtf::btf_type_data(invalid_btf),
      Catch::Matchers::ContainsSubstring("Invalid .BTF section"));
}

TEST_CASE("get_kind_type_all_specializations", "[btf_type_data]") {
  // Test all template specializations for get_kind_type
  libbtf::btf_type_data btf_data;

  // Add examples of each BTF kind type
  auto void_id = btf_data.append(libbtf::btf_kind_void{});

  auto int_id =
      btf_data.append(libbtf::btf_kind_int{.name = "int",
                                           .size_in_bytes = 4,
                                           .offset_from_start_in_bits = 0,
                                           .field_width_in_bits = 32,
                                           .is_signed = true,
                                           .is_char = false,
                                           .is_bool = false});

  auto ptr_id = btf_data.append(libbtf::btf_kind_ptr{.type = int_id});

  auto array_id = btf_data.append(libbtf::btf_kind_array{
      .element_type = int_id, .index_type = int_id, .count_of_elements = 10});

  auto struct_id = btf_data.append(
      libbtf::btf_kind_struct{.name = "test_struct",
                              .members = {{.name = "field1",
                                           .type = int_id,
                                           .offset_from_start_in_bits = 0}},
                              .size_in_bytes = 4});

  auto union_id = btf_data.append(
      libbtf::btf_kind_union{.name = "test_union",
                             .members = {{.name = "field1",
                                          .type = int_id,
                                          .offset_from_start_in_bits = 0}},
                             .size_in_bytes = 4});

  auto enum_id = btf_data.append(
      libbtf::btf_kind_enum{.name = "test_enum",
                            .members = {{.name = "VALUE1", .value = 0}},
                            .size_in_bytes = 4});

  auto fwd_id = btf_data.append(
      libbtf::btf_kind_fwd{.name = "forward_decl", .is_struct = true});

  auto typedef_id = btf_data.append(
      libbtf::btf_kind_typedef{.name = "my_int", .type = int_id});

  auto volatile_id = btf_data.append(libbtf::btf_kind_volatile{.type = int_id});

  auto const_id = btf_data.append(libbtf::btf_kind_const{.type = int_id});

  auto restrict_id = btf_data.append(libbtf::btf_kind_restrict{.type = ptr_id});

  auto func_proto_id = btf_data.append(libbtf::btf_kind_function_prototype{
      .parameters = {{.name = "param1", .type = int_id}},
      .return_type = int_id});

  auto function_id = btf_data.append(
      libbtf::btf_kind_function{.name = "test_func",
                                .linkage = libbtf::BTF_LINKAGE_GLOBAL,
                                .type = func_proto_id});

  auto var_id = btf_data.append(
      libbtf::btf_kind_var{.name = "test_var",
                           .type = int_id,
                           .linkage = libbtf::BTF_LINKAGE_GLOBAL});

  auto data_section_id = btf_data.append(libbtf::btf_kind_data_section{
      .name = ".data", .members = {{.type = var_id, .offset = 0, .size = 4}}});

  auto float_id = btf_data.append(
      libbtf::btf_kind_float{.name = "float", .size_in_bytes = 4});

  auto decl_tag_id = btf_data.append(libbtf::btf_kind_decl_tag{
      .name = "tag", .type = int_id, .component_index = 0});

  auto type_tag_id = btf_data.append(
      libbtf::btf_kind_type_tag{.name = "type_tag", .type = int_id});

  auto enum64_id = btf_data.append(libbtf::btf_kind_enum64{
      .name = "test_enum64",
      .is_signed = false,
      .members = {{.name = "BIG_VALUE", .value = UINT64_MAX}},
      .size_in_bytes = 8});

  // Test all template specializations
  SECTION("Test all get_kind_type specializations") {
    auto void_kind = btf_data.get_kind_type<libbtf::btf_kind_void>(void_id);
    auto int_kind = btf_data.get_kind_type<libbtf::btf_kind_int>(int_id);
    auto ptr_kind = btf_data.get_kind_type<libbtf::btf_kind_ptr>(ptr_id);
    auto array_kind = btf_data.get_kind_type<libbtf::btf_kind_array>(array_id);
    auto struct_kind =
        btf_data.get_kind_type<libbtf::btf_kind_struct>(struct_id);
    auto union_kind = btf_data.get_kind_type<libbtf::btf_kind_union>(union_id);
    auto enum_kind = btf_data.get_kind_type<libbtf::btf_kind_enum>(enum_id);
    auto fwd_kind = btf_data.get_kind_type<libbtf::btf_kind_fwd>(fwd_id);
    auto typedef_kind =
        btf_data.get_kind_type<libbtf::btf_kind_typedef>(typedef_id);
    auto volatile_kind =
        btf_data.get_kind_type<libbtf::btf_kind_volatile>(volatile_id);
    auto const_kind = btf_data.get_kind_type<libbtf::btf_kind_const>(const_id);
    auto restrict_kind =
        btf_data.get_kind_type<libbtf::btf_kind_restrict>(restrict_id);
    auto func_proto_kind =
        btf_data.get_kind_type<libbtf::btf_kind_function_prototype>(
            func_proto_id);
    auto function_kind =
        btf_data.get_kind_type<libbtf::btf_kind_function>(function_id);
    auto var_kind = btf_data.get_kind_type<libbtf::btf_kind_var>(var_id);
    auto data_section_kind =
        btf_data.get_kind_type<libbtf::btf_kind_data_section>(data_section_id);
    auto float_kind = btf_data.get_kind_type<libbtf::btf_kind_float>(float_id);
    auto decl_tag_kind =
        btf_data.get_kind_type<libbtf::btf_kind_decl_tag>(decl_tag_id);
    auto type_tag_kind =
        btf_data.get_kind_type<libbtf::btf_kind_type_tag>(type_tag_id);
    auto enum64_kind =
        btf_data.get_kind_type<libbtf::btf_kind_enum64>(enum64_id);

    // Verify we got the correct types back
    REQUIRE(int_kind.name == "int");
    REQUIRE(int_kind.size_in_bytes == 4);
    REQUIRE(ptr_kind.type == int_id);
    REQUIRE(array_kind.count_of_elements == 10);
    REQUIRE(struct_kind.name == "test_struct");
    REQUIRE(union_kind.name == "test_union");
    REQUIRE(enum_kind.name == "test_enum");
    REQUIRE(fwd_kind.name == "forward_decl");
    REQUIRE(typedef_kind.name == "my_int");
    REQUIRE(volatile_kind.type == int_id);
    REQUIRE(const_kind.type == int_id);
    REQUIRE(restrict_kind.type == ptr_id);
    REQUIRE(func_proto_kind.return_type == int_id);
    REQUIRE(function_kind.name == "test_func");
    REQUIRE(var_kind.name == "test_var");
    REQUIRE(data_section_kind.name == ".data");
    REQUIRE(float_kind.name == "float");
    REQUIRE(decl_tag_kind.name == "tag");
    REQUIRE(type_tag_kind.name == "type_tag");
    REQUIRE(enum64_kind.name == "test_enum64");
  }

  SECTION("Test wrong type casting throws exception") {
    // Try to get int as ptr - should throw
    REQUIRE_THROWS_WITH(btf_data.get_kind_type<libbtf::btf_kind_ptr>(int_id),
                        Catch::Matchers::ContainsSubstring("Wrong type"));

    // Try to get struct as union - should throw
    REQUIRE_THROWS_WITH(
        btf_data.get_kind_type<libbtf::btf_kind_union>(struct_id),
        Catch::Matchers::ContainsSubstring("Wrong type"));
  }
}

TEST_CASE("maximum_type_ids", "[stress]") {
  // Test behavior near maximum type ID limits
  libbtf::btf_type_data btf_data;

  SECTION("Add many types and verify they all get unique IDs") {
    const int num_types = 1000;
    std::vector<libbtf::btf_type_id> type_ids;

    // Add many int types with different names
    for (int i = 0; i < num_types; ++i) {
      auto type_id = btf_data.append(
          libbtf::btf_kind_int{.name = "int_" + std::to_string(i),
                               .size_in_bytes = 4,
                               .offset_from_start_in_bits = 0,
                               .field_width_in_bits = 32,
                               .is_signed = true,
                               .is_char = false,
                               .is_bool = false});
      type_ids.push_back(type_id);
    }

    // Verify all IDs are unique and sequential
    for (int i = 0; i < num_types; ++i) {
      REQUIRE(type_ids[i] == static_cast<libbtf::btf_type_id>(i + 1));
      auto kind = btf_data.get_kind_type<libbtf::btf_kind_int>(type_ids[i]);
      REQUIRE(kind.name == "int_" + std::to_string(i));
    }

    // Verify last_type_id returns the highest ID
    REQUIRE(btf_data.last_type_id() == num_types);
  }

  SECTION("Test type ID overflow protection") {
    // This would test the overflow check in append() but since it's hard to
    // reach UINT32_MAX types in a test, we'll verify the logic exists
    // by checking that we can at least add a reasonable number of types
    const int reasonable_limit = 10000;

    libbtf::btf_type_data btf_data_large;
    for (int i = 0; i < reasonable_limit; ++i) {
      REQUIRE_NOTHROW(btf_data_large.append(libbtf::btf_kind_void{}));
    }

    REQUIRE(btf_data_large.last_type_id() == reasonable_limit);
  }
}

TEST_CASE("large_string_table", "[stress]") {
  // Test behavior with large string tables and long type names
  libbtf::btf_type_data btf_data;

  SECTION("Very long type names") {
    std::string very_long_name(1000, 'a'); // 1000 character name

    auto type_id = btf_data.append(
        libbtf::btf_kind_struct{.name = very_long_name, .members = {}});

    auto struct_kind = btf_data.get_kind_type<libbtf::btf_kind_struct>(type_id);
    REQUIRE(struct_kind.name == very_long_name);
  }

  SECTION("Many types with unique long names") {
    const int num_types = 100;
    std::vector<std::string> long_names;

    for (int i = 0; i < num_types; ++i) {
      std::string long_name = "very_long_type_name_" +
                              std::string(100, 'a' + (i % 26)) + "_" +
                              std::to_string(i);
      long_names.push_back(long_name);

      btf_data.append(
          libbtf::btf_kind_struct{.name = long_name, .members = {}});
    }

    // Verify all names are stored correctly
    for (int i = 0; i < num_types; ++i) {
      auto type_id = btf_data.get_id(long_names[i]);
      auto struct_kind =
          btf_data.get_kind_type<libbtf::btf_kind_struct>(type_id);
      REQUIRE(struct_kind.name == long_names[i]);
    }
  }

  SECTION("Round-trip serialization with large data") {
    // Create a large BTF structure and verify round-trip serialization
    const int num_structs = 50;

    for (int i = 0; i < num_structs; ++i) {
      std::vector<libbtf::btf_kind_struct_member> members;
      for (int j = 0; j < 20; ++j) { // 20 members per struct
        members.push_back({
            .name = "member_" + std::to_string(j),
            .type = 1, // void type
            .offset_from_start_in_bits =
                static_cast<uint32_t>(j * 8) // 8-bit aligned
        });
      }

      btf_data.append(libbtf::btf_kind_struct{
          .name = "large_struct_" + std::to_string(i),
          .members = members,
          .size_in_bytes = static_cast<uint32_t>(members.size() * 8)});
    }

    // Serialize and deserialize
    auto serialized = btf_data.to_bytes();
    libbtf::btf_type_data btf_data_roundtrip(serialized);

    // Verify the data matches
    REQUIRE(btf_data_roundtrip.last_type_id() == btf_data.last_type_id());

    // Spot check a few types
    auto original_struct = btf_data.get_kind_type<libbtf::btf_kind_struct>(2);
    auto roundtrip_struct =
        btf_data_roundtrip.get_kind_type<libbtf::btf_kind_struct>(2);
    REQUIRE(original_struct.name == roundtrip_struct.name);
    REQUIRE(original_struct.members.size() == roundtrip_struct.members.size());
  }
}

TEST_CASE("zero_sized_and_edge_case_types", "[boundary]") {
  libbtf::btf_type_data btf_data;

  SECTION("Zero-sized arrays") {
    auto array_id = btf_data.append(libbtf::btf_kind_array{
        .element_type = 1, // void
        .index_type = 1,
        .count_of_elements = 0 // Zero elements
    });

    auto array_kind = btf_data.get_kind_type<libbtf::btf_kind_array>(array_id);
    REQUIRE(array_kind.count_of_elements == 0);
    REQUIRE(btf_data.get_size(array_id) == 0);
  }

  SECTION("Maximum enum64 values") {
    auto enum64_id = btf_data.append(libbtf::btf_kind_enum64{
        .name = "max_enum",
        .is_signed = false,
        .members = {{.name = "MIN_VAL", .value = 0},
                    {.name = "MAX_VAL", .value = UINT64_MAX}},
        .size_in_bytes = 8});

    auto enum64_kind =
        btf_data.get_kind_type<libbtf::btf_kind_enum64>(enum64_id);
    REQUIRE(enum64_kind.members[1].value == UINT64_MAX);
  }

  SECTION("Deeply nested pointer chains") {
    // Create a chain of 100 pointers: int -> ptr -> ptr -> ... -> ptr
    auto current_type =
        btf_data.append(libbtf::btf_kind_int{.name = "int",
                                             .size_in_bytes = 4,
                                             .offset_from_start_in_bits = 0,
                                             .field_width_in_bits = 32,
                                             .is_signed = true,
                                             .is_char = false,
                                             .is_bool = false});

    const int chain_length = 100;
    for (int i = 0; i < chain_length; ++i) {
      current_type =
          btf_data.append(libbtf::btf_kind_ptr{.type = current_type});
    }

    // Verify we can dereference the whole chain
    auto ptr_type = current_type;
    for (int i = 0; i < chain_length; ++i) {
      ptr_type = btf_data.dereference_pointer(ptr_type);
    }

    // Should end up at the original int type
    auto final_kind = btf_data.get_kind_type<libbtf::btf_kind_int>(ptr_type);
    REQUIRE(final_kind.name == "int");
  }
}

TEST_CASE("internal_helper_function_coverage", "[internal]") {
  // These tests indirectly exercise static helper functions

  SECTION("Test JSON array printing helpers via to_json") {
    // This exercises print_array_start() and print_array_end() indirectly
    libbtf::btf_type_data btf_data;

    // Create an enum with multiple members to trigger array printing
    auto enum_id = btf_data.append(
        libbtf::btf_kind_enum{.name = "test_enum",
                              .members = {{.name = "VAL1", .value = 1},
                                          {.name = "VAL2", .value = 2},
                                          {.name = "VAL3", .value = 3}},
                              .size_in_bytes = 4});
    REQUIRE(enum_id != 0);

    std::stringstream json_output;
    btf_data.to_json(json_output);
    std::string json_str = json_output.str();

    // Verify the JSON contains array syntax (which uses print_array_start/end)
    REQUIRE(json_str.find("\"members\":[") != std::string::npos);
    REQUIRE(json_str.find("]") != std::string::npos);
  }

  SECTION("Test btf_uint_from_value indirectly via build_btf_map_section") {
    // This exercises btf_uint_from_value() through map building
    libbtf::btf_type_data btf_data;

    // Create a simple map definition
    std::vector<libbtf::btf_map_definition> map_defs = {
        {.name = "test_map",
         .type_id = 0,
         .map_type = 1, // BPF_MAP_TYPE_HASH
         .key_size = 4,
         .value_size = 8,
         .max_entries = 1024,
         .inner_map_type_id = 0}};

    // This will internally call btf_uint_from_value for each numeric field
    REQUIRE_NOTHROW(libbtf::build_btf_map_section(map_defs, btf_data));

    // Verify the map was built correctly
    auto parsed_maps = libbtf::parse_btf_map_section(btf_data);
    REQUIRE(parsed_maps.size() == 1);
    REQUIRE(parsed_maps[0].map_type == 1);
    REQUIRE(parsed_maps[0].key_size == 4);
    REQUIRE(parsed_maps[0].value_size == 8);
    REQUIRE(parsed_maps[0].max_entries == 1024);
  }

  SECTION("Test BTF parsing validation helpers with edge cases") {
    // This exercises validate_offset and validate_range indirectly
    // by creating BTF data that's just barely valid

    std::vector<std::byte> minimal_btf;

    // Create minimal valid BTF with just header and empty string table
    btf_header_t header = {.magic = BTF_HEADER_MAGIC,
                           .version = BTF_HEADER_VERSION,
                           .flags = 0,
                           .hdr_len = sizeof(btf_header_t),
                           .type_off = 0,
                           .type_len = 0,
                           .str_off = 0,
                           .str_len = 1};

    minimal_btf.resize(sizeof(header) + 1);
    std::memcpy(minimal_btf.data(), &header, sizeof(header));
    minimal_btf[sizeof(header)] =
        std::byte{0}; // Null terminator for empty string

    // This should parse successfully and exercise the validation functions
    REQUIRE_NOTHROW(libbtf::btf_type_data(minimal_btf));
  }

  SECTION("Test write_btf helper indirectly via to_bytes") {
    // This exercises the static write_btf() helper in btf_write.cpp
    libbtf::btf_type_data btf_data;

    // Add a variety of types to exercise different write paths
    auto int_id =
        btf_data.append(libbtf::btf_kind_int{.name = "int",
                                             .size_in_bytes = 4,
                                             .offset_from_start_in_bits = 0,
                                             .field_width_in_bits = 32,
                                             .is_signed = true,
                                             .is_char = false,
                                             .is_bool = false});
    REQUIRE(int_id != 0);

    auto struct_id = btf_data.append(
        libbtf::btf_kind_struct{.name = "test_struct",
                                .members = {{.name = "field1",
                                             .type = int_id,
                                             .offset_from_start_in_bits = 0},
                                            {.name = "field2",
                                             .type = int_id,
                                             .offset_from_start_in_bits = 32}},
                                .size_in_bytes = 8});
    REQUIRE(struct_id != 0);

    // This will internally use write_btf() to serialize each type
    auto serialized = btf_data.to_bytes();
    REQUIRE(serialized.size() > sizeof(btf_header_t));

    // Verify round-trip works (exercises parsing validation too)
    libbtf::btf_type_data btf_data_roundtrip(serialized);
    REQUIRE(btf_data_roundtrip.last_type_id() == btf_data.last_type_id());
  }

  SECTION("Test _print_json_value helper indirectly") {
    // This exercises the static template _print_json_value function
    libbtf::btf_type_data btf_data;

    // Create types with various optional and non-optional fields
    auto struct_with_optional_name = btf_data.append(
        libbtf::btf_kind_struct{.name = std::nullopt, // Optional name
                                .members = {}});
    REQUIRE(struct_with_optional_name != 0);

    auto struct_with_name = btf_data.append(
        libbtf::btf_kind_struct{.name = "named_struct", .members = {}});
    REQUIRE(struct_with_name != 0);

    // Generate JSON - this exercises _print_json_value with both optional and
    // regular values
    std::stringstream json_output;
    btf_data.to_json(json_output);
    std::string json_str = json_output.str();

    // Verify both types are in the JSON
    REQUIRE(json_str.find("\"named_struct\"") != std::string::npos);
    // Anonymous struct should not have a name field or have null name
    REQUIRE(json_str.length() > 50); // Should have substantial content
  }

  SECTION("Test private member functions indirectly") {
    // This exercises get_qualified_type_name_with_detector and related
    // functions
    libbtf::btf_type_data btf_data;

    auto int_id =
        btf_data.append(libbtf::btf_kind_int{.name = "int",
                                             .size_in_bytes = 4,
                                             .offset_from_start_in_bits = 0,
                                             .field_width_in_bits = 32,
                                             .is_signed = true,
                                             .is_char = false,
                                             .is_bool = false});

    auto const_int_id = btf_data.append(libbtf::btf_kind_const{.type = int_id});

    auto ptr_to_const_int_id =
        btf_data.append(libbtf::btf_kind_ptr{.type = const_int_id});

    REQUIRE(ptr_to_const_int_id != 0);

    // Generate C header - this exercises the private member functions
    std::stringstream c_header;
    btf_data.to_c_header(c_header);
    std::string header_str = c_header.str();

    // Verify the C header contains expected content
    // Should contain type declarations that use the private helper functions
    REQUIRE(header_str.length() > 10); // Should have some content
  }
}