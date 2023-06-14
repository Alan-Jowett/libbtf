// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include <map>
#include <string>
#include <vector>

#if !defined(MAX_PATH)
#define MAX_PATH (256)
#endif

#include "btf.h"
#include "btf_json.h"
#include "btf_map.h"
#include "btf_parse.h"
#include "btf_type_data.h"
#include "btf_write.h"
#include "elfio/elfio.hpp"

#define TEST_OBJECT_FILE_DIRECTORY "external/ebpf-samples/build/"
#define TEST_SOURCE_FILE_DIRECTORY "external/ebpf-samples/src/"
#define TEST_JSON_FILE_DIRECTORY "external/ebpf-samples/json/"
#define BTF_CASE(file)                                                         \
  TEST_CASE("BTF JSON suite: " file, "[json]") { verify_BTF_json(file); }      \
  TEST_CASE("BTF LINE_INFO suite: " file, "[line_info]") {                     \
    verify_line_info(file);                                                    \
  }

void verify_line_by_line(std::istream &lhs, std::istream &rhs) {
  std::string lhs_line;
  std::string rhs_line;
  while (std::getline(lhs, lhs_line)) {
    bool has_more = (bool)std::getline(rhs, rhs_line);
    REQUIRE(has_more);
    REQUIRE(lhs_line == rhs_line);
  }
  bool has_more = (bool)std::getline(rhs, rhs_line);
  REQUIRE_FALSE(has_more);
}

void verify_BTF_json(const std::string &file) {
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
    switch (btf_data.get_kind(id).index()) {
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
      auto array = std::get<libbtf::BTF_KIND_ARRAY>(btf_data.get_kind(id));
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

  verify_line_by_line(expected_stream, generated_stream);

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

BTF_CASE("byteswap")
BTF_CASE("ctxoffset")
BTF_CASE("exposeptr")
BTF_CASE("exposeptr2")
BTF_CASE("map_in_map")
BTF_CASE("mapoverflow")
BTF_CASE("mapunderflow")
BTF_CASE("mapvalue-overrun")
BTF_CASE("nullmapref")
BTF_CASE("packet_access")
BTF_CASE("packet_overflow")
BTF_CASE("packet_reallocate")
BTF_CASE("packet_start_ok")
BTF_CASE("stackok")
BTF_CASE("tail_call")
BTF_CASE("tail_call_bad")
BTF_CASE("twomaps")
BTF_CASE("twostackvars")
BTF_CASE("twotypes")

TEST_CASE("validate-parsing-simple-loop", "[validation]") {
  libbtf::btf_type_data btf_data_loop;
  btf_data_loop.append(libbtf::btf_kind_ptr{.type = 1});

  REQUIRE_THROWS(
      [&] { libbtf::btf_type_data btf_data = btf_data_loop.to_bytes(); }());
}

TEST_CASE("validate-parsing-large-loop", "[validation]") {
  libbtf::btf_type_data btf_data_loop;

  // Each PTR points to the next PTR.
  for (uint32_t i = 0; i < 10; i++) {
    btf_data_loop.append(libbtf::btf_kind_ptr{.type = i + 1});
  }
  // Last PTR points to itself.
  btf_data_loop.append(libbtf::btf_kind_ptr{.type = 1});

  REQUIRE_THROWS(
      [&] { libbtf::btf_type_data btf_data = btf_data_loop.to_bytes(); }());
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

TEST_CASE("btf_maps", "[parsing][json]") {
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
  REQUIRE(map_definitions[0].name == "array_of_maps");
  REQUIRE(map_definitions[0].map_type == 12); // BPF_MAP_TYPE_ARRAY_OF_MAPS
  REQUIRE(map_definitions[0].key_size == 4);
  REQUIRE(map_definitions[0].value_size == 0);
  REQUIRE(map_definitions[0].max_entries == 1);
  REQUIRE(map_definitions[0].inner_map_type_id != 0);

  REQUIRE(map_definitions[1].name == "inner_map");
  REQUIRE(map_definitions[1].map_type == 2); // BPF_MAP_TYPE_ARRAY
  REQUIRE(map_definitions[1].key_size == 4);
  REQUIRE(map_definitions[1].value_size == 4);
  REQUIRE(map_definitions[1].max_entries == 1);
  REQUIRE(map_definitions[1].inner_map_type_id == 0);
}

TEST_CASE("get_unknown_type_id", "[btf_type_data][negative]") {
  libbtf::btf_type_data btf_data;
  REQUIRE_THROWS(btf_data.get_kind(1));
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