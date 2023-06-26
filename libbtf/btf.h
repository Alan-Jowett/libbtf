// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace libbtf {
typedef uint32_t btf_type_id;

enum btf_kind_index {
  BTF_KIND_NULL,
  BTF_KIND_INT,
  BTF_KIND_PTR,
  BTF_KIND_ARRAY,
  BTF_KIND_STRUCT,
  BTF_KIND_UNION,
  BTF_KIND_ENUM,
  BTF_KIND_FWD,
  BTF_KIND_TYPEDEF,
  BTF_KIND_VOLATILE,
  BTF_KIND_CONST,
  BTF_KIND_RESTRICT,
  BTF_KIND_FUNCTION,
  BTF_KIND_FUNCTION_PROTOTYPE,
  BTF_KIND_VAR,
  BTF_KIND_DATA_SECTION,
  BTF_KIND_FLOAT,
  BTF_KIND_DECL_TAG,
  BTF_KIND_TYPE_TAG,
  BTF_KIND_ENUM64,
};

struct btf_kind_int {
  std::string name;
  uint32_t size_in_bytes; // The size of the integer in bytes. This value
                          // multiplied by 8 must be >= field_width_in_bits
  uint16_t offset_from_start_in_bits; // The start of the integer relative to
                                      // the start of the member.
  uint8_t field_width_in_bits;        // The size of the integer in bits.
  bool is_signed;
  bool is_char;
  bool is_bool;
};

struct btf_kind_ptr {
  btf_type_id type;
};

struct btf_kind_array {
  btf_type_id element_type;
  btf_type_id index_type;
  uint32_t count_of_elements;
};

struct btf_kind_struct_member {
  std::optional<std::string> name;
  btf_type_id type;
  uint32_t offset_from_start_in_bits;
};

using btf_kind_union_member = btf_kind_struct_member;

struct btf_kind_struct {
  std::optional<std::string> name;
  std::vector<btf_kind_struct_member> members;
  uint32_t size_in_bytes;
};

struct btf_kind_union {
  std::optional<std::string> name;
  std::vector<btf_kind_union_member> members;
  uint32_t size_in_bytes;
};

struct btf_kind_enum_member {
  std::string name;
  uint32_t value;
};

struct btf_kind_enum {
  std::optional<std::string> name;
  bool is_signed;
  std::vector<btf_kind_enum_member> members;
  uint32_t size_in_bytes;
};

struct btf_kind_fwd {
  std::string name;
  bool is_struct;
};

struct btf_kind_typedef {
  std::string name;
  btf_type_id type;
};

struct btf_kind_volatile {
  btf_type_id type;
};

struct btf_kind_const {
  btf_type_id type;
};

struct btf_kind_restrict {
  btf_type_id type;
};

struct btf_kind_function {
  std::string name;
  enum {
    BTF_LINKAGE_GLOBAL,
    BTF_LINKAGE_STATIC,
    BTF_LINKAGE_EXTERN,
  } linkage;
  btf_type_id type;
};

struct btf_kind_function_parameter {
  std::string name;
  btf_type_id type;
};

struct btf_kind_function_prototype {
  std::vector<btf_kind_function_parameter> parameters;
  btf_type_id return_type;
};

struct btf_kind_var {
  std::string name;
  btf_type_id type;
  enum {
    BTF_LINKAGE_GLOBAL,
    BTF_LINKAGE_STATIC,
  } linkage;
};

struct btf_kind_data_member {
  btf_type_id type;
  uint32_t offset;
  uint32_t size;
};

struct btf_kind_data_section {
  std::string name;
  std::vector<btf_kind_data_member> members;
  uint32_t size;
};

struct btf_kind_float {
  std::string name;
  uint32_t size_in_bytes;
};

struct btf_kind_decl_tag {
  std::string name;
  btf_type_id type;
  uint32_t component_index;
};

struct btf_kind_type_tag {
  std::string name;
  btf_type_id type;
};

struct btf_kind_enum64_member {
  std::string name;
  uint64_t value;
};

struct btf_kind_enum64 {
  std::optional<std::string> name;
  bool is_signed;
  std::vector<btf_kind_enum64_member> members;
  uint32_t size_in_bytes;
};

struct btf_kind_null {};

template <typename T> struct btf_kind_traits {
  constexpr static bool has_optional_name = requires(const T &value) {
    value.name.has_value();
  };
  constexpr static bool has_name = requires(const T &value) { value.name; };
  constexpr static bool has_members = requires(const T &value) {
    value.members.size();
  };
  constexpr static bool has_parameters = requires(const T &value) {
    value.parameters.size();
  };
  constexpr static bool has_return_type = requires(const T &value) {
    value.return_type != 0;
  };
  constexpr static bool has_type = requires(const T &value) {
    value.type != 0;
  };
  constexpr static bool has_size_in_bytes = requires(const T &value) {
    value.size_in_bytes;
  };
  constexpr static bool has_linkage = requires(const T &value) {
    value.linkage;
  };
  constexpr static bool has_count_of_elements = requires(const T &value) {
    value.count_of_elements;
  };
  constexpr static bool has_element_type = requires(const T &value) {
    value.element_type;
  };
  constexpr static bool has_index_type = requires(const T &value) {
    value.index_type;
  };
};

// Note: The order of the variant types must match the order in the enum above.
using btf_kind = std::variant<
    btf_kind_null, btf_kind_int, btf_kind_ptr, btf_kind_array, btf_kind_struct,
    btf_kind_union, btf_kind_enum, btf_kind_fwd, btf_kind_typedef,
    btf_kind_volatile, btf_kind_const, btf_kind_restrict, btf_kind_function,
    btf_kind_function_prototype, btf_kind_var, btf_kind_data_section,
    btf_kind_float, btf_kind_decl_tag, btf_kind_type_tag, btf_kind_enum64>;
} // namespace libbtf