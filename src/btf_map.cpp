// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "btf_map.h"

#include "btf.h"
#include "btf_json.h"
#include "btf_parse.h"
#include "btf_type_data.h"
#include "btf_write.h"

#include <stdexcept>

namespace libbtf {
static uint32_t _value_from_BTF__uint(const btf_type_data &btf_types,
                                      btf_type_id type_id) {
  // The __uint macro is defined as follows:
  // #define __uint(name, val) int (*name)[val]
  // So, we need to get the value of val from the BTF type.

  // Top level should be a pointer. Dereference it.
  type_id = btf_types.dereference_pointer(type_id);

  // Next level should be an array.
  auto array = btf_types.get_kind(type_id);
  if (array.index() != BTF_KIND_ARRAY) {
    throw std::runtime_error("expected array type");
  }
  auto array_type = std::get<BTF_KIND_ARRAY>(array);

  // Value is encoded in the count of elements.
  return array_type.count_of_elements;
}

static btf_map_definition
_get_map_definition_from_btf(const btf_type_data &btf_types,
                             btf_type_id map_type_id) {
  btf_type_id type = 0;
  btf_type_id max_entries = 0;
  btf_type_id key = 0;
  btf_type_id key_size = 0;
  btf_type_id value = 0;
  btf_type_id value_size = 0;
  btf_type_id values = 0;

  auto map_var = btf_types.get_kind(map_type_id);
  if (map_var.index() != BTF_KIND_VAR) {
    throw std::runtime_error("expected BTF_KIND_VAR type");
  }

  auto map_struct = btf_types.get_kind(std::get<BTF_KIND_VAR>(map_var).type);
  if (map_struct.index() != BTF_KIND_STRUCT) {
    throw std::runtime_error("expected BTF_KIND_STRUCT type");
  }

  for (const auto &member : std::get<BTF_KIND_STRUCT>(map_struct).members) {
    if (member.name == "type") {
      type = member.type;
    } else if (member.name == "max_entries") {
      max_entries = member.type;
    } else if (member.name == "key") {
      key = btf_types.dereference_pointer(member.type);
    } else if (member.name == "value") {
      value = btf_types.dereference_pointer(member.type);
    } else if (member.name == "key_size") {
      key_size = member.type;
    } else if (member.name == "value_size") {
      value_size = member.type;
    } else if (member.name == "values") {
      values = member.type;
    }
  }

  if (type == 0) {
    throw std::runtime_error("invalid map type");
  }

  btf_map_definition map_definition = {0};

  // Required fields.
  map_definition.type_id = std::get<BTF_KIND_VAR>(map_var).type;
  map_definition.map_type = _value_from_BTF__uint(btf_types, type);
  map_definition.max_entries = _value_from_BTF__uint(btf_types, max_entries);

  // Optional fields.
  if (key) {
    size_t key_size = btf_types.get_size(key);
    if (key_size > UINT32_MAX) {
      throw std::runtime_error("key size too large");
    }
    map_definition.key_size = static_cast<uint32_t>(key_size);
  } else if (key_size) {
    map_definition.key_size = _value_from_BTF__uint(btf_types, key_size);
  }

  if (value) {
    size_t value_size = btf_types.get_size(value);
    if (value_size > UINT32_MAX) {
      throw std::runtime_error("value size too large");
    }
    map_definition.value_size = static_cast<uint32_t>(value_size);
  } else if (value_size) {
    map_definition.value_size = _value_from_BTF__uint(btf_types, value_size);
  }

  if (values) {
    // Values is an array of pointers to BTF map definitions.
    auto values_array = btf_types.get_kind(values);
    if (values_array.index() != BTF_KIND_ARRAY) {
      throw std::runtime_error("expected array type");
    }
    auto ptr =
        btf_types.get_kind(std::get<BTF_KIND_ARRAY>(values_array).element_type);
    if (ptr.index() != BTF_KIND_PTR) {
      throw std::runtime_error("expected pointer type");
    }
    // Verify this is a pointer to a BTF map definition.
    auto map_def = btf_types.get_kind(std::get<BTF_KIND_PTR>(ptr).type);
    map_definition.inner_map_type_id =
        static_cast<int>(std::get<BTF_KIND_PTR>(ptr).type);
  }

  return map_definition;
}

std::vector<btf_map_definition>
parse_btf_map_section(const btf_type_data &btf_data) {
  std::vector<btf_map_definition> map_definitions;
  auto maps_section_kind = btf_data.get_kind(btf_data.get_id(".maps"));

  // Check that the .maps section is a BTF_KIND_DATA_SECTION.
  if (maps_section_kind.index() != BTF_KIND_DATA_SECTION) {
    throw std::runtime_error(
        "expected .maps section to be a BTF_KIND_DATA_SECTION");
  }

  // For each BTF_KIND_VAR in the maps section, get the map definitions from the
  // BTF type.
  auto maps_section = std::get<BTF_KIND_DATA_SECTION>(maps_section_kind);
  size_t index = 0;
  for (const auto &var : maps_section.members) {
    map_definitions.push_back(_get_map_definition_from_btf(btf_data, var.type));
  }
  return map_definitions;
}
} // namespace libbtf