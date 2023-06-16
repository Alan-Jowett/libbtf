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

  // Value is encoded in the count of elements.
  return btf_types.get_kind_type<btf_kind_array>(type_id).count_of_elements;
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

  auto map_var = btf_types.get_kind_type<btf_kind_var>(map_type_id);
  auto map_struct = btf_types.get_kind_type<btf_kind_struct>(map_var.type);

  for (const auto &member : map_struct.members) {
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

  btf_map_definition map_definition = {};
  map_definition.name = map_var.name;

  // Required fields.
  map_definition.type_id = map_var.type;
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
    auto values_array = btf_types.get_kind_type<btf_kind_array>(values);
    auto ptr = btf_types.get_kind_type<btf_kind_ptr>(values_array.element_type);

    // Verify this is a pointer to a BTF map definition.
    auto map_def = btf_types.get_kind_type<btf_kind_struct>(ptr.type);
    map_definition.inner_map_type_id = static_cast<int>(ptr.type);
  }

  return map_definition;
}

std::vector<btf_map_definition>
parse_btf_map_section(const btf_type_data &btf_data) {
  std::vector<btf_map_definition> map_definitions;
  auto maps_section =
      btf_data.get_kind_type<btf_kind_data_section>(btf_data.get_id(".maps"));

  size_t index = 0;
  for (const auto &var : maps_section.members) {
    map_definitions.push_back(_get_map_definition_from_btf(btf_data, var.type));
  }
  return map_definitions;
}

btf_type_id btf_uint_from_value(btf_type_data &btf_data, uint32_t value) {
  btf_type_id int_id = btf_data.get_id("int");
  if (int_id == 0) {
    int_id = btf_data.append(btf_kind_int{
        .name = "int", .size_in_bytes = 4, .field_width_in_bits = 32});
  }

  btf_type_id array_size_id = btf_data.get_id("__ARRAY_SIZE_TYPE__");
  if (array_size_id == 0) {
    array_size_id = btf_data.append(btf_kind_int{
        .name = "__ARRAY_SIZE_TYPE__",
        .size_in_bytes = 4,
        .field_width_in_bits = 32,
    });
  }

  btf_type_id array = btf_data.append(btf_kind_array{
      .element_type = int_id,
      .index_type = array_size_id,
      .count_of_elements = value,
  });

  return btf_data.append(btf_kind_ptr{.type = array});
}

btf_type_id build_btf_map(btf_type_data &btf_data,
                          const btf_map_definition &map_definition) {
  uint32_t offset_in_bits = 0;
  btf_kind_struct map{
      .members =
          {
              {
                  .name = "type",
                  .type =
                      btf_uint_from_value(btf_data, map_definition.map_type),
              },
              {
                  .name = "max_entries",
                  .type =
                      btf_uint_from_value(btf_data, map_definition.max_entries),
              },
          },
  };
  if (map_definition.key_size) {
    map.members.push_back({
        .name = "key_size",
        .type = btf_uint_from_value(btf_data, map_definition.key_size),
    });
  }
  if (map_definition.value_size) {
    map.members.push_back({
        .name = "value_size",
        .type = btf_uint_from_value(btf_data, map_definition.value_size),
    });
  }

  if (map_definition.inner_map_type_id != 0) {
    map.members.push_back(
        {.name = "values",
         .type = btf_data.append({btf_kind_array{
             .element_type = btf_data.append(
                 btf_kind_ptr{.type = map_definition.inner_map_type_id}),
             .index_type = btf_data.get_id("__ARRAY_SIZE_TYPE__"),
         }})});
  }

  for (auto &member : map.members) {
    member.offset_from_start_in_bits = offset_in_bits;
    offset_in_bits += btf_data.get_size(member.type) * 8;
  }

  map.size_in_bytes = offset_in_bits / 8;

  return btf_data.append(btf_kind_var{
      .name = map_definition.name,
      .type = btf_data.append(map),
      .linkage = btf_kind_var::BTF_LINKAGE_STATIC,
  });
}

void build_btf_map_section(
    const std::vector<btf_map_definition> &map_definitions,
    btf_type_data &btf_data) {
  btf_kind_data_section maps_section{.name = ".maps"};
  std::map<btf_type_id, btf_type_id> old_id_to_new_id;

  for (auto &map_definition : map_definitions) {
    btf_type_id var_id = build_btf_map(btf_data, map_definition);
    btf_type_id map_id = btf_data.get_kind_type<btf_kind_var>(var_id).type;
    maps_section.members.push_back(btf_kind_data_member{
        .type = var_id,
        .size = static_cast<uint32_t>(btf_data.get_size(map_id)),
    });
    old_id_to_new_id[map_definition.type_id] = map_id;
  }

  // Update the map inner_map_type_id in the BTF types.
  for (auto &map_definition : map_definitions) {
    if (map_definition.inner_map_type_id == 0) {
      continue;
    }
    auto new_id = old_id_to_new_id[map_definition.type_id];
    auto ptr_id = btf_data
                      .get_kind_type<btf_kind_array>(
                          btf_data.get_kind_type<btf_kind_struct>(new_id)
                              .members.back()
                              .type)
                      .element_type;

    auto ptr = btf_data.get_kind_type<btf_kind_ptr>(ptr_id);
    ptr.type = old_id_to_new_id[ptr.type];

    btf_data.replace(ptr_id, ptr);
  }

  btf_data.append(maps_section);
  return;
}

} // namespace libbtf