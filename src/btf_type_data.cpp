// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "btf_type_data.h"

#include "btf.h"
#include "btf_json.h"
#include "btf_parse.h"
#include "btf_write.h"

#include <stdexcept>

namespace libbtf {
btf_type_data::btf_type_data(const std::vector<std::byte> &btf_data) {
  auto visitor = [&, this](btf_type_id id,
                           const std::optional<std::string> &name,
                           const btf_kind &kind) {
    this->id_to_kind.insert({id, kind});
    if (name.has_value()) {
      this->name_to_id.insert({name.value(), id});
    }
  };
  btf_parse_types(btf_data, visitor);
  // Validate that the type graph is valid.
  for (const auto &[id, kind] : id_to_kind) {
    std::set<btf_type_id> visited;
    validate_type_graph(id, visited);
  }
}

btf_type_id btf_type_data::get_id(const std::string &name) const {
  auto it = name_to_id.find(name);
  if (it == name_to_id.end()) {
    return 0;
  }
  return it->second;
}

btf_kind btf_type_data::get_kind(btf_type_id id) const {
  auto it = id_to_kind.find(id);
  if (it == id_to_kind.end()) {
    throw std::runtime_error("BTF type id not found: " + std::to_string(id));
  }
  return it->second;
}

btf_type_id btf_type_data::dereference_pointer(btf_type_id id) const {
  auto kind = get_kind(id);
  if (kind.index() != BTF_KIND_PTR) {
    throw std::runtime_error("BTF type is not a pointer: " +
                             std::to_string(id));
  }
  return std::get<BTF_KIND_PTR>(kind).type;
}

size_t btf_type_data::get_size(btf_type_id id) const {
  // Compute the effective size of a BTF type.

  auto kind = id_to_kind.at(id);

  switch (kind.index()) {
  case BTF_KIND_INT:
    return std::get<BTF_KIND_INT>(kind).size_in_bytes;
  case BTF_KIND_PTR:
    return sizeof(void *);
  case BTF_KIND_ARRAY:
    return std::get<BTF_KIND_ARRAY>(kind).count_of_elements *
           get_size(std::get<BTF_KIND_ARRAY>(kind).element_type);
  case BTF_KIND_STRUCT:
    return std::get<BTF_KIND_STRUCT>(kind).size_in_bytes;
  case BTF_KIND_UNION:
    return std::get<BTF_KIND_UNION>(kind).size_in_bytes;
  case BTF_KIND_ENUM:
    return std::get<BTF_KIND_ENUM>(kind).size_in_bytes;
  case BTF_KIND_FWD:
    return 0;
  case BTF_KIND_TYPEDEF:
    return get_size(std::get<BTF_KIND_TYPEDEF>(kind).type);
  case BTF_KIND_VOLATILE:
    return get_size(std::get<BTF_KIND_VOLATILE>(kind).type);
  case BTF_KIND_CONST:
    return get_size(std::get<BTF_KIND_CONST>(kind).type);
  case BTF_KIND_RESTRICT:
    return get_size(std::get<BTF_KIND_RESTRICT>(kind).type);
  case BTF_KIND_FUNCTION:
    return 0;
  case BTF_KIND_FUNCTION_PROTOTYPE:
    return 0;
  case BTF_KIND_VAR:
    return get_size(std::get<BTF_KIND_VAR>(kind).type);
  case BTF_KIND_DATA_SECTION:
    return 0;
  case BTF_KIND_FLOAT:
    return std::get<BTF_KIND_FLOAT>(kind).size_in_bytes;
  case BTF_KIND_DECL_TAG:
    return get_size(std::get<BTF_KIND_DECL_TAG>(kind).type);
  case BTF_KIND_TYPE_TAG:
    return get_size(std::get<BTF_KIND_TYPE_TAG>(kind).type);
  case BTF_KIND_ENUM64:
    return std::get<BTF_KIND_ENUM64>(kind).size_in_bytes;
  default:
    throw std::runtime_error("unknown BTF type kind");
  }
}

void btf_type_data::to_json(std::ostream &out) const {
  btf_type_to_json(id_to_kind, out);
}

void btf_type_data::validate_type_graph(btf_type_id id,
                                        std::set<btf_type_id> &visited) const {
  // BTF types must be an acyclic graph. This function validates that the type
  // graph is acyclic.
  if (visited.find(id) != visited.end()) {
    throw std::runtime_error("BTF type cycle detected: " + std::to_string(id));
  } else {
    visited.insert(id);
  }

  auto kind = get_kind(id);
  switch (kind.index()) {
  case 0:
    break;
  case BTF_KIND_INT:
    break;
  case BTF_KIND_PTR:
    validate_type_graph(std::get<BTF_KIND_PTR>(kind).type, visited);
    break;
  case BTF_KIND_ARRAY:
    validate_type_graph(std::get<BTF_KIND_ARRAY>(kind).element_type, visited);
    validate_type_graph(std::get<BTF_KIND_ARRAY>(kind).index_type, visited);
    break;
  case BTF_KIND_STRUCT: {
    auto &struct_ = std::get<BTF_KIND_STRUCT>(kind);
    for (auto &member : struct_.members) {
      validate_type_graph(member.type, visited);
    }
    break;
  }
  case BTF_KIND_UNION: {
    auto &union_ = std::get<BTF_KIND_UNION>(kind);
    for (auto &member : union_.members) {
      validate_type_graph(member.type, visited);
    }
    break;
  }
  case BTF_KIND_ENUM:
    break;
  case BTF_KIND_FWD:
    break;
  case BTF_KIND_TYPEDEF:
    validate_type_graph(std::get<BTF_KIND_TYPEDEF>(kind).type, visited);
    break;
  case BTF_KIND_VOLATILE:
    validate_type_graph(std::get<BTF_KIND_VOLATILE>(kind).type, visited);
    break;
  case BTF_KIND_CONST:
    validate_type_graph(std::get<BTF_KIND_CONST>(kind).type, visited);
    break;
  case BTF_KIND_RESTRICT:
    validate_type_graph(std::get<BTF_KIND_RESTRICT>(kind).type, visited);
    break;
  case BTF_KIND_FUNCTION:
    validate_type_graph(std::get<BTF_KIND_FUNCTION>(kind).type, visited);
    break;
  case BTF_KIND_FUNCTION_PROTOTYPE: {
    auto &prototype = std::get<BTF_KIND_FUNCTION_PROTOTYPE>(kind);
    for (auto &parameter : prototype.parameters) {
      validate_type_graph(parameter.type, visited);
    }
    validate_type_graph(prototype.return_type, visited);
    break;
  }
  case BTF_KIND_VAR:
    validate_type_graph(std::get<BTF_KIND_VAR>(kind).type, visited);
    break;
  case BTF_KIND_DATA_SECTION: {
    auto &datasec = std::get<BTF_KIND_DATA_SECTION>(kind);
    for (auto &variable : datasec.members) {
      validate_type_graph(variable.type, visited);
    }
    break;
  }
  case BTF_KIND_FLOAT:
    break;
  case BTF_KIND_DECL_TAG:
    validate_type_graph(std::get<BTF_KIND_DECL_TAG>(kind).type, visited);
    break;
  case BTF_KIND_TYPE_TAG:
    validate_type_graph(std::get<BTF_KIND_TYPE_TAG>(kind).type, visited);
    break;
  case BTF_KIND_ENUM64:
    break;
  default:
    throw std::runtime_error("unknown BTF type kind " +
                             std::to_string(kind.index()));
  }

  visited.erase(id);
}

std::vector<std::byte> btf_type_data::to_bytes() const {
  std::vector<btf_kind> kinds;
  for (const auto &[id, kind] : id_to_kind) {
    kinds.push_back(kind);
  }
  return btf_write_types(kinds);
}

void btf_type_data::append(const btf_kind &kind) {
  btf_type_id next_id = id_to_kind.size();
  id_to_kind.insert({next_id, kind});
  switch (kind.index()) {
  case BTF_KIND_INT:
    name_to_id.insert({std::get<BTF_KIND_INT>(kind).name, next_id});
    break;
  case BTF_KIND_PTR:
    break;
  case BTF_KIND_ARRAY:
    break;
  case BTF_KIND_STRUCT:
    if (std::get<BTF_KIND_STRUCT>(kind).name.has_value()) {
      name_to_id.insert(
          {std::get<BTF_KIND_STRUCT>(kind).name.value(), next_id});
    }
    break;
  case BTF_KIND_UNION:
    if (std::get<BTF_KIND_UNION>(kind).name.has_value()) {
      name_to_id.insert({std::get<BTF_KIND_UNION>(kind).name.value(), next_id});
    }
    break;
  case BTF_KIND_ENUM:
    if (std::get<BTF_KIND_ENUM>(kind).name.has_value()) {
      name_to_id.insert({std::get<BTF_KIND_ENUM>(kind).name.value(), next_id});
    }
    break;
  case BTF_KIND_FWD:
    name_to_id.insert({std::get<BTF_KIND_FWD>(kind).name, next_id});
    break;
  case BTF_KIND_TYPEDEF:
    name_to_id.insert({std::get<BTF_KIND_TYPEDEF>(kind).name, next_id});
    break;
  case BTF_KIND_VOLATILE:
    break;
  case BTF_KIND_CONST:
    break;
  case BTF_KIND_RESTRICT:
    break;
  case BTF_KIND_FUNCTION:
    name_to_id.insert({std::get<BTF_KIND_FUNCTION>(kind).name, next_id});
    break;
  case BTF_KIND_FUNCTION_PROTOTYPE:
    break;
  case BTF_KIND_VAR:
    name_to_id.insert({std::get<BTF_KIND_VAR>(kind).name, next_id});
    break;
  case BTF_KIND_DATA_SECTION:
    name_to_id.insert({std::get<BTF_KIND_DATA_SECTION>(kind).name, next_id});
    break;
  case BTF_KIND_FLOAT:
    name_to_id.insert({std::get<BTF_KIND_FLOAT>(kind).name, next_id});
    break;
  case BTF_KIND_DECL_TAG:
    name_to_id.insert({std::get<BTF_KIND_DECL_TAG>(kind).name, next_id});
    break;
  case BTF_KIND_TYPE_TAG:
    name_to_id.insert({std::get<BTF_KIND_TYPE_TAG>(kind).name, next_id});
    break;
  case BTF_KIND_ENUM64:
    if (std::get<BTF_KIND_ENUM64>(kind).name.has_value()) {
      name_to_id.insert(
          {std::get<BTF_KIND_ENUM64>(kind).name.value(), next_id});
    }
    break;
  default:
    throw std::runtime_error("unknown BTF_KIND");
  }
}
} // namespace libbtf