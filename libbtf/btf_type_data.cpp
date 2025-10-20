// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "btf_type_data.h"

#include "btf.h"
#include "btf_json.h"
#include "btf_parse.h"
#include "btf_write.h"
#include "cycle_detector.h"

#include <algorithm>
#include <iomanip>
#include <sstream>
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
  return get_kind_type<btf_kind_ptr>(id).type;
}

uint32_t btf_type_data::get_size(btf_type_id id) const {
  cycle_detector detector;
  return get_size_with_detector(id, detector);
}

uint32_t btf_type_data::get_size_with_detector(btf_type_id id,
                                               cycle_detector &detector) const {
  return detector.with_cycle_detection<uint32_t>(
      id,
      [this, id, &detector]() -> uint32_t {
        // Main processing logic - same as original but using detector
        return std::visit(
            [this, id, &detector](auto kind) -> uint32_t {
              if constexpr (std::is_same_v<decltype(kind), btf_kind_ptr>) {
                return sizeof(void *);
              } else if constexpr (btf_kind_traits<decltype(kind)>::has_type) {
                return get_size_with_detector(kind.type, detector);
              } else if constexpr (btf_kind_traits<
                                       decltype(kind)>::has_size_in_bytes) {
                return kind.size_in_bytes;
              } else if constexpr (std::is_same_v<decltype(kind),
                                                  btf_kind_array>) {
                return kind.count_of_elements *
                       get_size_with_detector(kind.element_type, detector);
              } else {
                return 0;
              }
            },
            get_kind(id));
      },
      []() -> uint32_t {
        // Cycle detected - return 0 to avoid infinite recursion
        return 0;
      });
}

void btf_type_data::to_json(
    std::ostream &out,
    std::optional<std::function<bool(btf_type_id)>> filter) const {
  btf_type_to_json(id_to_kind, out, filter);
}

std::vector<std::byte> btf_type_data::to_bytes() const {
  std::vector<btf_kind> kinds;
  for (const auto &[id, kind] : id_to_kind) {
    kinds.push_back(kind);
  }
  return btf_write_types(kinds);
}

void btf_type_data::replace(btf_type_id id, const btf_kind &kind) {
  if (id_to_kind.find(id) == id_to_kind.end()) {
    throw std::runtime_error("BTF type not found: " + std::to_string(id));
  }

  id_to_kind[id] = kind;
  update_name_to_id(id);
}

btf_type_id btf_type_data::append(const btf_kind &kind) {
  if (id_to_kind.size() > UINT32_MAX) {
    throw std::runtime_error("Too many BTF types");
  }
  btf_type_id next_id = static_cast<btf_type_id>(id_to_kind.size());
  id_to_kind.insert({next_id, kind});
  update_name_to_id(next_id);
  return next_id;
}

void btf_type_data::update_name_to_id(btf_type_id id) {

  auto name = get_type_name(id);
  if (!name.empty()) {
    name_to_id.insert({name, id});
  }
}

void btf_type_data::visit_depth_first(
    std::optional<std::function<bool(btf_type_id)>> before,
    std::optional<std::function<void(btf_type_id)>> after,
    btf_type_id id) const {
  if (before) {
    if (!(*before)(id)) {
      return;
    }
  }

  std::visit(
      [&, this](auto kind) {
        if constexpr (btf_kind_traits<decltype(kind)>::has_type) {
          visit_depth_first(before, after, kind.type);
        }
        if constexpr (btf_kind_traits<decltype(kind)>::has_index_type) {
          visit_depth_first(before, after, kind.index_type);
        }
        if constexpr (btf_kind_traits<decltype(kind)>::has_element_type) {
          visit_depth_first(before, after, kind.element_type);
        }
        if constexpr (btf_kind_traits<decltype(kind)>::has_members) {
          for (auto member : kind.members) {
            if constexpr (btf_kind_traits<decltype(member)>::has_type) {
              visit_depth_first(before, after, member.type);
            }
          }
        }
        if constexpr (btf_kind_traits<decltype(kind)>::has_return_type) {
          visit_depth_first(before, after, kind.return_type);
        }
        if constexpr (btf_kind_traits<decltype(kind)>::has_parameters) {
          for (auto param : kind.parameters) {
            if constexpr (btf_kind_traits<decltype(param)>::has_type) {
              visit_depth_first(before, after, param.type);
            }
          }
        }
      },
      get_kind(id));

  if (after) {
    (*after)(id);
  }
}

std::vector<btf_type_id> btf_type_data::dependency_order(
    std::optional<std::function<bool(btf_type_id)>> filter) const {
  std::map<btf_type_id, std::set<btf_type_id>> children;
  std::map<btf_type_id, std::set<btf_type_id>> parents;
  std::set<btf_type_id> filtered_types;
  std::vector<btf_type_id> result;

  // Build list of dependencies manually to avoid infinite recursion with
  // cycles. Previous implementation used visit_depth_first which could infinite
  // loop on cyclic types. This approach directly extracts immediate
  // dependencies without recursive traversal.
  for (const auto &[id, kind] : id_to_kind) {
    // Copy id to a local variable to workaround a bug in Apple's clang.
    // See: https://github.com/llvm/llvm-project/issues/48582
    auto local_id = id;
    bool match = false;
    if (!filter || (*filter)(local_id)) {
      match = true;
      filtered_types.insert(local_id);
    }

    // Initialize entries for this type
    if (parents.find(local_id) == parents.end()) {
      parents[local_id] = std::set<btf_type_id>();
    }
    if (children.find(local_id) == children.end()) {
      children[local_id] = std::set<btf_type_id>();
    }

    // Directly extract dependencies from the kind without recursive traversal
    std::visit(
        [&](auto k) {
          if constexpr (btf_kind_traits<decltype(k)>::has_type) {
            btf_type_id dep_id = k.type;
            if (dep_id != local_id &&
                id_to_kind.find(dep_id) != id_to_kind.end()) {
              children[local_id].insert(dep_id);
              if (parents.find(dep_id) == parents.end()) {
                parents[dep_id] = std::set<btf_type_id>();
              }
              parents[dep_id].insert(local_id);
            }
          }
          if constexpr (btf_kind_traits<decltype(k)>::has_index_type) {
            btf_type_id dep_id = k.index_type;
            if (dep_id != local_id &&
                id_to_kind.find(dep_id) != id_to_kind.end()) {
              children[local_id].insert(dep_id);
              if (parents.find(dep_id) == parents.end()) {
                parents[dep_id] = std::set<btf_type_id>();
              }
              parents[dep_id].insert(local_id);
            }
          }
          if constexpr (btf_kind_traits<decltype(k)>::has_element_type) {
            btf_type_id dep_id = k.element_type;
            if (dep_id != local_id &&
                id_to_kind.find(dep_id) != id_to_kind.end()) {
              children[local_id].insert(dep_id);
              if (parents.find(dep_id) == parents.end()) {
                parents[dep_id] = std::set<btf_type_id>();
              }
              parents[dep_id].insert(local_id);
            }
          }
          if constexpr (btf_kind_traits<decltype(k)>::has_return_type) {
            btf_type_id dep_id = k.return_type;
            if (dep_id != local_id &&
                id_to_kind.find(dep_id) != id_to_kind.end()) {
              children[local_id].insert(dep_id);
              if (parents.find(dep_id) == parents.end()) {
                parents[dep_id] = std::set<btf_type_id>();
              }
              parents[dep_id].insert(local_id);
            }
          }
          if constexpr (btf_kind_traits<decltype(k)>::has_members) {
            for (auto member : k.members) {
              if constexpr (btf_kind_traits<decltype(member)>::has_type) {
                btf_type_id dep_id = member.type;
                if (dep_id != local_id &&
                    id_to_kind.find(dep_id) != id_to_kind.end()) {
                  children[local_id].insert(dep_id);
                  if (parents.find(dep_id) == parents.end()) {
                    parents[dep_id] = std::set<btf_type_id>();
                  }
                  parents[dep_id].insert(local_id);
                }
              }
            }
          }
          if constexpr (btf_kind_traits<decltype(k)>::has_parameters) {
            for (auto param : k.parameters) {
              if constexpr (btf_kind_traits<decltype(param)>::has_type) {
                btf_type_id dep_id = param.type;
                if (dep_id != local_id &&
                    id_to_kind.find(dep_id) != id_to_kind.end()) {
                  children[local_id].insert(dep_id);
                  if (parents.find(dep_id) == parents.end()) {
                    parents[dep_id] = std::set<btf_type_id>();
                  }
                  parents[dep_id].insert(local_id);
                }
              }
            }
          }
        },
        kind);
  }

  // Perform topological sort with cycle breaking
  // Add safety limit to prevent infinite loops in case of bugs in
  // cycle-breaking logic
  size_t previous_size = 0;
  size_t iteration_count = 0;
  const size_t max_iterations =
      id_to_kind.size() * 3; // Safety limit to prevent infinite loops in cycles

  while (!parents.empty() && iteration_count < max_iterations) {
    iteration_count++;
    std::vector<btf_type_id> types_to_remove;

    // Find all types with no parents.
    for (auto &[id, child_set] : parents) {
      if (child_set.empty()) {
        types_to_remove.push_back(id);
      }
    }

    // If we can't make progress (no types with empty parents),
    // we have cycles. Break them by selecting arbitrary types.
    if (types_to_remove.empty()) {
      // Pick the first type with the fewest dependencies to break the cycle
      btf_type_id min_id = parents.begin()->first;
      size_t min_deps = parents.begin()->second.size();
      for (const auto &[id, deps] : parents) {
        if (deps.size() < min_deps) {
          min_id = id;
          min_deps = deps.size();
        }
      }
      types_to_remove.push_back(min_id);
    }

    if (types_to_remove.empty()) {
      // Safety: force progress if we're still stuck
      types_to_remove.push_back(parents.begin()->first);
    }

    previous_size = parents.size();

    // Remove these parents from all children.
    for (auto id : types_to_remove) {
      for (auto child : children[id]) {
        parents[child].erase(id);
      }
      parents.erase(id);
    }
    // Append these types to the result.
    result.insert(result.end(), types_to_remove.begin(), types_to_remove.end());
  }

  // Remove types that are not children of the filtered type.
  std::vector<btf_type_id> filtered_result;
  for (auto id : result) {
    if (filtered_types.find(id) != filtered_types.end()) {
      filtered_result.push_back(id);
    }
  }

  std::reverse(filtered_result.begin(), filtered_result.end());
  return filtered_result;
}

void btf_type_data::to_c_header(
    std::ostream &out,
    std::optional<std::function<bool(btf_type_id)>> filter) const {
  std::set<btf_type_id> declared_types;

  size_t indent = 0;
  out << "#pragma once\n\n";

  // Print each type in dependency order.
  for (auto id : dependency_order(filter)) {
    if (get_type_name(id).empty()) {
      continue;
    }
    std::visit(
        [&, this](auto kind) {
          if constexpr (std::is_same_v<decltype(kind), btf_kind_typedef>) {
            out << "typedef ";
            out << get_type_declaration(kind.type, kind.name, indent)
                << ";\n\n";
          } else if constexpr (std::is_same_v<decltype(kind),
                                              btf_kind_struct>) {
            out << get_type_declaration(id, "", indent) << ";\n\n";
          } else if constexpr (std::is_same_v<decltype(kind), btf_kind_union>) {
            out << get_type_declaration(id, "", indent) << ";\n\n";
          } else if constexpr (std::is_same_v<decltype(kind), btf_kind_fwd>) {
            out << (kind.is_struct ? "union" : "struct ") << kind.name
                << ";\n\n";
          } else if constexpr (std::is_same_v<decltype(kind), btf_kind_var>) {
            out << get_type_declaration(kind.type, kind.name, indent)
                << ";\n\n";
          } else if constexpr (std::is_same_v<decltype(kind),
                                              btf_kind_function>) {
            if (kind.linkage == BTF_LINKAGE_STATIC) {
              out << "static ";
            } else if (kind.linkage == BTF_LINKAGE_EXTERN) {
              out << "extern ";
            }
            out << get_type_declaration(kind.type, kind.name, indent)
                << ";\n\n";
          }
        },
        get_kind(id));
  }
}

std::string btf_type_data::get_type_name(btf_type_id id) const {
  // Use visit to return the name if the type has it.
  auto kind = get_kind(id);
  return std::visit(
      [](auto kind) -> std::string {
        if constexpr (btf_kind_traits<decltype(kind)>::has_optional_name) {
          return kind.name.value_or("");
        } else if constexpr (btf_kind_traits<decltype(kind)>::has_name) {
          return kind.name;
        } else {
          return "";
        }
      },
      get_kind(id));
}

std::string btf_type_data::get_qualified_type_name_with_detector(
    btf_type_id id, cycle_detector &detector) const {
  return detector.with_cycle_detection<std::string>(
      id,
      [this, id, &detector]() -> std::string {
        // Main processing logic - adapted from original but using detector
        auto kind = get_kind(id);
        return std::visit(
            [this, &detector](auto kind) -> std::string {
              // Add possible qualifiers.
              std::string qualifier;
              if constexpr (std::is_same_v<decltype(kind), btf_kind_const>) {
                qualifier = "const ";
              } else if constexpr (std::is_same_v<decltype(kind),
                                                  btf_kind_volatile>) {
                qualifier = "volatile ";
              } else if constexpr (std::is_same_v<decltype(kind),
                                                  btf_kind_restrict>) {
                qualifier = "restrict ";
              }

              std::string suffix;
              if constexpr (std::is_same_v<decltype(kind), btf_kind_ptr>) {
                suffix = "*";
              }

              if constexpr (btf_kind_traits<
                                decltype(kind)>::has_optional_name) {
                return qualifier + kind.name.value_or("") + suffix;
              } else if constexpr (btf_kind_traits<decltype(kind)>::has_name) {
                return kind.name + suffix;
              } else if constexpr (btf_kind_traits<decltype(kind)>::has_type) {
                return qualifier +
                       this->get_qualified_type_name_with_detector(kind.type,
                                                                   detector) +
                       suffix;
              } else if constexpr (std::is_same_v<decltype(kind),
                                                  btf_kind_void>) {
                return qualifier + "void" + suffix;
              } else {
                return "";
              }
            },
            kind);
      },
      [id]() -> std::string {
        // Cycle detected - return placeholder
        return "/* cyclic type " + std::to_string(id) + " */";
      });
}

btf_type_id btf_type_data::get_descendant_type_id_with_detector(
    btf_type_id id, cycle_detector &detector) const {
  return detector.with_cycle_detection<btf_type_id>(
      id,
      [this, id, &detector]() -> btf_type_id {
        // Main processing logic - same as original but using detector
        return std::visit(
            [id, this, &detector](auto kind) -> btf_type_id {
              if constexpr (btf_kind_traits<decltype(kind)>::has_type) {
                return this->get_descendant_type_id_with_detector(kind.type,
                                                                  detector);
              } else {
                return id;
              }
            },
            get_kind(id));
      },
      [id]() -> btf_type_id {
        // Cycle detected - return current id to break the cycle
        return id;
      });
}

std::string btf_type_data::get_type_declaration(btf_type_id id,
                                                const std::string &name,
                                                size_t indent) const {
  cycle_detector detector;
  return get_type_declaration_with_detector(id, name, indent, detector);
}

std::string btf_type_data::get_type_declaration_with_detector(
    btf_type_id id, const std::string &name, size_t indent,
    cycle_detector &detector) const {
  return detector.with_cycle_detection<std::string>(
      id,
      [this, id, &name, indent, &detector]() -> std::string {
        // Build a string of type qualifiers.
        std::string result = std::string(indent, ' ');
        auto kind = get_kind(id);
        std::visit(
            [&](auto kind) {
              if constexpr (std::is_same_v<decltype(kind), btf_kind_typedef>) {
                result += get_type_name(id) + " " + name;
              } else if constexpr (std::is_same_v<decltype(kind),
                                                  btf_kind_array>) {
                auto local_name = name;
                if (!local_name.empty() && local_name[0] == '*') {
                  local_name = "(" + local_name + ")";
                }
                auto local_type = get_type_name(kind.element_type);
                if (local_type.empty()) {
                  local_type = get_type_declaration_with_detector(
                      kind.element_type, "", indent, detector);
                }
                result += local_type + " " + local_name + "[" +
                          std::to_string(kind.count_of_elements) + "]";
              } else if constexpr (std::is_same_v<decltype(kind),
                                                  btf_kind_const>) {
                result += "const " + get_type_declaration_with_detector(
                                         kind.type, name, indent, detector);
              } else if constexpr (std::is_same_v<decltype(kind),
                                                  btf_kind_volatile>) {
                result += "volatile " + get_type_declaration_with_detector(
                                            kind.type, name, indent, detector);
              } else if constexpr (std::is_same_v<decltype(kind),
                                                  btf_kind_restrict>) {
                result += "restrict " + get_type_declaration_with_detector(
                                            kind.type, name, indent, detector);
              } else if constexpr (std::is_same_v<decltype(kind),
                                                  btf_kind_ptr>) {
                result = get_type_declaration_with_detector(
                    kind.type, "*" + name, indent, detector);
              } else if constexpr (std::is_same_v<decltype(kind),
                                                  btf_kind_struct>) {
                if (kind.name.has_value()) {
                  result = "struct " + kind.name.value_or("") + " {\n";
                } else {
                  result = "struct {\n";
                }
                for (auto member : kind.members) {
                  std::string type_name = get_type_name(member.type);
                  if (type_name.empty()) {
                    result += get_type_declaration_with_detector(
                                  member.type, member.name.value_or(""),
                                  indent + 2, detector) +
                              ";\n";
                  } else {
                    result += std::string(indent + 2, ' ') + type_name + " " +
                              member.name.value_or("") + ";\n";
                  }
                }
                result += std::string(indent, ' ') + "}";
                if (!name.empty()) {
                  result += " " + name;
                }
              } else if constexpr (std::is_same_v<decltype(kind),
                                                  btf_kind_union>) {
                if (kind.name.has_value()) {
                  result += "union " + kind.name.value_or("") + " {\n";
                } else {
                  result += "union {\n";
                }
                for (auto member : kind.members) {
                  std::string type_name = get_type_name(member.type);
                  if (type_name.empty()) {
                    result += get_type_declaration_with_detector(
                                  member.type, member.name.value_or(""),
                                  indent + 2, detector) +
                              ";\n";
                  } else {
                    result += std::string(indent + 2, ' ') + type_name + " " +
                              member.name.value_or("") + ";\n";
                  }
                }
                result += std::string(indent, ' ') + "}";
                if (!name.empty()) {
                  result += " " + name;
                }
              } else if constexpr (std::is_same_v<
                                       decltype(kind),
                                       btf_kind_function_prototype>) {
                result += get_qualified_type_name_with_detector(
                              kind.return_type, detector) +
                          " " + name + "(";
                for (auto param : kind.parameters) {
                  result += get_qualified_type_name_with_detector(param.type,
                                                                  detector);
                  if (!param.name.empty()) {
                    result += " " + param.name;
                  }
                  result += ", ";
                }
                if (kind.parameters.size() > 0) {
                  result.pop_back();
                  result.pop_back();
                }
                result += ")";
              } else if constexpr (!btf_kind_traits<decltype(kind)>::has_type) {
                result += get_type_name(id) + " " + name;
              }
            },
            kind);

        return result;
      },
      [this, id, &name, indent]() -> std::string {
        // Cycle detected - return just the type name if available, or a
        // placeholder
        auto type_name = get_type_name(id);
        if (!type_name.empty()) {
          return std::string(indent, ' ') + type_name + " " + name;
        } else {
          return std::string(indent, ' ') + "/* cyclic type " +
                 std::to_string(id) + " */ " + name;
        }
      });
}

} // namespace libbtf