// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "btf_json.h"

#include "btf_c_type.h"

#include <functional>
#include <set>

namespace libbtf {
std::string pretty_print_json(const std::string &input) {
  // Walk over the input string, inserting newlines and indentation.
  std::string output;
  int indent = 0;
  bool in_string = false;
  for (size_t i = 0; i < input.size(); i++) {
    char c = input[i];
    if (c == '"') {
      in_string = !in_string;
    }
    if (in_string) {
      output += c;
      continue;
    }
    switch (c) {
    case '{':
    case '[':
      output += c;
      if (i + 1 < input.size() && input[i + 1] != '}' && input[i + 1] != ']') {
        output += '\n';
        indent += 2;
        output += std::string(indent, ' ');
      } else {
        output += input[++i];
      }
      break;
    case '}':
    case ']':
      output += '\n';
      indent -= 2;
      output += std::string(indent, ' ');
      output += c;
      break;
    case ',':
      output += c;
      output += '\n';
      output += std::string(indent, ' ');
      break;
    case ':':
      output += c;
      output += ' ';
      break;
    default:
      output += c;
      break;
    }
  }
  return output;
}

template <typename T>
static void _print_json_value(bool &first, const std::string &name, T value,
                              std::ostream &out) {
  // If T is a string type, print it as a string, then quote the value.
  if constexpr (std::is_same_v<T, std::string> ||
                std::is_same_v<T, const char *> || std::is_same_v<T, char *>) {
    out << (first ? "" : ",") << "\"" << name << "\":\"" << value << "\"";
    first = false;
  }
  // If T is a bool, print it as a string, then quote the value.
  else if constexpr (std::is_same_v<T, bool>) {
    out << (first ? "" : ",") << "\"" << name
        << "\":" << (value ? "true" : "false");
    first = false;
  }
  // If T is a std::optional<std::string>, then only print if it's present
  else if constexpr (std::is_same_v<T, std::optional<std::string>>) {
    if (value.has_value()) {
      out << (first ? "" : ",") << "\"" << name << "\":\"" << value.value()
          << "\"";
      first = false;
    }
  } else {
    out << (first ? "" : ",") << "\"" << name << "\":" << std::to_string(value);
    first = false;
  }
}

void print_array_start(const std::string &name, std::ostream &out) {
  out << "\"" << name << "\":[";
}

void print_array_end(std::ostream &out) { out << "]"; }

#define PRINT_JSON_FIXED(name, value)                                          \
  _print_json_value(first, name, value, out);

#define PRINT_JSON_VALUE(object, value)                                        \
  _print_json_value(first, #value, object.value, out)

#define PRINT_JSON_TYPE(object, value)                                         \
  if (!first) {                                                                \
    out << ",";                                                                \
  } else {                                                                     \
    first = false;                                                             \
  };                                                                           \
  out << "\"" << #value << "\":";                                              \
  print_btf_kind(object.value, id_to_kind.at(object.value));

#define PRINT_JSON_ARRAY_START(object, value)                                  \
  if (!first) {                                                                \
    out << ",";                                                                \
  } else {                                                                     \
    first = false;                                                             \
  }                                                                            \
  print_array_start(#value, out);                                              \
  {                                                                            \
    bool first = true;

#define PRINT_JSON_ARRAY_END()                                                 \
  print_array_end(out);                                                        \
  }

#define PRINT_JSON_OBJECT_START()                                              \
  if (!first) {                                                                \
    out << ",";                                                                \
  } else {                                                                     \
    first = false;                                                             \
  };                                                                           \
  {                                                                            \
    bool first = true;                                                         \
    out << "{";

#define PRINT_JSON_OBJECT_END()                                                \
  out << "}";                                                                  \
  }

// Suppress C4456 on when using MSVC:
// declaration of 'first' hides previous local declaration
#pragma warning(push)
#pragma warning(disable : 4456)

void btf_type_to_json(const std::map<btf_type_id, btf_kind> &id_to_kind,
                      std::ostream &out) {
  std::function<void(btf_type_id, const btf_kind &)> print_btf_kind =
      [&](btf_type_id id, const btf_kind &kind) {
        bool first = true;
        PRINT_JSON_OBJECT_START();
        PRINT_JSON_FIXED("id", id);
        switch (kind.index()) {
        case 0:
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_VOID");
          break;
        case BTF_KIND_INT: {
          auto &kind_int = std::get<BTF_KIND_INT>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_INT");
          PRINT_JSON_VALUE(kind_int, name);
          PRINT_JSON_VALUE(kind_int, size_in_bytes);
          PRINT_JSON_VALUE(kind_int, offset_from_start_in_bits);
          PRINT_JSON_VALUE(kind_int, field_width_in_bits);
          PRINT_JSON_VALUE(kind_int, is_signed);
          PRINT_JSON_VALUE(kind_int, is_char);
          PRINT_JSON_VALUE(kind_int, is_bool);
          break;
        }
        case BTF_KIND_PTR: {
          auto &kind_ptr = std::get<BTF_KIND_PTR>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_PTR");
          PRINT_JSON_TYPE(kind_ptr, type);
          break;
        }
        case BTF_KIND_ARRAY: {
          auto &kind_array = std::get<BTF_KIND_ARRAY>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_ARRAY");
          PRINT_JSON_VALUE(kind_array, count_of_elements);
          PRINT_JSON_TYPE(kind_array, element_type);
          PRINT_JSON_TYPE(kind_array, index_type);
          break;
        }
        case BTF_KIND_STRUCT: {
          auto &kind_struct = std::get<BTF_KIND_STRUCT>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_STRUCT");
          PRINT_JSON_VALUE(kind_struct, name);
          PRINT_JSON_VALUE(kind_struct, size_in_bytes);
          PRINT_JSON_ARRAY_START(kind_struct, members);
          for (auto &member : kind_struct.members) {
            PRINT_JSON_OBJECT_START();
            PRINT_JSON_VALUE(member, name);
            PRINT_JSON_VALUE(member, offset_from_start_in_bits);
            PRINT_JSON_TYPE(member, type);
            PRINT_JSON_OBJECT_END();
          }
          PRINT_JSON_ARRAY_END();
          break;
        }
        case BTF_KIND_UNION: {
          auto kind_union = std::get<BTF_KIND_UNION>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_UNION");
          PRINT_JSON_VALUE(kind_union, name);
          PRINT_JSON_VALUE(kind_union, size_in_bytes);
          PRINT_JSON_ARRAY_START(kind_union, members);
          for (auto &member : kind_union.members) {
            PRINT_JSON_OBJECT_START();
            PRINT_JSON_VALUE(member, name);
            PRINT_JSON_VALUE(member, offset_from_start_in_bits);
            PRINT_JSON_TYPE(member, type);
            PRINT_JSON_OBJECT_END();
          }
          PRINT_JSON_ARRAY_END();
          break;
        }
        case BTF_KIND_ENUM: {
          auto &kind_enum = std::get<BTF_KIND_ENUM>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_ENUM");
          PRINT_JSON_VALUE(kind_enum, name);
          PRINT_JSON_VALUE(kind_enum, size_in_bytes);
          PRINT_JSON_ARRAY_START(kind_union, members);
          for (auto &member : kind_enum.members) {
            PRINT_JSON_OBJECT_START();
            PRINT_JSON_VALUE(member, name);
            PRINT_JSON_VALUE(member, value);
            PRINT_JSON_OBJECT_END();
          }
          PRINT_JSON_ARRAY_END();
          break;
        }
        case BTF_KIND_FWD: {
          auto kind_fwd = std::get<BTF_KIND_FWD>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_FWD");
          PRINT_JSON_VALUE(kind_fwd, name);
          PRINT_JSON_VALUE(kind_fwd, is_struct);
          break;
        }
        case BTF_KIND_TYPEDEF: {
          auto &kind_typedef = std::get<BTF_KIND_TYPEDEF>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_TYPEDEF");
          PRINT_JSON_VALUE(kind_typedef, name);
          PRINT_JSON_TYPE(kind_typedef, type);
          break;
        }
        case BTF_KIND_VOLATILE: {
          auto &kind_volatile = std::get<BTF_KIND_VOLATILE>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_VOLATILE");
          PRINT_JSON_TYPE(kind_volatile, type);
          break;
        }
        case BTF_KIND_CONST: {
          auto &kind_const = std::get<BTF_KIND_CONST>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_CONST");
          PRINT_JSON_TYPE(kind_const, type);
          break;
        }
        case BTF_KIND_RESTRICT: {
          auto &kind_restrict = std::get<BTF_KIND_RESTRICT>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_RESTRICT");
          PRINT_JSON_TYPE(kind_restrict, type);
          break;
        }
        case BTF_KIND_FUNCTION: {
          auto kind_func = std::get<BTF_KIND_FUNCTION>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_FUNC");
          PRINT_JSON_VALUE(kind_func, name);
          switch (kind_func.linkage) {
          case 0:
            PRINT_JSON_FIXED("linkage", "BTF_FUNC_STATIC");
            break;
          case 1:
            PRINT_JSON_FIXED("linkage", "BTF_FUNC_GLOBAL");
            break;
          case 2:
            PRINT_JSON_FIXED("linkage", "BTF_FUNC_EXTERN");
            break;
          default:
            PRINT_JSON_FIXED("linkage", "UNKNOWN");
            break;
          }
          PRINT_JSON_TYPE(kind_func, type);
          break;
        }
        case BTF_KIND_FUNCTION_PROTOTYPE: {
          auto &kind_func_proto = std::get<BTF_KIND_FUNCTION_PROTOTYPE>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_FUNC_PROTO");
          PRINT_JSON_ARRAY_START(kind_func_proto, parameters);
          for (auto &parameter : kind_func_proto.parameters) {
            PRINT_JSON_OBJECT_START();
            PRINT_JSON_VALUE(parameter, name);
            PRINT_JSON_TYPE(parameter, type);
            PRINT_JSON_OBJECT_END();
          }
          PRINT_JSON_ARRAY_END();
          PRINT_JSON_TYPE(kind_func_proto, return_type);
          break;
        }
        case BTF_KIND_VAR: {
          auto &kind_var = std::get<BTF_KIND_VAR>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_VAR");
          PRINT_JSON_VALUE(kind_var, name);
          switch (kind_var.linkage) {
          case 0:
            PRINT_JSON_FIXED("linkage", "BTF_LINKAGE_GLOBAL");
            break;
          case 1:
            PRINT_JSON_FIXED("linkage", "BTF_LINKAGE_STATIC");
            break;
          default:
            PRINT_JSON_FIXED("linkage", "UNKNOWN");
            break;
          }
          PRINT_JSON_TYPE(kind_var, type);
          break;
        }
        case BTF_KIND_DATA_SECTION: {
          auto &kind_datasec = std::get<BTF_KIND_DATA_SECTION>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_DATASEC");
          PRINT_JSON_VALUE(kind_datasec, name);
          PRINT_JSON_VALUE(kind_datasec, size);
          PRINT_JSON_ARRAY_START(kind_datasec, members);
          for (auto &data : kind_datasec.members) {
            PRINT_JSON_OBJECT_START();
            PRINT_JSON_VALUE(data, offset);
            PRINT_JSON_VALUE(data, size);
            PRINT_JSON_TYPE(data, type);
            PRINT_JSON_OBJECT_END();
          }
          PRINT_JSON_ARRAY_END();
          break;
        }
        case BTF_KIND_FLOAT: {
          auto kind_float = std::get<BTF_KIND_FLOAT>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_FLOAT");
          PRINT_JSON_VALUE(kind_float, name);
          PRINT_JSON_VALUE(kind_float, size_in_bytes);
          break;
        }
        case BTF_KIND_DECL_TAG: {
          auto &kind_decl_tag = std::get<BTF_KIND_DECL_TAG>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_DECL_TAG");
          PRINT_JSON_VALUE(kind_decl_tag, name);
          PRINT_JSON_TYPE(kind_decl_tag, type);
          break;
        }
        case BTF_KIND_TYPE_TAG: {
          auto &kind_type_tag = std::get<BTF_KIND_TYPE_TAG>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_TYPE_TAG");
          PRINT_JSON_VALUE(kind_type_tag, name);
          PRINT_JSON_TYPE(kind_type_tag, type);
          break;
        }
        case BTF_KIND_ENUM64: {
          auto &kind_enum = std::get<BTF_KIND_ENUM64>(kind);
          PRINT_JSON_FIXED("kind_type", "BTF_KIND_ENUM64");
          PRINT_JSON_VALUE(kind_enum, name);
          PRINT_JSON_VALUE(kind_enum, size_in_bytes);
          PRINT_JSON_ARRAY_START(kind_enum, members);
          for (auto &member : kind_enum.members) {
            PRINT_JSON_OBJECT_START();
            PRINT_JSON_VALUE(member, name);
            PRINT_JSON_VALUE(member, value);
            PRINT_JSON_OBJECT_END();
          }
          PRINT_JSON_ARRAY_END();
          break;
        }
        default:
          PRINT_JSON_FIXED("kind_type", "UNKNOWN");
        }
        PRINT_JSON_OBJECT_END();
      };

  // Determine the list of types that are not referenced by other types. These
  // are the root types.
  std::set<btf_type_id> root_types;

  // Add all types as root types.
  for (auto &[id, kind] : id_to_kind) {
    root_types.insert(id);
  }

  // Erase the VOID type.
  root_types.erase(0);

  // Remove all types that are referenced by other types.
  for (auto &[id, kind] : id_to_kind) {
    switch (kind.index()) {
    case BTF_KIND_PTR:
      root_types.erase(std::get<BTF_KIND_PTR>(kind).type);
      break;
    case BTF_KIND_ARRAY:
      root_types.erase(std::get<BTF_KIND_ARRAY>(kind).element_type);
      root_types.erase(std::get<BTF_KIND_ARRAY>(kind).index_type);
      break;
    case BTF_KIND_STRUCT:
      for (auto &member : std::get<BTF_KIND_STRUCT>(kind).members) {
        root_types.erase(member.type);
      }
      break;
    case BTF_KIND_UNION:
      for (auto &member : std::get<BTF_KIND_UNION>(kind).members) {
        root_types.erase(member.type);
      }
      break;
    case BTF_KIND_TYPEDEF:
      root_types.erase(std::get<BTF_KIND_TYPEDEF>(kind).type);
      break;
    case BTF_KIND_VOLATILE:
      root_types.erase(std::get<BTF_KIND_VOLATILE>(kind).type);
      break;
    case BTF_KIND_CONST:
      root_types.erase(std::get<BTF_KIND_CONST>(kind).type);
      break;
    case BTF_KIND_RESTRICT:
      root_types.erase(std::get<BTF_KIND_RESTRICT>(kind).type);
      break;
    case BTF_KIND_FUNCTION_PROTOTYPE:
      for (auto &param :
           std::get<BTF_KIND_FUNCTION_PROTOTYPE>(kind).parameters) {
        root_types.erase(param.type);
      }
      root_types.erase(std::get<BTF_KIND_FUNCTION_PROTOTYPE>(kind).return_type);
      break;
    case BTF_KIND_FUNCTION:
      root_types.erase(std::get<BTF_KIND_FUNCTION>(kind).type);
      break;
    case BTF_KIND_VAR:
      root_types.erase(std::get<BTF_KIND_VAR>(kind).type);
      break;
    case BTF_KIND_DATA_SECTION:
      for (auto &variable : std::get<BTF_KIND_DATA_SECTION>(kind).members) {
        root_types.erase(variable.type);
      }
      break;
    case BTF_KIND_DECL_TAG:
      root_types.erase(std::get<BTF_KIND_DECL_TAG>(kind).type);
      break;
    case BTF_KIND_TYPE_TAG:
      root_types.erase(std::get<BTF_KIND_TYPE_TAG>(kind).type);
      break;
    }
  }
  bool first = true;
  PRINT_JSON_OBJECT_START();
  PRINT_JSON_ARRAY_START("", btf_kinds);
  for (const auto &[id, kind] : id_to_kind) {
    // Skip non-root types.
    if (root_types.find(id) == root_types.end()) {
      continue;
    }

    out << (first ? "" : ",");
    first = false;
    print_btf_kind(id, kind);
  }
  PRINT_JSON_ARRAY_END();
  PRINT_JSON_OBJECT_END();
}

#pragma warning(pop)

} // namespace libbtf