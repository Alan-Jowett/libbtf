// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "btf_write.h"
#include "btf_c_type.h"

#include <cstring>

namespace libbtf {

template <typename T>
static void _write_btf(std::vector<std::byte> &btf, const T &value) {
  size_t length = 0;
  size_t offset = btf.size();
  if constexpr (std::is_same<T, std::string>::value) {
    length = value.length();
    btf.resize(offset + length + 1);
    memcpy(btf.data() + offset, value.c_str(), length + 1);
  } else if constexpr (std::is_same<T, std::vector<std::byte>>::value) {
    length = value.size();
    btf.resize(offset + length);
    memcpy(btf.data() + offset, value.data(), length);
  } else {
    length = sizeof(T);
    btf.resize(offset + length);
    memcpy(btf.data() + offset, &value, length);
  }
}

std::vector<std::byte> btf_write_types(const std::vector<btf_kind> &btf_kind) {
  std::vector<std::byte> btf;
  std::vector<std::byte> string_table_bytes;
  std::map<std::string, uint32_t> string_table_map;
  std::vector<std::byte> type_table_bytes;

  auto string_to_offset =
      [&](const std::optional<std::string> &str) -> uint32_t {
    if (!str) {
      return 0;
    }
    auto it = string_table_map.find(*str);
    if (it != string_table_map.end()) {
      return it->second;
    }
    size_t offset = string_table_bytes.size();
    _write_btf(string_table_bytes, *str);
    string_table_map[*str] = static_cast<uint32_t>(offset);
    return static_cast<uint32_t>(offset);
  };

  string_to_offset("");

  auto pack_btf_int_data = [](bool is_signed, bool is_char, bool is_bool,
                              size_t offset, size_t bits) {
    uint32_t value = 0;
    value |= is_signed ? BTF_INT_SIGNED : 0;
    value |= is_char ? BTF_INT_CHAR : 0;
    value |= is_bool ? BTF_INT_BOOL : 0;
    value = value << 24;
    value |= offset & UINT8_MAX << 16;
    value |= bits & UINT8_MAX;
    return value;
  };

  for (const auto &kind : btf_kind) {
    auto pack_btf_info = [&](size_t vlen = 0, bool flag = false) {
      union {
        struct {
          int vlen : 16;
          int unused : 8;
          int kind : 5;
          int unused2 : 2;
          int flag : 1;
        };
        uint32_t value;
      } info;
      info.vlen = vlen;
      info.kind = kind.index();
      info.flag = flag;
      return info.value;
    };
    switch (kind.index()) {
    case BTF_KIND_INT: {
      const auto &int_type = std::get<BTF_KIND_INT>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(int_type.name),
                     .info = pack_btf_info(),
                     .size = int_type.size_in_bytes,
                 });
      _write_btf(type_table_bytes,
                 pack_btf_int_data(int_type.is_signed, int_type.is_char,
                                   int_type.is_bool,
                                   int_type.offset_from_start_in_bits,
                                   int_type.field_width_in_bits));
      break;
    }
    case BTF_KIND_PTR: {
      const auto &ptr_type = std::get<BTF_KIND_PTR>(kind);
      _write_btf(type_table_bytes, btf_type_t{
                                       .info = pack_btf_info(),
                                       .type = ptr_type.type,
                                   });
      break;
    }
    case BTF_KIND_ARRAY: {
      const auto &array_type = std::get<BTF_KIND_ARRAY>(kind);
      _write_btf(type_table_bytes, btf_type_t{
                                       .info = pack_btf_info(),
                                   });
      _write_btf(type_table_bytes, btf_array_t{
                                       .type = array_type.element_type,
                                       .index_type = array_type.index_type,
                                       .nelems = array_type.count_of_elements,
                                   });
      break;
    }
    case BTF_KIND_STRUCT: {
      const auto &struct_type = std::get<BTF_KIND_STRUCT>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(struct_type.name),
                     .info = pack_btf_info(struct_type.members.size()),
                     .size = struct_type.size_in_bytes,
                 });
      for (const auto &member : struct_type.members) {
        _write_btf(type_table_bytes,
                   btf_member_t{
                       .name_off = string_to_offset(member.name),
                       .type = member.type,
                       .offset = member.offset_from_start_in_bits,
                   });
      }
      break;
    }
    case BTF_KIND_UNION: {
      const auto &union_type = std::get<BTF_KIND_UNION>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(union_type.name),
                     .info = pack_btf_info(union_type.members.size()),
                     .size = union_type.size_in_bytes,
                 });
      for (const auto &member : union_type.members) {
        _write_btf(type_table_bytes,
                   btf_member_t{
                       .name_off = string_to_offset(member.name),
                       .type = member.type,
                       .offset = member.offset_from_start_in_bits,
                   });
      }
      break;
    }
    case BTF_KIND_ENUM: {
      const auto &enum_type = std::get<BTF_KIND_ENUM>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(enum_type.name),
                     .info = pack_btf_info(enum_type.members.size()),
                     .size = enum_type.size_in_bytes,
                 });
      for (const auto &member : enum_type.members) {
        _write_btf(type_table_bytes,
                   btf_enum_t{
                       .name_off = string_to_offset(member.name),
                       .val = member.value,
                   });
      }
      break;
    }
    case BTF_KIND_FWD: {
      const auto &fwd_type = std::get<BTF_KIND_FWD>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(fwd_type.name),
                     .info = pack_btf_info(),
                 });
      break;
    }
    case BTF_KIND_TYPEDEF: {
      const auto &typedef_type = std::get<BTF_KIND_TYPEDEF>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(typedef_type.name),
                     .info = pack_btf_info(),
                     .type = typedef_type.type,
                 });
      break;
    }
    case BTF_KIND_VOLATILE: {
      const auto &volatile_type = std::get<BTF_KIND_VOLATILE>(kind);
      _write_btf(type_table_bytes, btf_type_t{
                                       .info = pack_btf_info(),
                                       .type = volatile_type.type,
                                   });
      break;
    }
    case BTF_KIND_CONST: {
      const auto &const_type = std::get<BTF_KIND_CONST>(kind);
      _write_btf(type_table_bytes, btf_type_t{
                                       .info = pack_btf_info(),
                                       .type = const_type.type,
                                   });
      break;
    }
    case BTF_KIND_RESTRICT: {
      const auto &restrict_type = std::get<BTF_KIND_RESTRICT>(kind);
      _write_btf(type_table_bytes, btf_type_t{
                                       .info = pack_btf_info(),
                                       .type = restrict_type.type,
                                   });
      break;
    }
    case BTF_KIND_FUNCTION: {
      const auto &func_type = std::get<BTF_KIND_FUNCTION>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(func_type.name),
                     .info = pack_btf_info(func_type.linkage),
                     .type = func_type.type,
                 });
      break;
    }
    case BTF_KIND_FUNCTION_PROTOTYPE: {
      const auto &func_proto_type = std::get<BTF_KIND_FUNCTION_PROTOTYPE>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .info = pack_btf_info(func_proto_type.parameters.size()),
                     .type = func_proto_type.return_type,
                 });
      for (const auto &parameter : func_proto_type.parameters) {
        _write_btf(type_table_bytes,
                   btf_param_t{
                       .name_off = string_to_offset(parameter.name),
                       .type = parameter.type,
                   });
      }
      break;
    }
    case BTF_KIND_VAR: {
      const auto &var_type = std::get<BTF_KIND_VAR>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(var_type.name),
                     .info = pack_btf_info(),
                     .type = var_type.type,
                 });
      _write_btf(type_table_bytes, static_cast<uint32_t>(var_type.linkage));
      break;
    }
    case BTF_KIND_DATA_SECTION: {
      const auto &data_section_type = std::get<BTF_KIND_DATA_SECTION>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(data_section_type.name),
                     .info = pack_btf_info(data_section_type.members.size()),
                 });
      for (const auto &member : data_section_type.members) {
        _write_btf(type_table_bytes, btf_var_secinfo_t{
                                         .type = member.type,
                                         .offset = member.offset,
                                         .size = member.size,
                                     });
      }

      break;
    }
    case BTF_KIND_FLOAT: {
      const auto &float_type = std::get<BTF_KIND_FLOAT>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(float_type.name),
                     .info = pack_btf_info(),
                     .size = float_type.size_in_bytes,
                 });
      break;
    }
    case BTF_KIND_DECL_TAG: {
      const auto &decl_tag_type = std::get<BTF_KIND_DECL_TAG>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(decl_tag_type.name),
                     .info = pack_btf_info(),
                     .type = decl_tag_type.type,
                 });
      _write_btf(
          type_table_bytes,
          btf_decl_tag_t{.component_idx = decl_tag_type.component_index});
      break;
    }
    case BTF_KIND_TYPE_TAG: {
      const auto &type_tag_type = std::get<BTF_KIND_TYPE_TAG>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(type_tag_type.name),
                     .info = pack_btf_info(),
                     .type = type_tag_type.type,
                 });
      break;
    }
    case BTF_KIND_ENUM64: {
      const auto &enum64_type = std::get<BTF_KIND_ENUM64>(kind);
      _write_btf(type_table_bytes,
                 btf_type_t{
                     .name_off = string_to_offset(enum64_type.name),
                     .info = pack_btf_info(enum64_type.members.size()),
                     .size = enum64_type.size_in_bytes,
                 });
      for (const auto &member : enum64_type.members) {
        btf_enum64_t enum_member = {0};
        enum_member.name_off = string_to_offset(member.name);
        enum_member.val_lo32 = member.value & 0xFFFFFFFF;
        enum_member.val_hi32 = member.value >> 32;
        _write_btf(type_table_bytes, enum_member);
      }
      break;
    }
    }
  }

  // Write the BTF header.
  _write_btf(
      btf, btf_header_t{
               .magic = BTF_HEADER_MAGIC,
               .version = BTF_HEADER_VERSION,
               .flags = 0,
               .hdr_len = sizeof(btf_header_t),
               .type_off = 0,
               .type_len = static_cast<unsigned int>(type_table_bytes.size()),
               .str_off = static_cast<unsigned int>(type_table_bytes.size()),
               .str_len = static_cast<unsigned int>(string_table_bytes.size()),
           });

  // Write the type table.
  _write_btf(btf, type_table_bytes);

  // Write the string table.
  _write_btf(btf, string_table_bytes);

  return btf;
}
} // namespace libbtf