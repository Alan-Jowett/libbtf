// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include "btf.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace libbtf {
/**
 * @brief A class to represent the type information in a BTF section.
 */
class btf_type_data {
public:
  /**
   * @brief Construct a new empty btf type data object
   */
  btf_type_data() {
    // Add the void type.
    id_to_kind[0] = btf_kind_null{};
  }

  /**
   * @brief Construct a new btf type data object from a vector of bytes.
   *
   * @param[in] btf_data The BTF data.
   */
  btf_type_data(const std::vector<std::byte> &btf_data);

  /**
   * @brief Destroy the btf type data object
   */
  ~btf_type_data() = default;

  /**
   * @brief Get btf_type_id from a name.
   *
   * @param[in] name Name of the type.
   * @return Type id of the type.
   */
  btf_type_id get_id(const std::string &name) const;

  /**
   * @brief Get the kind object from a type id.
   *
   * @param[in] id Id of the type.
   * @return The kind of the type.
   */
  btf_kind get_kind(btf_type_id id) const;
  btf_type_id dereference_pointer(btf_type_id id) const;
  size_t get_size(btf_type_id id) const;
  void to_json(std::ostream &out) const;
  std::vector<std::byte> to_bytes() const;
  void append(const btf_kind &kind);
  btf_type_id last_type_id() const { return id_to_kind.rbegin()->first; }

private:
  void validate_type_graph(btf_type_id id,
                           std::set<btf_type_id> &visited) const;
  std::map<btf_type_id, btf_kind> id_to_kind;
  std::map<std::string, btf_type_id> name_to_id;
};
} // namespace libbtf