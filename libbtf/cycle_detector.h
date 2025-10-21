// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include "btf.h"
#include <functional>
#include <set>
#include <stdexcept>

namespace libbtf {

/**
 * @brief A generic cycle detection utility for BTF type traversal.
 *
 * This class provides a reusable way to detect cycles when traversing
 * BTF type graphs, eliminating code duplication across the codebase.
 */
class cycle_detector {
public:
  using type_id = btf_type_id;

  /**
   * @brief Construct a new cycle detector object
   */
  cycle_detector() = default;

  /**
   * @brief Check if a type ID would create a cycle
   *
   * @param id The type ID to check
   * @return true if adding this ID would create a cycle, false otherwise
   */
  bool would_create_cycle(type_id id) const {
    return visited_.find(id) != visited_.end();
  }

  /**
   * @brief Add a type ID to the visited set
   *
   * @param id The type ID to mark as visited
   * @return true if the ID was newly added, false if it was already visited
   * (cycle detected)
   */
  bool mark_visited(type_id id) {
    if (would_create_cycle(id)) {
      return false;
    }
    visited_.insert(id);
    return true;
  }

  /**
   * @brief Remove a type ID from the visited set (for backtracking)
   *
   * @param id The type ID to unmark
   */
  void unmark_visited(type_id id) { visited_.erase(id); }

  /**
   * @brief Get the current visited set (for debugging or advanced usage)
   *
   * @return const reference to the visited set
   */
  const std::set<type_id> &get_visited() const { return visited_; }

  /**
   * @brief Clear all visited markers
   */
  void clear() { visited_.clear(); }

  /**
   * @brief Execute a function with automatic cycle detection and cleanup
   *
   * This RAII-style method automatically handles marking/unmarking the type ID
   * and provides cycle detection. If a cycle is detected, the on_cycle handler
   * is called instead of the main function.
   *
   * @tparam T Return type of the functions
   * @param id The type ID to process
   * @param func The main function to execute if no cycle is detected
   * @param on_cycle The function to execute if a cycle is detected
   * @param backtrack Whether to automatically unmark the ID after processing
   * (default: true)
   * @return The result of either func or on_cycle
   */
  template <typename T>
  T with_cycle_detection(type_id id, std::function<T()> func,
                         std::function<T()> on_cycle, bool backtrack = true) {
    if (would_create_cycle(id)) {
      return on_cycle();
    }

    visited_.insert(id);
    T result;
    try {
      result = func();
    } catch (...) {
      if (backtrack) {
        visited_.erase(id);
      }
      throw;
    }

    if (backtrack) {
      visited_.erase(id);
    }

    return result;
  }

private:
  std::set<type_id> visited_;
};

/**
 * @brief RAII helper for automatic visited tracking
 *
 * This class automatically marks a type as visited in its constructor
 * and unmarks it in its destructor, ensuring proper cleanup even
 * in the presence of exceptions.
 */
class scoped_visit {
public:
  /**
   * @brief Construct and mark a type as visited
   *
   * @param detector The cycle detector to use
   * @param id The type ID to mark as visited
   * @throws std::runtime_error if a cycle would be created
   */
  scoped_visit(cycle_detector &detector, btf_type_id id)
      : detector_(detector), id_(id), marked_(false) {
    if (!detector_.mark_visited(id)) {
      throw std::runtime_error("Cycle detected for type ID " +
                               std::to_string(id));
    }
    marked_ = true;
  }

  /**
   * @brief Construct without throwing on cycle detection
   *
   * @param detector The cycle detector to use
   * @param id The type ID to mark as visited
   * @param no_throw Tag to indicate no exception should be thrown
   * @return true if successfully marked, false if cycle detected
   */
  scoped_visit(cycle_detector &detector, btf_type_id id, std::nothrow_t)
      : detector_(detector), id_(id) {
    marked_ = detector_.mark_visited(id);
  }

  /**
   * @brief Destructor automatically unmarks the type
   */
  ~scoped_visit() {
    if (marked_) {
      detector_.unmark_visited(id_);
    }
  }

  /**
   * @brief Check if the type was successfully marked as visited
   *
   * @return true if marked (no cycle), false if cycle was detected
   */
  bool is_marked() const { return marked_; }

  // Non-copyable, non-movable to prevent issues with RAII
  scoped_visit(const scoped_visit &) = delete;
  scoped_visit &operator=(const scoped_visit &) = delete;
  scoped_visit(scoped_visit &&) = delete;
  scoped_visit &operator=(scoped_visit &&) = delete;

private:
  cycle_detector &detector_;
  btf_type_id id_;
  bool marked_;
};

} // namespace libbtf