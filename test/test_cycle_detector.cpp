// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "cycle_detector.h"
#include <catch2/catch_test_macros.hpp>
#include <stdexcept>

using namespace libbtf;

TEST_CASE("cycle_detector basic functionality", "[cycle_detector]") {
  cycle_detector detector;

  SECTION("Initial state") {
    REQUIRE_FALSE(detector.would_create_cycle(1));
    REQUIRE(detector.get_visited().empty());
  }

  SECTION("Mark and check visited") {
    REQUIRE(detector.mark_visited(1));
    REQUIRE(detector.would_create_cycle(1));
    REQUIRE(detector.get_visited().size() == 1);
    REQUIRE(detector.get_visited().count(1) == 1);

    // Trying to mark the same ID again should return false
    REQUIRE_FALSE(detector.mark_visited(1));
  }

  SECTION("Unmark visited") {
    detector.mark_visited(1);
    detector.mark_visited(2);
    REQUIRE(detector.get_visited().size() == 2);

    detector.unmark_visited(1);
    REQUIRE_FALSE(detector.would_create_cycle(1));
    REQUIRE(detector.would_create_cycle(2));
    REQUIRE(detector.get_visited().size() == 1);
  }

  SECTION("Clear all") {
    detector.mark_visited(1);
    detector.mark_visited(2);
    detector.mark_visited(3);

    detector.clear();
    REQUIRE(detector.get_visited().empty());
    REQUIRE_FALSE(detector.would_create_cycle(1));
    REQUIRE_FALSE(detector.would_create_cycle(2));
    REQUIRE_FALSE(detector.would_create_cycle(3));
  }
}

TEST_CASE("cycle_detector with_cycle_detection method", "[cycle_detector]") {
  cycle_detector detector;

  SECTION("No cycle - calls main function") {
    int result = detector.with_cycle_detection<int>(
        1, []() { return 42; }, []() { return -1; });
    REQUIRE(result == 42);
  }

  SECTION("Cycle detected - calls cycle handler") {
    detector.mark_visited(1); // Pre-mark to simulate cycle

    int result = detector.with_cycle_detection<int>(
        1, []() { return 42; }, []() { return -1; });
    REQUIRE(result == -1);
  }

  SECTION("Backtracking enabled by default") {
    detector.with_cycle_detection<int>(
        1, []() { return 42; }, []() { return -1; });

    // After the call, ID should be unmarked due to backtracking
    REQUIRE_FALSE(detector.would_create_cycle(1));
  }

  SECTION("Backtracking disabled") {
    detector.with_cycle_detection<int>(
        1, []() { return 42; }, []() { return -1; },
        false // backtrack = false
    );

    // After the call, ID should still be marked
    REQUIRE(detector.would_create_cycle(1));
  }
}

TEST_CASE("scoped_visit RAII behavior", "[cycle_detector][scoped_visit]") {
  cycle_detector detector;

  SECTION("Successful visit and automatic cleanup") {
    {
      scoped_visit visit(detector, 1, std::nothrow);
      REQUIRE(visit.is_marked());
      REQUIRE(detector.would_create_cycle(1));
    }
    // After scope, should be automatically unmarked
    REQUIRE_FALSE(detector.would_create_cycle(1));
  }

  SECTION("Cycle detected - no marking") {
    detector.mark_visited(1); // Pre-mark

    {
      scoped_visit visit(detector, 1, std::nothrow);
      REQUIRE_FALSE(visit.is_marked()); // Should detect cycle
    }

    // Should still be marked from the original mark_visited call
    REQUIRE(detector.would_create_cycle(1));
  }

  SECTION("Exception throwing constructor") {
    detector.mark_visited(1); // Pre-mark to cause cycle

    REQUIRE_THROWS_AS(scoped_visit(detector, 1), std::runtime_error);
  }

  SECTION("Multiple scoped visits") {
    {
      scoped_visit visit1(detector, 1, std::nothrow);
      REQUIRE(visit1.is_marked());

      {
        scoped_visit visit2(detector, 2, std::nothrow);
        REQUIRE(visit2.is_marked());
        REQUIRE(detector.get_visited().size() == 2);
      }

      // visit2 should be cleaned up, visit1 still active
      REQUIRE(detector.get_visited().size() == 1);
      REQUIRE(detector.would_create_cycle(1));
      REQUIRE_FALSE(detector.would_create_cycle(2));
    }

    // All should be cleaned up
    REQUIRE(detector.get_visited().empty());
  }
}

TEST_CASE("Real-world usage patterns", "[cycle_detector][integration]") {
  cycle_detector detector;

  SECTION("Simulated recursive type size calculation") {
    // Simulate calculating size of recursive types
    std::function<int(int, cycle_detector &)> calc_size =
        [&](int type_id, cycle_detector &det) -> int {
      return det.with_cycle_detection<int>(
          type_id,
          [&]() -> int {
            // Simulate different type sizes
            if (type_id == 1)
              return 4; // int
            if (type_id == 2)
              return 8; // double
            if (type_id == 3)
              return calc_size(1, det) + calc_size(2, det); // struct
            if (type_id == 4)
              return calc_size(4, det); // self-referential (cycle)
            return 0;
          },
          [&]() -> int {
            return 0; // Cycle detected, return 0
          });
    };

    REQUIRE(calc_size(1, detector) == 4);
    REQUIRE(calc_size(2, detector) == 8);
    REQUIRE(calc_size(3, detector) == 12); // 4 + 8
    REQUIRE(calc_size(4, detector) == 0);  // Cycle detected
  }

  SECTION("Simulated type name resolution with cycles") {
    std::map<int, std::string> type_names = {
        {1, "int"}, {2, "MyStruct"}, {3, "ptr_to_2"}};

    std::map<int, int> type_refs = {
        {3, 2}, // ptr_to_2 -> MyStruct
        {2, 3}  // MyStruct -> ptr_to_2 (creates cycle)
    };

    std::function<std::string(int, cycle_detector &)> get_name =
        [&](int type_id, cycle_detector &det) -> std::string {
      scoped_visit visit(det, type_id, std::nothrow);
      if (!visit.is_marked()) {
        return "cyclic_type_" + std::to_string(type_id);
      }

      // Check for references first to ensure cycles are encountered
      auto ref_it = type_refs.find(type_id);
      if (ref_it != type_refs.end()) {
        return "ref_to_" + get_name(ref_it->second, det);
      }

      auto name_it = type_names.find(type_id);
      if (name_it != type_names.end()) {
        return name_it->second;
      }

      return "unknown_" + std::to_string(type_id);
    };

    REQUIRE(get_name(1, detector) == "int");
    // Type 2 and 3 have a cycle, should be detected
    std::string result2 = get_name(2, detector);
    std::string result3 = get_name(3, detector);

    // One of them should detect the cycle
    REQUIRE((result2.find("cyclic_type") != std::string::npos ||
             result3.find("cyclic_type") != std::string::npos));
  }
}

TEST_CASE("Performance considerations", "[cycle_detector][performance]") {
  cycle_detector detector;

  SECTION("Large number of types") {
    const int num_types = 10000;

    // Mark many types as visited
    for (int i = 0; i < num_types; ++i) {
      REQUIRE(detector.mark_visited(i));
    }

    REQUIRE(detector.get_visited().size() == num_types);

    // Check that lookups are still reasonably fast
    for (int i = 0; i < num_types; ++i) {
      REQUIRE(detector.would_create_cycle(i));
    }

    // Unmark all
    for (int i = 0; i < num_types; ++i) {
      detector.unmark_visited(i);
    }

    REQUIRE(detector.get_visited().empty());
  }
}