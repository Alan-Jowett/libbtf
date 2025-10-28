// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <functional>
#include <iostream>
#include <map>
#include <string>
#include <vector>

class options {
public:
  typedef std::function<void(std::vector<std::string>::iterator)>
      option_handler;
  options(std::ostream &out = std::cout) : out(out) {
    add(
        "-h", 1, [this](auto) { this->print_help(); },
        "Print this help message");
  }
  ~options() = default;

  /**
   * @brief The parse function processes command-line arguments.
   *
   * @param[in] argc The number of command-line arguments.
   * @param[in] argv An array of command-line argument strings.
   */
  void parse(int argc, char **argv);

  /**
   * @brief Add an option to the option map.
   *
   * @param[in] option The option string (e.g., "-o" or "--output").
   * @param[in] num_args The number of arguments the option takes including the
   * option itself (e.g., 2 for "-o output.txt").
   * @param[in] func The handler function to call when the option is
   * @param[in] help The help string for the option.
   */
  void add(const std::string &option, size_t num_args, option_handler func,
           const std::string &help);

  /**
   * @brief Print the help message for all options.
   */
  void print_help();

private:
  std::map<std::string, std::tuple<size_t, option_handler, std::string>>
      option_map;
  std::vector<std::string> args;
  std::ostream &out;
};
