#include <iostream>
#include <string_view>

int main(int argc, char** argv) {
  const std::string_view tool_name = "crispctl";

  if (argc > 1 && std::string_view(argv[1]) == "--version") {
    std::cout << tool_name << " 0.1.0\n";
    return 0;
  }

  std::cout << tool_name << " (stub)\n"
            << "Usage:\n"
            << "  crispctl --version\n"
            << "  crispctl <future-command>\n";
  return 0;
}
