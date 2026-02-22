add_executable(crispctl src/main.cpp)
target_link_libraries(crispctl PRIVATE crisp::core)

crisp_enable_warnings(crispctl)
crisp_enable_sanitizers(crispctl)
crisp_enable_clang_tidy(crispctl)
