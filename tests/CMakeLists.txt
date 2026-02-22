include(FetchContent)

set(CATCH_INSTALL_DOCS OFF CACHE BOOL "" FORCE)
set(CATCH_INSTALL_EXTRAS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v3.5.4)

FetchContent_MakeAvailable(Catch2)

add_executable(
  crisp_tests
  unit/test_golden_vectors.cpp
  unit/test_message.cpp
  unit/test_replay_window.cpp
  unit/test_suites.cpp)

target_link_libraries(crisp_tests PRIVATE Catch2::Catch2WithMain crisp::core crisp::dummy_crypto)

crisp_enable_warnings(crisp_tests)
crisp_enable_sanitizers(crisp_tests)
crisp_enable_clang_tidy(crisp_tests)

include(Catch)
catch_discover_tests(crisp_tests)
