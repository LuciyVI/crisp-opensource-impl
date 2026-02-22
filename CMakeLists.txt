cmake_minimum_required(VERSION 3.20)

project(crisp VERSION 0.1.0 LANGUAGES C CXX)

option(CRISP_BUILD_TESTS "Build tests." ON)
option(CRISP_BUILD_TOOLS "Build command-line tools." ON)
option(CRISP_ENABLE_ASAN "Enable AddressSanitizer." OFF)
option(CRISP_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer." OFF)
option(CRISP_ENABLE_TSAN "Enable ThreadSanitizer." OFF)
option(CRISP_WERROR "Treat warnings as errors." ON)
option(CRISP_ENABLE_CLANG_TIDY "Enable clang-tidy for supported targets." OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Warnings)
include(Sanitizers)
include(ClangTidy)

add_library(crisp_common INTERFACE)
target_compile_features(crisp_common INTERFACE c_std_11 cxx_std_20)
target_include_directories(crisp_common INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/crisp-core/include")
add_library(crisp::common ALIAS crisp_common)

add_library(crisp_crypto_iface INTERFACE)
target_link_libraries(crisp_crypto_iface INTERFACE crisp_common)
add_library(crisp::crypto_iface ALIAS crisp_crypto_iface)

add_subdirectory(crisp-core)
add_subdirectory(crisp-driver)

if(CRISP_BUILD_TOOLS)
  add_subdirectory(crispctl)
endif()

if(CRISP_BUILD_TESTS)
  include(CTest)
  if(BUILD_TESTING)
    add_subdirectory(tests)
  endif()
endif()
