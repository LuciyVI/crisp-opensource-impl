add_library(
  crisp_core STATIC
  src/crypto_iface.c
  src/message.c
  src/replay_window.c
  src/suites.c)

add_library(crisp::core ALIAS crisp_core)

target_include_directories(
  crisp_core
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include>)

target_link_libraries(crisp_core PUBLIC crisp_common crisp_crypto_iface)

crisp_enable_warnings(crisp_core)
crisp_enable_sanitizers(crisp_core)
crisp_enable_clang_tidy(crisp_core)

add_library(crisp_dummy_crypto STATIC src/dummy_crypto_backend.c)
add_library(crisp::dummy_crypto ALIAS crisp_dummy_crypto)

target_include_directories(
  crisp_dummy_crypto
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include>)

target_link_libraries(crisp_dummy_crypto PUBLIC crisp_common crisp_crypto_iface)

crisp_enable_warnings(crisp_dummy_crypto)
crisp_enable_sanitizers(crisp_dummy_crypto)
crisp_enable_clang_tidy(crisp_dummy_crypto)
