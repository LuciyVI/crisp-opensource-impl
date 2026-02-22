function(crisp_enable_clang_tidy target)
  if(NOT TARGET ${target})
    message(FATAL_ERROR "crisp_enable_clang_tidy: target '${target}' does not exist")
  endif()

  if(NOT CRISP_ENABLE_CLANG_TIDY)
    return()
  endif()

  find_program(CLANG_TIDY_BIN NAMES clang-tidy)
  if(NOT CLANG_TIDY_BIN)
    message(WARNING "CRISP_ENABLE_CLANG_TIDY=ON, but clang-tidy was not found")
    return()
  endif()

  set(_clang_tidy_args ${CLANG_TIDY_BIN})
  if(CRISP_WERROR)
    list(APPEND _clang_tidy_args --warnings-as-errors=*)
  endif()

  set_target_properties(
    ${target}
    PROPERTIES C_CLANG_TIDY "${_clang_tidy_args}" CXX_CLANG_TIDY "${_clang_tidy_args}")
endfunction()
