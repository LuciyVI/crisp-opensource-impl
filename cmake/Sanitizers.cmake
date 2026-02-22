function(crisp_enable_sanitizers target)
  if(NOT TARGET ${target})
    message(FATAL_ERROR "crisp_enable_sanitizers: target '${target}' does not exist")
  endif()

  if(MSVC)
    return()
  endif()

  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang|GNU" AND
     NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    return()
  endif()

  if(CRISP_ENABLE_TSAN AND (CRISP_ENABLE_ASAN OR CRISP_ENABLE_UBSAN))
    message(FATAL_ERROR "TSAN cannot be enabled together with ASAN or UBSAN")
  endif()

  set(_sanitizers)
  if(CRISP_ENABLE_ASAN)
    list(APPEND _sanitizers address)
  endif()
  if(CRISP_ENABLE_UBSAN)
    list(APPEND _sanitizers undefined)
  endif()
  if(CRISP_ENABLE_TSAN)
    list(APPEND _sanitizers thread)
  endif()

  if(NOT _sanitizers)
    return()
  endif()

  string(REPLACE ";" "," _sanitizer_flags "${_sanitizers}")
  target_compile_options(${target} PRIVATE -fsanitize=${_sanitizer_flags} -fno-omit-frame-pointer)
  target_link_options(${target} PRIVATE -fsanitize=${_sanitizer_flags})
endfunction()
