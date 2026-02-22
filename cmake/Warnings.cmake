function(crisp_enable_warnings target)
  if(NOT TARGET ${target})
    message(FATAL_ERROR "crisp_enable_warnings: target '${target}' does not exist")
  endif()

  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive-)
    if(CRISP_WERROR)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    return()
  endif()

  target_compile_options(
    ${target}
    PRIVATE
      $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Wall>
      $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Wextra>
      $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Wpedantic>
      $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Wconversion>
      $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Wsign-conversion>
      $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Wshadow>
      $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Wformat=2>
      $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Wundef>
      $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Wnull-dereference>
      $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Wdouble-promotion>
      $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Wimplicit-fallthrough>
      $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Wall>
      $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Wextra>
      $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Wpedantic>
      $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Wconversion>
      $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Wsign-conversion>
      $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Wshadow>
      $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Wformat=2>
      $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Wundef>
      $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Wnull-dereference>
      $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Wdouble-promotion>
      $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Wimplicit-fallthrough>)

  if(CRISP_WERROR)
    target_compile_options(
      ${target}
      PRIVATE
        $<$<COMPILE_LANG_AND_ID:C,Clang,GNU>:-Werror>
        $<$<COMPILE_LANG_AND_ID:CXX,Clang,GNU>:-Werror>)
  endif()
endfunction()
