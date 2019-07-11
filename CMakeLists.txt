cmake_minimum_required(VERSION 3.5)

project(sha-2 CXX)

add_library(sha-2 INTERFACE)

target_sources(sha-2 INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/sha2.hpp)

target_include_directories(sha-2 INTERFACE src/)

if(BUILD_TESTING)

  add_executable(test-sha-2
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
  )

  target_compile_options(test-sha-2 PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
    $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Os -fno-rtti -fno-exceptions -Wall -Wextra -Wpedantic>
    $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization>
    $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wnoexcept>
    $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-promo>
    $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Wstrict-null-sentinel -Wstrict-overflow=5 -Wundef>
  )

  add_test(NAME run-test-sha-2 COMMAND $<TARGET_FILE:test-sha-2>)
endif(BUILD_TESTING)
