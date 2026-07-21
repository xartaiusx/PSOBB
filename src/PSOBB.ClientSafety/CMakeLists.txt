cmake_minimum_required(VERSION 3.25)

project(PSOBBClientSafety VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "PSOBB.ClientSafety is a Windows-only x86 component")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "PSOBB.ClientSafety must be configured for Win32/x86 (use -A Win32)")
endif()

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(psobb_client_safety STATIC
  src/exact_image.cpp
  src/hook_patch.cpp
  src/relative_call_hook.cpp
  src/sha256.cpp)

add_library(PSOBB::ClientSafety ALIAS psobb_client_safety)

target_include_directories(psobb_client_safety
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_compile_definitions(psobb_client_safety PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_link_libraries(psobb_client_safety PUBLIC bcrypt)

if(MSVC)
  target_compile_options(psobb_client_safety PRIVATE
    /W4
    /WX
    /permissive-
    /sdl
    /Brepro
    /guard:cf
    /utf-8
    /Zc:__cplusplus
    /Zc:inline)
endif()

if(BUILD_TESTING AND PROJECT_IS_TOP_LEVEL)
  add_library(psobb_client_safety_hook_testable STATIC
    src/hook_patch.cpp)
  add_library(
    PSOBB::ClientSafetyHookTestable
    ALIAS psobb_client_safety_hook_testable)
  target_include_directories(psobb_client_safety_hook_testable
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_definitions(psobb_client_safety_hook_testable PRIVATE
    PSOBB_CLIENT_SAFETY_TEST_SEAM
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX)
  if(MSVC)
    target_compile_options(psobb_client_safety_hook_testable PRIVATE
      /W4
      /WX
      /permissive-
      /sdl
      /Brepro
      /guard:cf
      /utf-8
      /Zc:__cplusplus
      /Zc:inline)
  endif()

  add_library(psobb_client_safety_relative_call_testable STATIC
    src/relative_call_hook.cpp)
  add_library(
    PSOBB::ClientSafetyRelativeCallTestable
    ALIAS psobb_client_safety_relative_call_testable)
  target_include_directories(psobb_client_safety_relative_call_testable
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_definitions(psobb_client_safety_relative_call_testable PRIVATE
    PSOBB_CLIENT_SAFETY_RELATIVE_CALL_TEST_SEAM
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX)
  if(MSVC)
    target_compile_options(psobb_client_safety_relative_call_testable PRIVATE
      /W4
      /WX
      /permissive-
      /sdl
      /Brepro
      /guard:cf
      /utf-8
      /Zc:__cplusplus
      /Zc:inline)
  endif()
  add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../../tests/PSOBB.ClientSafety"
    "${CMAKE_CURRENT_BINARY_DIR}/tests")
endif()
