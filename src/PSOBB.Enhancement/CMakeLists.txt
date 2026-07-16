cmake_minimum_required(VERSION 3.25)

project(PSOBBEnhancement VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "PSOBB.Enhancement is a Windows-only x86 component")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "PSOBB.Enhancement must be configured for Win32/x86 (use -A Win32)")
endif()

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(psobb_enhancement_core STATIC
  src/pinned_image.cpp
  src/policy.cpp
  src/sha256.cpp)

target_include_directories(psobb_enhancement_core
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_definitions(psobb_enhancement_core PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_link_libraries(psobb_enhancement_core PUBLIC bcrypt)

add_library(PSOBB.Enhancement SHARED
  src/exports.def
  src/dllmain.cpp
  src/enhancement.cpp)

target_compile_definitions(PSOBB.Enhancement PRIVATE
  PSOBB_ENHANCEMENT_BUILD
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_include_directories(PSOBB.Enhancement PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_link_libraries(PSOBB.Enhancement PRIVATE
  psobb_enhancement_core
  user32)

set_target_properties(PSOBB.Enhancement PROPERTIES
  PREFIX ""
  OUTPUT_NAME "PSOBB.Enhancement"
  SUFFIX ".asi")

add_executable(PSOBB.Enhancement.Verify tools/verify_main.cpp)
target_compile_definitions(PSOBB.Enhancement.Verify PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)
target_include_directories(PSOBB.Enhancement.Verify PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(PSOBB.Enhancement.Verify PRIVATE psobb_enhancement_core)

if(MSVC)
  foreach(target psobb_enhancement_core PSOBB.Enhancement PSOBB.Enhancement.Verify)
    target_compile_options(${target} PRIVATE
      /W4
      /WX
      /permissive-
      /sdl
      /Brepro
      /guard:cf
      /utf-8
      /Zc:__cplusplus
      /Zc:inline)
  endforeach()

  foreach(target PSOBB.Enhancement PSOBB.Enhancement.Verify)
    target_link_options(${target} PRIVATE
      /Brepro
      /DYNAMICBASE
      /INCREMENTAL:NO
      /NXCOMPAT
      /GUARD:CF)
  endforeach()
endif()

if(BUILD_TESTING)
  add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../../tests/PSOBB.Enhancement"
    "${CMAKE_CURRENT_BINARY_DIR}/tests")
endif()
