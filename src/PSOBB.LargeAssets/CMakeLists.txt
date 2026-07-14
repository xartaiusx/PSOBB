cmake_minimum_required(VERSION 3.25)

project(PSOBBLargeAssets VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "PSOBB.LargeAssets is a Windows-only x86 component")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "PSOBB.LargeAssets must be configured for Win32/x86 (use -A Win32)")
endif()

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(psobb_large_assets_core STATIC
  src/patch_plan.cpp
  src/pinned_image.cpp)

target_include_directories(psobb_large_assets_core
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_compile_definitions(psobb_large_assets_core PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_link_libraries(psobb_large_assets_core PUBLIC bcrypt)

add_library(PSOBB.LargeAssets SHARED
  src/dllmain.cpp
  src/exports.def
  src/runtime.cpp)

target_include_directories(PSOBB.LargeAssets PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_definitions(PSOBB.LargeAssets PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_link_libraries(PSOBB.LargeAssets PRIVATE
  psobb_large_assets_core)

set_target_properties(PSOBB.LargeAssets PROPERTIES
  PREFIX ""
  OUTPUT_NAME "PSOBB.LargeAssets"
  SUFFIX ".asi")

add_executable(PSOBB.LargeAssets.Verify tools/verify_main.cpp)
target_compile_definitions(PSOBB.LargeAssets.Verify PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)
target_include_directories(PSOBB.LargeAssets.Verify PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(PSOBB.LargeAssets.Verify PRIVATE
  psobb_large_assets_core)

if(MSVC)
  foreach(target
      psobb_large_assets_core
      PSOBB.LargeAssets
      PSOBB.LargeAssets.Verify)
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

  target_link_options(PSOBB.LargeAssets PRIVATE
    /Brepro
    /DYNAMICBASE
    /INCREMENTAL:NO
    /NXCOMPAT
    /GUARD:CF)
endif()

if(BUILD_TESTING)
  add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../../tests/PSOBB.LargeAssets"
    "${CMAKE_CURRENT_BINARY_DIR}/tests")
endif()
