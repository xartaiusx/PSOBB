cmake_minimum_required(VERSION 3.25)

project(PSOBBGameplay VERSION 0.2.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "PSOBB.Gameplay is a Windows-only x86 component")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "PSOBB.Gameplay must be configured for Win32/x86 (use -A Win32)")
endif()

include(CTest)

if(NOT TARGET PSOBB::ClientSafety)
  add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../PSOBB.ClientSafety"
    "${CMAKE_CURRENT_BINARY_DIR}/client-safety"
    EXCLUDE_FROM_ALL)
endif()

add_library(psobb_gameplay_core STATIC
  src/observation_ring.cpp)

target_include_directories(psobb_gameplay_core
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_features(psobb_gameplay_core PUBLIC cxx_std_20)

add_library(PSOBB.Gameplay SHARED
  src/dllmain.cpp
  src/exports.def
  src/gameplay.cpp)

target_compile_definitions(PSOBB.Gameplay PRIVATE
  PSOBB_GAMEPLAY_BUILD
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_include_directories(PSOBB.Gameplay PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_link_libraries(PSOBB.Gameplay PRIVATE
  psobb_gameplay_core
  PSOBB::ClientSafety)

target_compile_features(PSOBB.Gameplay PRIVATE cxx_std_20)

set_target_properties(PSOBB.Gameplay PROPERTIES
  CXX_EXTENSIONS OFF
  PREFIX ""
  OUTPUT_NAME "PSOBB.Gameplay"
  SUFFIX ".asi"
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set_target_properties(psobb_gameplay_core PROPERTIES
  CXX_EXTENSIONS OFF
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(MSVC)
  foreach(target psobb_gameplay_core PSOBB.Gameplay)
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

  target_link_options(PSOBB.Gameplay PRIVATE
    /Brepro
    /DYNAMICBASE
    /INCREMENTAL:NO
    /NXCOMPAT
    /GUARD:CF)
endif()

if(BUILD_TESTING)
  add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../../tests/PSOBB.Gameplay"
    "${CMAKE_CURRENT_BINARY_DIR}/tests")
endif()
