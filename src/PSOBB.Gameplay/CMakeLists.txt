cmake_minimum_required(VERSION 3.25)

project(PSOBBGameplay VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "PSOBB.Gameplay is a Windows-only x86 component")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "PSOBB.Gameplay must be configured for Win32/x86 (use -A Win32)")
endif()

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(NOT TARGET PSOBB::ClientSafety)
  add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../PSOBB.ClientSafety"
    "${CMAKE_CURRENT_BINARY_DIR}/client-safety"
    EXCLUDE_FROM_ALL)
endif()

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
  PSOBB::ClientSafety)

set_target_properties(PSOBB.Gameplay PROPERTIES
  PREFIX ""
  OUTPUT_NAME "PSOBB.Gameplay"
  SUFFIX ".asi")

if(MSVC)
  target_compile_options(PSOBB.Gameplay PRIVATE
    /W4
    /WX
    /permissive-
    /sdl
    /Brepro
    /guard:cf
    /utf-8
    /Zc:__cplusplus
    /Zc:inline)

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
