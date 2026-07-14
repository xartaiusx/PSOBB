add_executable(PSOBB.LargeAssets.Tests patch_tests.cpp)

target_compile_definitions(PSOBB.LargeAssets.Tests PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_include_directories(PSOBB.LargeAssets.Tests PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../../src/PSOBB.LargeAssets/include")

target_link_libraries(PSOBB.LargeAssets.Tests PRIVATE
  psobb_large_assets_core)

add_executable(PSOBB.LargeAssets.AbiSmoke abi_smoke.cpp)
target_compile_definitions(PSOBB.LargeAssets.AbiSmoke PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)
target_include_directories(PSOBB.LargeAssets.AbiSmoke PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../../src/PSOBB.LargeAssets/include")

if(MSVC)
  foreach(target PSOBB.LargeAssets.Tests PSOBB.LargeAssets.AbiSmoke)
    target_compile_options(${target} PRIVATE
      /W4
      /WX
      /permissive-
      /sdl
      /guard:cf
      /utf-8
      /Zc:__cplusplus)
  endforeach()
endif()

add_test(
  NAME PSOBB.LargeAssets.Unit
  COMMAND PSOBB.LargeAssets.Tests)

add_test(
  NAME PSOBB.LargeAssets.AbiSmoke
  COMMAND PSOBB.LargeAssets.AbiSmoke $<TARGET_FILE:PSOBB.LargeAssets>)
