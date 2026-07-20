add_executable(PSOBB.ClientSafety.Tests exact_image_tests.cpp)

add_executable(PSOBB.ClientSafety.HookPatch.Tests hook_patch_tests.cpp)

target_compile_definitions(PSOBB.ClientSafety.Tests PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_link_libraries(PSOBB.ClientSafety.Tests PRIVATE
  PSOBB::ClientSafety)

target_compile_definitions(PSOBB.ClientSafety.HookPatch.Tests PRIVATE
  PSOBB_CLIENT_SAFETY_TEST_SEAM
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_link_libraries(PSOBB.ClientSafety.HookPatch.Tests PRIVATE
  PSOBB::ClientSafetyHookTestable)

target_include_directories(PSOBB.ClientSafety.HookPatch.Tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../../src/PSOBB.ClientSafety/src")

if(MSVC)
  target_compile_options(PSOBB.ClientSafety.Tests PRIVATE
    /W4
    /WX
    /permissive-
    /sdl
    /guard:cf
    /utf-8
    /Zc:__cplusplus)

  target_compile_options(PSOBB.ClientSafety.HookPatch.Tests PRIVATE
    /W4
    /WX
    /permissive-
    /sdl
    /guard:cf
    /utf-8
    /Zc:__cplusplus)
endif()

add_test(
  NAME PSOBB.ClientSafety.Unit
  COMMAND PSOBB.ClientSafety.Tests)

add_test(
  NAME PSOBB.ClientSafety.HookPatch.Unit
  COMMAND PSOBB.ClientSafety.HookPatch.Tests)
