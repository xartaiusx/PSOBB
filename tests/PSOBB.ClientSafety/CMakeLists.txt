add_executable(PSOBB.ClientSafety.Tests exact_image_tests.cpp)

add_executable(PSOBB.ClientSafety.HookPatch.Tests hook_patch_tests.cpp)

add_executable(
  PSOBB.ClientSafety.RelativeCallHook.Tests
  relative_call_hook_tests.cpp)

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

target_compile_definitions(
  PSOBB.ClientSafety.RelativeCallHook.Tests PRIVATE
  PSOBB_CLIENT_SAFETY_RELATIVE_CALL_TEST_SEAM
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_link_libraries(
  PSOBB.ClientSafety.RelativeCallHook.Tests PRIVATE
  PSOBB::ClientSafetyRelativeCallTestable
  PSOBB::ClientSafetyHookTestable)

target_include_directories(
  PSOBB.ClientSafety.RelativeCallHook.Tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../../src/PSOBB.ClientSafety/src")

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

  target_compile_options(
    PSOBB.ClientSafety.RelativeCallHook.Tests PRIVATE
    /W4
    /WX
    /permissive-
    /sdl
    /guard:cf
    /utf-8
    /Zc:__cplusplus)

  target_link_options(
    PSOBB.ClientSafety.RelativeCallHook.Tests PRIVATE
    /SECTION:.hktest,ERW)
endif()

add_test(
  NAME PSOBB.ClientSafety.Unit
  COMMAND PSOBB.ClientSafety.Tests)

add_test(
  NAME PSOBB.ClientSafety.HookPatch.Unit
  COMMAND PSOBB.ClientSafety.HookPatch.Tests)

add_test(
  NAME PSOBB.ClientSafety.RelativeCallHook.Unit
  COMMAND PSOBB.ClientSafety.RelativeCallHook.Tests)
