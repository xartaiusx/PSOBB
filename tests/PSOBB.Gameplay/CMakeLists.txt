add_executable(PSOBB.Gameplay.AbiSmoke abi_smoke.cpp)

target_compile_definitions(PSOBB.Gameplay.AbiSmoke PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_include_directories(PSOBB.Gameplay.AbiSmoke PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../../src/PSOBB.Gameplay/include")

if(MSVC)
  target_compile_options(PSOBB.Gameplay.AbiSmoke PRIVATE
    /W4
    /WX
    /permissive-
    /sdl
    /guard:cf
    /utf-8
    /Zc:__cplusplus)
endif()

add_test(
  NAME PSOBB.Gameplay.AbiMissingConfig
  COMMAND PSOBB.Gameplay.AbiSmoke
    $<TARGET_FILE:PSOBB.Gameplay> missing)

add_test(
  NAME PSOBB.Gameplay.AbiDisabledConfig
  COMMAND PSOBB.Gameplay.AbiSmoke
    $<TARGET_FILE:PSOBB.Gameplay> disabled)

add_test(
  NAME PSOBB.Gameplay.AbiRejectsUnpinnedHost
  COMMAND PSOBB.Gameplay.AbiSmoke
    $<TARGET_FILE:PSOBB.Gameplay> enabled-rejected)

set_tests_properties(
  PSOBB.Gameplay.AbiMissingConfig
  PSOBB.Gameplay.AbiDisabledConfig
  PSOBB.Gameplay.AbiRejectsUnpinnedHost
  PROPERTIES RUN_SERIAL TRUE)
