add_executable(PSOBB.Enhancement.Tests policy_tests.cpp)

target_compile_definitions(PSOBB.Enhancement.Tests PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_include_directories(PSOBB.Enhancement.Tests PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../../src/PSOBB.Enhancement/include")

target_link_libraries(PSOBB.Enhancement.Tests PRIVATE psobb_enhancement_core)

if(MSVC)
  target_compile_options(PSOBB.Enhancement.Tests PRIVATE
    /W4
    /WX
    /permissive-
    /sdl
    /guard:cf
    /utf-8
    /Zc:__cplusplus)
endif()

add_test(NAME PSOBB.Enhancement.Unit COMMAND PSOBB.Enhancement.Tests)

add_executable(PSOBB.Enhancement.AbiSmoke abi_smoke.cpp)
target_compile_definitions(PSOBB.Enhancement.AbiSmoke PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)
target_include_directories(PSOBB.Enhancement.AbiSmoke PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../../src/PSOBB.Enhancement/include")

if(MSVC)
  target_compile_options(PSOBB.Enhancement.AbiSmoke PRIVATE
    /W4
    /WX
    /permissive-
    /sdl
    /guard:cf
    /utf-8
    /Zc:__cplusplus)
endif()

add_test(
  NAME PSOBB.Enhancement.AbiSmoke
  COMMAND PSOBB.Enhancement.AbiSmoke $<TARGET_FILE:PSOBB.Enhancement>)
