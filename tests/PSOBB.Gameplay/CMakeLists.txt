add_executable(PSOBB.Gameplay.AbiSmoke abi_smoke.cpp)

target_compile_features(PSOBB.Gameplay.AbiSmoke PRIVATE cxx_std_20)

set_target_properties(PSOBB.Gameplay.AbiSmoke PROPERTIES
  CXX_EXTENSIONS OFF
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

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

add_executable(
  PSOBB.Gameplay.ObservationRingTests
  observation_ring_tests.cpp)

add_executable(
  PSOBB.Gameplay.Send60ProbeTests
  send60_probe_tests.cpp)

target_compile_features(
  PSOBB.Gameplay.ObservationRingTests PRIVATE cxx_std_20)

target_compile_features(
  PSOBB.Gameplay.Send60ProbeTests PRIVATE cxx_std_20)

target_include_directories(
  PSOBB.Gameplay.ObservationRingTests PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../../src/PSOBB.Gameplay/src")

target_include_directories(
  PSOBB.Gameplay.Send60ProbeTests PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../../src/PSOBB.Gameplay/src")

target_link_libraries(
  PSOBB.Gameplay.ObservationRingTests PRIVATE psobb_gameplay_core)

target_link_libraries(
  PSOBB.Gameplay.Send60ProbeTests PRIVATE psobb_gameplay_core)

set_target_properties(PSOBB.Gameplay.ObservationRingTests PROPERTIES
  CXX_EXTENSIONS OFF
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set_target_properties(PSOBB.Gameplay.Send60ProbeTests PROPERTIES
  CXX_EXTENSIONS OFF
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(MSVC)
  target_compile_options(PSOBB.Gameplay.ObservationRingTests PRIVATE
    /W4
    /WX
    /permissive-
    /sdl
    /guard:cf
    /utf-8
    /Zc:__cplusplus)

  target_compile_options(PSOBB.Gameplay.Send60ProbeTests PRIVATE
    /W4
    /WX
    /permissive-
    /sdl
    /guard:cf
    /utf-8
    /Zc:__cplusplus)
endif()

add_test(
  NAME PSOBB.Gameplay.ObservationRing
  COMMAND PSOBB.Gameplay.ObservationRingTests)

add_test(
  NAME PSOBB.Gameplay.Send60Probe
  COMMAND PSOBB.Gameplay.Send60ProbeTests)
