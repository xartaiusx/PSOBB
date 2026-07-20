add_executable(PSOBB.ClientSafety.Tests exact_image_tests.cpp)

target_compile_definitions(PSOBB.ClientSafety.Tests PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX)

target_link_libraries(PSOBB.ClientSafety.Tests PRIVATE
  PSOBB::ClientSafety)

if(MSVC)
  target_compile_options(PSOBB.ClientSafety.Tests PRIVATE
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
