cmake_minimum_required(VERSION 3.16)

project(ChioGuardCpp VERSION 0.1.0 LANGUAGES C CXX)

include(CMakePackageConfigHelpers)
include(CTest)

option(CHIO_GUARD_CPP_BUILD_EXAMPLES "Build chio-guard-cpp examples" ON)
option(CHIO_GUARD_CPP_BUILD_TESTS "Build and register chio-guard-cpp smoke tests" ON)
option(CHIO_GUARD_CPP_GENERATE "Generate C++ guest bindings with wit-bindgen" OFF)
option(CHIO_GUARD_CPP_BUILD_WASI_COMPONENT "Build the sample guard component with WASI SDK" OFF)
option(CHIO_GUARD_CPP_INSTALL "Install chio-guard-cpp CMake package files" ON)

add_library(chio_guard_cpp INTERFACE)
add_library(ChioGuardCpp::chio_guard_cpp ALIAS chio_guard_cpp)

target_compile_features(chio_guard_cpp INTERFACE cxx_std_17)
target_include_directories(chio_guard_cpp INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

set(CHIO_GUARD_CPP_WIT
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../wit/chio-guard/world.wit"
  CACHE FILEPATH
  "Path to the Chio guard world.wit file"
)
set(CHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND "c"
  CACHE STRING
  "wit-bindgen subcommand used for guest bindings"
)
set(CHIO_GUARD_CPP_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated"
  CACHE PATH
  "Directory for generated WIT bindings"
)
set_property(CACHE CHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND PROPERTY STRINGS c cpp)

if(CHIO_GUARD_CPP_GENERATE)
  find_program(WIT_BINDGEN_EXECUTABLE wit-bindgen REQUIRED)
  set(CHIO_GUARD_CPP_GENERATED_STAMP "${CHIO_GUARD_CPP_GENERATED_DIR}/.generated")
  set(CHIO_GUARD_CPP_GENERATED_C "${CHIO_GUARD_CPP_GENERATED_DIR}/guard.c")
  add_custom_command(
    OUTPUT "${CHIO_GUARD_CPP_GENERATED_STAMP}"
    BYPRODUCTS
      "${CHIO_GUARD_CPP_GENERATED_DIR}/guard.h"
      "${CHIO_GUARD_CPP_GENERATED_C}"
      "${CHIO_GUARD_CPP_GENERATED_DIR}/guard_component_type.o"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CHIO_GUARD_CPP_GENERATED_DIR}"
    COMMAND "${WIT_BINDGEN_EXECUTABLE}" "${CHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND}"
      --world guard
      --out-dir "${CHIO_GUARD_CPP_GENERATED_DIR}"
      "${CHIO_GUARD_CPP_WIT}"
    COMMAND "${CMAKE_COMMAND}" -E touch "${CHIO_GUARD_CPP_GENERATED_STAMP}"
    DEPENDS "${CHIO_GUARD_CPP_WIT}"
    VERBATIM
  )
  add_custom_target(chio_guard_cpp_generate DEPENDS "${CHIO_GUARD_CPP_GENERATED_STAMP}")
endif()

if(CHIO_GUARD_CPP_BUILD_EXAMPLES)
  add_library(chio_guard_cpp_path_guard_example OBJECT
    examples/path_guard.cpp
  )
  target_link_libraries(chio_guard_cpp_path_guard_example PRIVATE chio_guard_cpp)
  target_include_directories(chio_guard_cpp_path_guard_example PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/examples"
  )

  add_executable(chio_guard_cpp_path_guard_smoke
    examples/path_guard.cpp
    examples/path_guard_smoke.cpp
  )
  target_link_libraries(chio_guard_cpp_path_guard_smoke PRIVATE chio_guard_cpp)
  target_include_directories(chio_guard_cpp_path_guard_smoke PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/examples"
  )

  if(CHIO_GUARD_CPP_BUILD_TESTS AND BUILD_TESTING)
    add_test(NAME chio_guard_cpp_path_guard_smoke
      COMMAND chio_guard_cpp_path_guard_smoke
    )
  endif()
endif()

if(CHIO_GUARD_CPP_BUILD_WASI_COMPONENT)
  if(NOT CHIO_GUARD_CPP_GENERATE)
    message(FATAL_ERROR "CHIO_GUARD_CPP_BUILD_WASI_COMPONENT requires CHIO_GUARD_CPP_GENERATE=ON")
  endif()
  if(NOT CHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND STREQUAL "c")
    message(FATAL_ERROR "The sample component currently targets wit-bindgen c output")
  endif()
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    message(FATAL_ERROR "CHIO_GUARD_CPP_BUILD_WASI_COMPONENT requires the WASI SDK CMake toolchain")
  endif()

  add_executable(chio_guard_cpp_path_guard_component
    examples/path_guard.cpp
    examples/path_guard_component.cpp
    "${CHIO_GUARD_CPP_GENERATED_C}"
  )
  add_dependencies(chio_guard_cpp_path_guard_component chio_guard_cpp_generate)
  target_link_libraries(chio_guard_cpp_path_guard_component PRIVATE chio_guard_cpp)
  target_include_directories(chio_guard_cpp_path_guard_component PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/examples"
    "${CHIO_GUARD_CPP_GENERATED_DIR}"
  )
  target_link_options(chio_guard_cpp_path_guard_component PRIVATE
    "-Wl,--no-entry"
    "-Wl,--export=__heap_base"
    "-Wl,--export=__data_end"
  )
  set_target_properties(chio_guard_cpp_path_guard_component PROPERTIES
    OUTPUT_NAME path_guard_component
    SUFFIX ".wasm"
  )
endif()

if(CHIO_GUARD_CPP_INSTALL)
  install(TARGETS chio_guard_cpp EXPORT ChioGuardCppTargets)
  install(DIRECTORY include/ DESTINATION include)

  configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ChioGuardCppConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/ChioGuardCppConfig.cmake"
    INSTALL_DESTINATION lib/cmake/ChioGuardCpp
  )
  write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/ChioGuardCppConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
  )

  install(EXPORT ChioGuardCppTargets
    NAMESPACE ChioGuardCpp::
    DESTINATION lib/cmake/ChioGuardCpp
  )
  install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/ChioGuardCppConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/ChioGuardCppConfigVersion.cmake"
    DESTINATION lib/cmake/ChioGuardCpp
  )
endif()
