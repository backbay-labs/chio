cmake_minimum_required(VERSION 3.16)

project(ChioDrogon VERSION 0.1.0 LANGUAGES CXX)

option(CHIO_DROGON_BUILD_TESTS "Build chio-drogon tests" ON)
option(CHIO_DROGON_REQUIRE_DEPS "Fail configure when Drogon or ChioCpp is missing" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Drogon CONFIG QUIET)

if(NOT TARGET Drogon::Drogon)
  if(CHIO_DROGON_REQUIRE_DEPS)
    message(FATAL_ERROR "Drogon::Drogon was not found")
  endif()
  message(STATUS "Drogon::Drogon was not found; skipping chio-drogon target")
  return()
endif()

find_package(ChioCpp CONFIG QUIET)

if(NOT TARGET ChioCpp::chio_cpp AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../chio-cpp/CMakeLists.txt")
  set(CHIO_CPP_BUILD_TESTS OFF CACHE BOOL "Build chio-cpp tests" FORCE)
  set(CHIO_CPP_BUILD_EXAMPLES OFF CACHE BOOL "Build chio-cpp examples" FORCE)
  set(CHIO_CPP_BUILD_CONFORMANCE_PEER OFF CACHE BOOL "Build chio-cpp conformance peer" FORCE)
  set(CHIO_CPP_ENABLE_CURL ON CACHE BOOL "Build chio-cpp libcurl transport" FORCE)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../chio-cpp" "${CMAKE_CURRENT_BINARY_DIR}/chio-cpp" EXCLUDE_FROM_ALL)
endif()

if(NOT TARGET ChioCpp::chio_cpp)
  if(CHIO_DROGON_REQUIRE_DEPS)
    message(FATAL_ERROR "ChioCpp::chio_cpp was not found")
  endif()
  message(STATUS "ChioCpp::chio_cpp was not found; skipping chio-drogon target")
  return()
endif()

add_library(chio_drogon
  src/drogon.cpp
)
add_library(ChioDrogon::chio_drogon ALIAS chio_drogon)

target_include_directories(chio_drogon
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(chio_drogon PUBLIC cxx_std_17)
target_link_libraries(chio_drogon
  PUBLIC
    ChioCpp::chio_cpp
    Drogon::Drogon
)

if(MSVC)
  target_compile_options(chio_drogon PRIVATE /W4)
else()
  target_compile_options(chio_drogon PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(CHIO_DROGON_BUILD_TESTS)
  enable_testing()
  add_executable(chio_drogon_smoke_tests tests/smoke.cpp)
  target_link_libraries(chio_drogon_smoke_tests PRIVATE chio_drogon)
  add_test(NAME chio_drogon_smoke_tests COMMAND chio_drogon_smoke_tests)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS chio_drogon
  EXPORT ChioDrogonTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/ChioDrogonConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ChioDrogonConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/ChioDrogonConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ChioDrogon
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/ChioDrogonConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/ChioDrogonConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ChioDrogon
)

install(EXPORT ChioDrogonTargets
  NAMESPACE ChioDrogon::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ChioDrogon
)
