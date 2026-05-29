cmake_minimum_required(VERSION 3.16)

project(HelloDrogon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(HELLO_DROGON_SKIP_FILE "${CMAKE_BINARY_DIR}/hello-drogon.skip")
set(HELLO_DROGON_READY_FILE "${CMAKE_BINARY_DIR}/hello-drogon.ready")
file(REMOVE "${HELLO_DROGON_SKIP_FILE}" "${HELLO_DROGON_READY_FILE}")

find_package(Drogon CONFIG QUIET)
if(NOT TARGET Drogon::Drogon)
  file(WRITE "${HELLO_DROGON_SKIP_FILE}"
       "Drogon::Drogon was not found. Install Drogon or set CMAKE_PREFIX_PATH to its CMake package directory.\n")
  message(STATUS "Drogon::Drogon was not found; skipping hello-drogon example")
  return()
endif()

set(CHIO_DROGON_BUILD_TESTS OFF CACHE BOOL "Build chio-drogon tests" FORCE)
set(CHIO_DROGON_REQUIRE_DEPS OFF CACHE BOOL "Require chio-drogon deps" FORCE)
add_subdirectory(
  "${CMAKE_CURRENT_SOURCE_DIR}/../../sdks/cpp/chio-drogon"
  "${CMAKE_CURRENT_BINARY_DIR}/chio-drogon"
  EXCLUDE_FROM_ALL
)

if(NOT TARGET ChioDrogon::chio_drogon)
  file(WRITE "${HELLO_DROGON_SKIP_FILE}"
       "ChioDrogon::chio_drogon was not available after configuring sdks/cpp/chio-drogon.\n")
  message(STATUS "ChioDrogon::chio_drogon was not available; skipping hello-drogon example")
  return()
endif()

add_executable(hello_drogon main.cpp)
target_link_libraries(hello_drogon PRIVATE ChioDrogon::chio_drogon)
target_compile_features(hello_drogon PRIVATE cxx_std_17)

if(MSVC)
  target_compile_options(hello_drogon PRIVATE /W4)
else()
  target_compile_options(hello_drogon PRIVATE -Wall -Wextra -Wpedantic)
endif()

file(WRITE "${HELLO_DROGON_READY_FILE}" "hello_drogon target configured\n")
