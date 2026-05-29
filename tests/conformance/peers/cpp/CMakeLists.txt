cmake_minimum_required(VERSION 3.16)
project(ChioCppConformancePeer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CHIO_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CHIO_CPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CHIO_CPP_ENABLE_CURL ON CACHE BOOL "" FORCE)
add_subdirectory(../../../../sdks/cpp/chio-cpp chio-cpp)

add_executable(chio_cpp_conformance_peer client.cpp)
target_link_libraries(chio_cpp_conformance_peer PRIVATE chio_cpp)
