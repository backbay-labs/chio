cmake_minimum_required(VERSION 3.16)
project(ChioCppTestPackage LANGUAGES CXX)

find_package(ChioCpp CONFIG REQUIRED)

add_executable(chio_cpp_test_package test_package.cpp)
target_compile_features(chio_cpp_test_package PRIVATE cxx_std_17)
target_link_libraries(chio_cpp_test_package PRIVATE ChioCpp::chio_cpp)
