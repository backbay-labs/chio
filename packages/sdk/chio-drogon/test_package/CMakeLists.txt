cmake_minimum_required(VERSION 3.16)
project(ChioDrogonTestPackage LANGUAGES CXX)

find_package(ChioDrogon CONFIG REQUIRED)

add_executable(chio_drogon_test_package test_package.cpp)
target_compile_features(chio_drogon_test_package PRIVATE cxx_std_17)
target_link_libraries(chio_drogon_test_package PRIVATE ChioDrogon::chio_drogon)
