cmake_minimum_required(VERSION 3.16)

project(ChioCppKernel VERSION 0.1.0 LANGUAGES CXX)

option(CHIO_CPP_KERNEL_BUILD_TESTS "Build chio-cpp-kernel tests" ON)
option(CHIO_CPP_KERNEL_BUILD_EXAMPLES "Build chio-cpp-kernel examples" ON)
option(CHIO_CPP_KERNEL_ENABLE_FFI "Link chio-cpp-kernel to the Rust kernel FFI backend" OFF)
set(CHIO_CPP_KERNEL_FFI_INCLUDE_DIR "" CACHE PATH "Path containing chio/chio_kernel_ffi.h")
set(CHIO_CPP_KERNEL_FFI_LIBRARY "" CACHE FILEPATH "Path to libchio_cpp_kernel_ffi")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(chio_cpp_kernel
  src/kernel.cpp
)

add_library(ChioCppKernel::chio_cpp_kernel ALIAS chio_cpp_kernel)

target_include_directories(chio_cpp_kernel
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(chio_cpp_kernel PUBLIC cxx_std_17)

if(CHIO_CPP_KERNEL_ENABLE_FFI)
  if(NOT CHIO_CPP_KERNEL_FFI_INCLUDE_DIR)
    message(FATAL_ERROR "CHIO_CPP_KERNEL_FFI_INCLUDE_DIR is required when CHIO_CPP_KERNEL_ENABLE_FFI=ON")
  endif()
  if(NOT CHIO_CPP_KERNEL_FFI_LIBRARY)
    message(FATAL_ERROR "CHIO_CPP_KERNEL_FFI_LIBRARY is required when CHIO_CPP_KERNEL_ENABLE_FFI=ON")
  endif()
  add_library(chio_cpp_kernel_ffi STATIC IMPORTED GLOBAL)
  set_target_properties(chio_cpp_kernel_ffi PROPERTIES
    IMPORTED_LOCATION "${CHIO_CPP_KERNEL_FFI_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "$<BUILD_INTERFACE:${CHIO_CPP_KERNEL_FFI_INCLUDE_DIR}>"
  )
  target_compile_definitions(chio_cpp_kernel PRIVATE CHIO_CPP_KERNEL_ENABLE_FFI=1)
  target_include_directories(chio_cpp_kernel PRIVATE "${CHIO_CPP_KERNEL_FFI_INCLUDE_DIR}")
  target_link_libraries(chio_cpp_kernel PUBLIC chio_cpp_kernel_ffi)
  if(APPLE)
    target_link_libraries(chio_cpp_kernel PUBLIC "-framework Security" "-framework CoreFoundation")
  elseif(UNIX)
    target_link_libraries(chio_cpp_kernel PUBLIC dl pthread m)
  elseif(WIN32)
    target_link_libraries(chio_cpp_kernel PUBLIC ws2_32 bcrypt userenv advapi32 ntdll)
  endif()
  get_filename_component(CHIO_CPP_KERNEL_FFI_LIBRARY_DIR "${CHIO_CPP_KERNEL_FFI_LIBRARY}" DIRECTORY)
  set_target_properties(chio_cpp_kernel PROPERTIES
    BUILD_RPATH "${CHIO_CPP_KERNEL_FFI_LIBRARY_DIR}"
    INSTALL_RPATH ""
  )
endif()

if(MSVC)
  target_compile_options(chio_cpp_kernel PRIVATE /W4)
else()
  target_compile_options(chio_cpp_kernel PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(CHIO_CPP_KERNEL_BUILD_TESTS)
  enable_testing()
  add_executable(chio_cpp_kernel_tests tests/kernel_tests.cpp)
  target_link_libraries(chio_cpp_kernel_tests PRIVATE chio_cpp_kernel)
  add_test(NAME chio_cpp_kernel_tests COMMAND chio_cpp_kernel_tests)
endif()

if(CHIO_CPP_KERNEL_BUILD_EXAMPLES)
  add_executable(chio_cpp_kernel_offline_evaluate examples/offline_evaluate.cpp)
  target_link_libraries(chio_cpp_kernel_offline_evaluate PRIVATE chio_cpp_kernel)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS chio_cpp_kernel
  EXPORT ChioCppKernelTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(CHIO_CPP_KERNEL_ENABLE_FFI)
  install(FILES "${CHIO_CPP_KERNEL_FFI_LIBRARY}" DESTINATION ${CMAKE_INSTALL_LIBDIR})
  install(DIRECTORY "${CHIO_CPP_KERNEL_FFI_INCLUDE_DIR}/" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/ChioCppKernelConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ChioCppKernelConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/ChioCppKernelConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ChioCppKernel
  PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_INCLUDEDIR
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/ChioCppKernelConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/ChioCppKernelConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ChioCppKernel
)

install(EXPORT ChioCppKernelTargets
  NAMESPACE ChioCppKernel::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ChioCppKernel
)
