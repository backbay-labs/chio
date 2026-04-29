# chio-cpp-kernel ships a Rust workspace member (crates/chio-cpp-kernel-ffi)
# that must be built before CMake configure. The portfile invokes
# `cargo build -p chio-cpp-kernel-ffi --release` against the source tarball,
# then points CMake at the resulting libchio_cpp_kernel_ffi.a via the
# CHIO_CPP_KERNEL_FFI_LIBRARY / CHIO_CPP_KERNEL_FFI_INCLUDE_DIR variables.
# Cargo needs a Rust toolchain on PATH and either network access OR a
# vendored ${SOURCE_PATH}/vendor/ directory.

# release-cpp.yml tags releases as `cpp/v<X.Y.Z>` and computes the SHA512
# against the corresponding archive. Use the same ref so the published
# port resolves to the exact tarball the SHA was hashed against.
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO bb-connor/arc
    REF "cpp/v${VERSION}"
    SHA512 0
    HEAD_REF main
)

find_program(CARGO_EXECUTABLE cargo)
if(NOT CARGO_EXECUTABLE)
    message(FATAL_ERROR
        "chio-cpp-kernel requires cargo on PATH to build "
        "crates/chio-cpp-kernel-ffi. Install a Rust toolchain via rustup, or "
        "use the prebuilt binaries from the OCI Object Storage binary cache.")
endif()

vcpkg_execute_required_process(
    COMMAND "${CARGO_EXECUTABLE}" build -p chio-cpp-kernel-ffi --release
    WORKING_DIRECTORY "${SOURCE_PATH}"
    LOGNAME "cargo-build-${TARGET_TRIPLET}"
)

if(VCPKG_TARGET_IS_WINDOWS)
    set(CHIO_KERNEL_FFI_LIB_NAME "chio_cpp_kernel_ffi.lib")
else()
    set(CHIO_KERNEL_FFI_LIB_NAME "libchio_cpp_kernel_ffi.a")
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/packages/sdk/chio-cpp-kernel"
    OPTIONS
        -DCHIO_CPP_KERNEL_BUILD_TESTS=OFF
        -DCHIO_CPP_KERNEL_BUILD_EXAMPLES=OFF
        -DCHIO_CPP_KERNEL_ENABLE_FFI=ON
        "-DCHIO_CPP_KERNEL_FFI_INCLUDE_DIR=${SOURCE_PATH}/crates/chio-cpp-kernel-ffi/include"
        "-DCHIO_CPP_KERNEL_FFI_LIBRARY=${SOURCE_PATH}/target/release/${CHIO_KERNEL_FFI_LIB_NAME}"
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME ChioCppKernel CONFIG_PATH lib/cmake/ChioCppKernel)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

file(INSTALL "${SOURCE_PATH}/LICENSE"
    DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}"
    RENAME copyright
)
