# chio-cpp ships a Rust workspace member (crates/chio-bindings-ffi) that
# must be built before CMake configure. The portfile invokes
# `cargo build -p chio-bindings-ffi --release` against the source tarball,
# then points CMake at the resulting libchio_bindings_ffi.a via
# CHIO_CPP_REPO_ROOT. Cargo needs a Rust toolchain on PATH and either
# network access OR a vendored ${SOURCE_PATH}/vendor/ directory.

# The release-cpp.yml workflow tags chio-cpp releases under the
# `cpp/v<MAJOR.MINOR.PATCH>` tag family (alongside the unprefixed
# `v<MAJOR.MINOR.PATCH>` Rust release tags) and computes the SHA512
# from `archive/refs/tags/cpp/v<VERSION>.tar.gz` before publishing to
# the registry. The previous `REF "v${VERSION}"` fetched a different
# (or non-existent) ref than the one the SHA was hashed against, so
# consumers installing from the published registry hit a checksum
# mismatch (cleanup-c11d; PR #94 review thread r3144022628 - P1).
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
        "chio-cpp requires cargo on PATH to build crates/chio-bindings-ffi. "
        "Install a Rust toolchain via rustup, or use the prebuilt binaries "
        "from the OCI Object Storage binary cache.")
endif()

vcpkg_execute_required_process(
    COMMAND "${CARGO_EXECUTABLE}" build -p chio-bindings-ffi --release
    WORKING_DIRECTORY "${SOURCE_PATH}"
    LOGNAME "cargo-build-${TARGET_TRIPLET}"
)

vcpkg_check_features(
    OUT_FEATURE_OPTIONS FEATURE_OPTIONS
    FEATURES
        curl CHIO_CPP_ENABLE_CURL
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/packages/sdk/chio-cpp"
    OPTIONS
        ${FEATURE_OPTIONS}
        -DCHIO_CPP_BUILD_TESTS=OFF
        -DCHIO_CPP_BUILD_EXAMPLES=OFF
        -DCHIO_CPP_BUILD_RUST_FFI=OFF
        -DCHIO_CPP_BUILD_CONFORMANCE_PEER=OFF
        "-DCHIO_CPP_REPO_ROOT=${SOURCE_PATH}"
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME ChioCpp CONFIG_PATH lib/cmake/ChioCpp)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

file(INSTALL "${SOURCE_PATH}/LICENSE"
    DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}"
    RENAME copyright
)
