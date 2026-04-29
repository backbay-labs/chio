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

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/packages/sdk/chio-drogon"
    OPTIONS
        -DCHIO_DROGON_BUILD_TESTS=OFF
        -DCHIO_DROGON_REQUIRE_DEPS=ON
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME ChioDrogon CONFIG_PATH lib/cmake/ChioDrogon)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

file(INSTALL "${SOURCE_PATH}/LICENSE"
    DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}"
    RENAME copyright
)
