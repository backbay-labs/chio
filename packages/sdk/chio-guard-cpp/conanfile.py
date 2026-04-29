from conan import ConanFile
from conan.tools.files import copy
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.layout import basic_layout


class ChioGuardCppConan(ConanFile):
    name = "chio-guard-cpp"
    version = "0.1.0"
    package_type = "header-library"
    license = "Apache-2.0"
    author = "Back Bay Labs"
    url = "https://github.com/backbay-labs/chio"
    description = "Header-only C++17 authoring SDK for Chio WASM guard components"
    settings = "os", "compiler", "build_type", "arch"
    no_copy_source = True
    exports_sources = (
        "CMakeLists.txt",
        "cmake/*",
        "include/*",
    )

    def layout(self):
        cmake_layout(self)

    def generate(self):
        toolchain = CMakeToolchain(self)
        toolchain.variables["CHIO_GUARD_CPP_BUILD_EXAMPLES"] = False
        toolchain.variables["CHIO_GUARD_CPP_BUILD_TESTS"] = False
        toolchain.variables["CHIO_GUARD_CPP_GENERATE"] = False
        toolchain.variables["CHIO_GUARD_CPP_BUILD_WASI_COMPONENT"] = False
        toolchain.variables["CHIO_GUARD_CPP_INSTALL"] = True
        toolchain.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "ChioGuardCpp")
        self.cpp_info.set_property("cmake_target_name", "ChioGuardCpp::chio_guard_cpp")
        self.cpp_info.bindirs = []
        self.cpp_info.libdirs = []
