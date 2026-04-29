from pathlib import Path

from conan import ConanFile
from conan.tools.files import copy
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout


class ChioDrogonConan(ConanFile):
    name = "chio-drogon"
    version = "0.1.0"
    package_type = "library"
    license = "Apache-2.0"
    author = "Back Bay Labs"
    url = "https://github.com/backbay-labs/chio"
    description = "Drogon middleware for Chio sidecar enforcement"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False]}
    default_options = {"shared": False}

    def export_sources(self):
        package_dir = Path(self.recipe_folder)
        for pattern in [
            "CMakeLists.txt",
            "cmake/*",
            "include/*",
            "src/*",
            "tests/*",
        ]:
            copy(self, pattern, src=package_dir, dst=self.export_sources_folder)

    def layout(self):
        cmake_layout(self)

    def requirements(self):
        self.requires("chio-cpp/0.1.0", transitive_headers=True)
        self.requires("drogon/1.9.12", transitive_headers=True)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        toolchain = CMakeToolchain(self)
        toolchain.variables["CHIO_DROGON_BUILD_TESTS"] = False
        toolchain.variables["CHIO_DROGON_REQUIRE_DEPS"] = True
        toolchain.variables["BUILD_SHARED_LIBS"] = self.options.shared
        toolchain.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "ChioDrogon")
        self.cpp_info.set_property("cmake_target_name", "ChioDrogon::chio_drogon")
        self.cpp_info.libs = ["chio_drogon"]
        self.cpp_info.requires = ["chio-cpp::chio-cpp", "drogon::drogon"]
