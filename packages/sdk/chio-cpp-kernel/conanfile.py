import re
from pathlib import Path

from conan import ConanFile
from conan.tools.files import chdir, copy, save
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout


class ChioCppKernelConan(ConanFile):
    name = "chio-cpp-kernel"
    version = "0.1.0"
    package_type = "library"
    license = "Apache-2.0"
    author = "Back Bay Labs"
    url = "https://github.com/backbay-labs/chio"
    description = "C++17 SDK for the Chio offline policy kernel"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False]}
    default_options = {"shared": False}

    _rust_workspace_roots = ["crates/chio-cpp-kernel-ffi"]

    @staticmethod
    def _extract_manifest_section(manifest, header):
        start_marker = f"{header}\n"
        start = manifest.find(start_marker)
        if start == -1:
            raise ValueError(f"missing {header} in workspace Cargo.toml")
        section_name = header.strip("[]")
        lines = manifest[start:].splitlines()
        out = []
        for index, line in enumerate(lines):
            stripped = line.strip()
            if index > 0 and stripped.startswith("[") and stripped.endswith("]"):
                current = stripped.strip("[]")
                if current != section_name and not current.startswith(f"{section_name}."):
                    break
            out.append(line)
        return "\n".join(out).strip()

    @staticmethod
    def _path_dependency_members(crate_manifest, repo_root):
        text = crate_manifest.read_text()
        repo_root = repo_root.resolve()
        members = []
        for dependency_path in re.findall(r'path\s*=\s*"([^"]+)"', text):
            dependency_dir = (crate_manifest.parent / dependency_path).resolve()
            if not (dependency_dir / "Cargo.toml").exists():
                continue
            try:
                members.append(dependency_dir.relative_to(repo_root).as_posix())
            except ValueError:
                continue
        return members

    def _rust_workspace_members(self, repo_root):
        members = set()
        pending = list(self._rust_workspace_roots)
        while pending:
            crate = pending.pop()
            if crate in members:
                continue
            crate_manifest = repo_root / crate / "Cargo.toml"
            if not crate_manifest.exists():
                raise ValueError(f"missing Cargo.toml for Rust crate {crate}")
            members.add(crate)
            pending.extend(
                dependency
                for dependency in self._path_dependency_members(crate_manifest, repo_root)
                if dependency not in members
            )
        return sorted(members)

    def _trimmed_workspace_manifest(self, repo_root):
        root_manifest = (repo_root / "Cargo.toml").read_text()
        workspace_members = self._rust_workspace_members(repo_root)
        members = "\n".join(
            f'    "{member}",' for member in workspace_members
        )
        copied_sections = "\n\n".join(
            self._extract_manifest_section(root_manifest, header)
            for header in [
                "[workspace.package]",
                "[workspace.lints.clippy]",
                "[workspace.dependencies]",
            ]
        )
        return (
            "[workspace]\n"
            'resolver = "2"\n'
            "members = [\n"
            f"{members}\n"
            "]\n\n"
            f"{copied_sections}\n"
        )

    @staticmethod
    def _cmake_repo_root(source_folder):
        source_root = Path(source_folder)
        if (source_root / "Cargo.toml").exists():
            return source_root
        candidate = source_root.parents[2]
        if (candidate / "Cargo.toml").exists():
            return candidate
        raise ValueError("cannot find Cargo.toml for CMake CHIO_CPP_KERNEL_REPO_ROOT")

    def export_sources(self):
        package_dir = Path(self.recipe_folder)
        repo_root = package_dir.parents[2]
        workspace_members = self._rust_workspace_members(repo_root)
        for pattern in [
            "CMakeLists.txt",
            "cmake/*",
            "include/*",
            "src/*",
            "tests/*",
            "examples/*",
        ]:
            copy(self, pattern, src=package_dir, dst=self.export_sources_folder)
        for member in workspace_members:
            copy(
                self,
                "*",
                src=repo_root / member,
                dst=Path(self.export_sources_folder) / member,
            )
        save(
            self,
            Path(self.export_sources_folder) / "Cargo.toml",
            self._trimmed_workspace_manifest(repo_root),
        )
        copy(self, "Cargo.lock", src=repo_root, dst=self.export_sources_folder)

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        toolchain = CMakeToolchain(self)
        toolchain.variables["CHIO_CPP_KERNEL_BUILD_TESTS"] = False
        toolchain.variables["CHIO_CPP_KERNEL_BUILD_EXAMPLES"] = False
        toolchain.variables["CHIO_CPP_KERNEL_ENABLE_FFI"] = True
        repo_root = self._cmake_repo_root(self.source_folder)
        build_type = str(self.settings.build_type or "Debug")
        profile = "release" if build_type and build_type != "Debug" else "debug"
        ffi_lib_name = "libchio_cpp_kernel_ffi.a"
        if str(self.settings.os) == "Windows":
            ffi_lib_name = "chio_cpp_kernel_ffi.lib"
        toolchain.variables["CHIO_CPP_KERNEL_FFI_INCLUDE_DIR"] = str(
            repo_root / "crates" / "chio-cpp-kernel-ffi" / "include"
        )
        toolchain.variables["CHIO_CPP_KERNEL_FFI_LIBRARY"] = str(
            repo_root / "target" / profile / ffi_lib_name
        )
        toolchain.variables["BUILD_SHARED_LIBS"] = self.options.shared
        toolchain.generate()

    def build(self):
        cargo = "cargo build -p chio-cpp-kernel-ffi"
        build_type = str(self.settings.build_type or "")
        if build_type and build_type != "Debug":
            cargo += " --release"
        with chdir(self, self.source_folder):
            self.run(cargo)
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "ChioCppKernel")
        self.cpp_info.set_property(
            "cmake_target_name", "ChioCppKernel::chio_cpp_kernel"
        )
        self.cpp_info.libs = ["chio_cpp_kernel", "chio_cpp_kernel_ffi"]
        if str(self.settings.os) == "Macos":
            self.cpp_info.frameworks = ["Security", "CoreFoundation"]
        elif str(self.settings.os) in ["Linux", "FreeBSD"]:
            self.cpp_info.system_libs = ["dl", "pthread", "m"]
        elif str(self.settings.os) == "Windows":
            self.cpp_info.system_libs = [
                "ws2_32",
                "bcrypt",
                "userenv",
                "advapi32",
                "ntdll",
            ]
