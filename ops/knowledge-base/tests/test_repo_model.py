from __future__ import annotations

from chio_kb import repo_model


def test_normalize_path_strips_workspace_prefixes(monkeypatch) -> None:
    monkeypatch.setenv("CHIO_KB_REPO_ROOT", "/workspace/chio")
    cases = {
        "workspace/crates/chio-kernel/src/kernel/mod.rs": "crates/chio-kernel/src/kernel/mod.rs",
        "/workspace/crates/chio-core-types/src/capability.rs": "crates/chio-core-types/src/capability.rs",
        "/workspace/chio/docs/README.md": "docs/README.md",
        "spec/PROTOCOL.md": "spec/PROTOCOL.md",
        "": "",
        ".": "",
        "./": "",
        "/workspace": "",
    }
    for raw, expected in cases.items():
        assert repo_model.normalize_path(raw) == expected


def test_file_info_classifies_crate_metadata() -> None:
    info = repo_model.file_info("/workspace/crates/chio-kernel/src/kernel/mod.rs")
    assert info.path == "crates/chio-kernel/src/kernel/mod.rs"
    assert info.source_root == "crates"
    assert info.crate == "chio-kernel"
    assert info.package == ""
    assert info.kind == "code"
    assert info.nearest_manifest == "crates/chio-kernel/Cargo.toml"
    assert info.canonicality == "source"
    assert info.validation_command == "cargo test -p chio-kernel"


def test_file_info_classifies_package_metadata() -> None:
    info = repo_model.file_info("packages/sdk/chio-cpp/src/client.cpp")
    assert info.source_root == "packages"
    assert info.package == "packages/sdk/chio-cpp"
    assert info.language == "cpp"
    assert info.validation_command == "npm test"


def test_canonicality_and_generation() -> None:
    assert repo_model.file_info("spec/PROTOCOL.md").canonicality == "canonical"
    assert repo_model.file_info("docs/conformance/verdict-matrix.md").canonicality == "canonical"
    assert repo_model.file_info(".planning/v3.14-MILESTONE-AUDIT.md").canonicality == "planning"
    generated = repo_model.file_info("crates/chio-core-types/src/_generated/chio_wire_v1.rs")
    assert generated.is_generated is True
    assert generated.canonicality == "generated"


def test_scoped_concepts_are_path_sensitive() -> None:
    text = "Capability tokens validate delegated revocation scopes before dispatch."
    scoped = repo_model.scoped_concepts("crates/chio-kernel/src/kernel/mod.rs", text)
    assert {item.id for item in scoped} >= {"capability:kernel-validation"}
    unrelated = repo_model.scoped_concepts("docs/release/QUALIFICATION.md", text)
    assert {item.id for item in unrelated} == set()
