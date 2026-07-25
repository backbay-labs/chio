use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::support::{
    copy_dir_recursive, digest_to_hex, display_path, walk_schema_json, workspace_root, TempDir,
};
use crate::XtaskError;

use super::CHIO_WIRE_V1_SCHEMAS;

/// Pinned tool spec for the Python codegen target. Reflected in
/// `[python]` in `xtask/codegen-tools.lock.toml`. Bumping this is a
/// spec-affecting change and must regenerate every `_generated/*.py` byte.
const PYTHON_CODEGEN_TOOL_PIN: &str = "datamodel-code-generator==0.34.0";

/// Relative path (from workspace root) of the generated Python output dir.
const CHIO_WIRE_V1_PYTHON_OUT: &str = "sdks/python/chio-sdk-python/src/chio_sdk/_generated";

/// Filename of the per-package `__init__.py` re-export written under each
/// generated subpackage. The xtask does not author these; datamodel-codegen
/// emits them as part of its directory-mode output.
const PYTHON_INIT_FILE: &str = "__init__.py";

pub(super) fn codegen_python(check_only: bool) -> Result<(), XtaskError> {
    let workspace_root = workspace_root()?;
    let schemas_dir = workspace_root.join(CHIO_WIRE_V1_SCHEMAS);
    let final_out_dir = workspace_root.join(CHIO_WIRE_V1_PYTHON_OUT);

    if !schemas_dir.exists() {
        return Err(XtaskError::Codegen(
            chio_spec_codegen::CodegenError::SchemasDirMissing(schemas_dir.clone()),
        ));
    }

    let mut schema_files: Vec<PathBuf> = Vec::new();
    walk_schema_json(&schemas_dir, &mut schema_files)?;
    schema_files.sort();
    let schema_digest = hash_schema_set(&workspace_root, &schema_files)?;

    let staging = TempDir::new("chio-codegen-py")
        .map_err(|err| XtaskError::Io("<temp staging dir for codegen python>".to_string(), err))?;

    let clean_input = staging.path().join("input");
    mirror_schema_tree(&schemas_dir, &clean_input, &schema_files)?;

    let staging_out = staging.path().join("output");
    fs::create_dir_all(&staging_out)
        .map_err(|err| XtaskError::Io(display_path(&staging_out), err))?;

    let header_path = staging.path().join("file-header.txt");
    fs::write(&header_path, build_python_file_header(&schema_digest))
        .map_err(|err| XtaskError::Io(display_path(&header_path), err))?;

    invoke_datamodel_codegen(&clean_input, &staging_out, &header_path)?;
    harden_python_generated_models(&staging_out)?;

    // Walk the freshly-generated tree and rewrite each subpackage's
    // `__init__.py` to re-export its top-level model classes. The
    // top-level `__init__.py` then star-imports every subpackage. Together
    // these provide the documented `from chio_sdk._generated import
    // CapabilityToken` import path; without this step datamodel-codegen's
    // empty subpackage init files cause that import to raise `ImportError`.
    let subpackage_exports = rewrite_python_subpackage_inits(&staging_out, &schema_digest)?;

    let top_init = staging_out.join(PYTHON_INIT_FILE);
    fs::write(
        &top_init,
        build_python_top_init(&schema_digest, &subpackage_exports),
    )
    .map_err(|err| XtaskError::Io(display_path(&top_init), err))?;

    if check_only {
        let drift = diff_python_trees(&staging_out, &final_out_dir)?;
        if let Some(detail) = drift {
            return Err(XtaskError::Drift(format!(
                "{} is stale; rerun `cargo xtask codegen python` ({} schema files inspected)\n{}",
                display_path(&final_out_dir),
                schema_files.len(),
                detail
            )));
        }
        println!(
            "codegen python: {} in sync ({} schema files, {} python files)",
            display_path(&final_out_dir),
            schema_files.len(),
            count_python_files(&staging_out)?
        );
        return Ok(());
    }

    if final_out_dir.exists() {
        fs::remove_dir_all(&final_out_dir)
            .map_err(|err| XtaskError::Io(display_path(&final_out_dir), err))?;
    }
    if let Some(parent) = final_out_dir.parent() {
        fs::create_dir_all(parent).map_err(|err| XtaskError::Io(display_path(parent), err))?;
    }
    copy_dir_recursive(&staging_out, &final_out_dir)?;
    let py_count = count_python_files(&final_out_dir)?;
    println!(
        "codegen python: wrote {} ({} python files; {} schema files; sha256={})",
        display_path(&final_out_dir),
        py_count,
        schema_files.len(),
        schema_digest
    );
    Ok(())
}

fn build_python_file_header(schema_digest: &str) -> String {
    format!(
        "# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.\n\
         #\n\
         # Source: spec/schemas/chio-wire/v1/**/*.schema.json\n\
         # Tool:   {PYTHON_CODEGEN_TOOL_PIN} (see xtask/codegen-tools.lock.toml)\n\
         # Schema sha256: {schema_digest}\n\
         #\n\
         # Manual edits will be overwritten by the next regeneration; the\n\
         # spec-drift CI lane enforces this header on every file\n\
         # under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.\n"
    )
}

fn harden_python_generated_models(root_dir: &Path) -> Result<(), XtaskError> {
    harden_python_jsonrpc_response(&root_dir.join("jsonrpc").join("response_schema.py"))?;
    harden_python_receipt_record(&root_dir.join("receipt").join("record_schema.py"))?;
    harden_python_provenance_verdict_link(
        &root_dir.join("provenance").join("verdict_link_schema.py"),
    )?;
    harden_python_capability_negotiation(
        &root_dir.join("capability").join("capabilities_schema.py"),
    )?;
    harden_python_capability_token(&root_dir.join("capability").join("token_schema.py"))?;
    Ok(())
}

fn harden_python_capability_token(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    root: (\n        GenericConstraint\n        | LegacyApprovalConstraint\n        | CumulativeApprovalDirectConstraint\n        | CumulativeApprovalDelegableConstraint\n    )\n\n\nclass AttenuationProof(BaseModel):",
        "    root: (\n        GenericConstraint\n        | LegacyApprovalConstraint\n        | CumulativeApprovalDirectConstraint\n        | CumulativeApprovalDelegableConstraint\n    )\n\n    @property\n    def type(self) -> str:\n        return self.root.type\n\n    @property\n    def value(self) -> Any:\n        return self.root.value\n\n\nclass AttenuationProof(BaseModel):",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

/// Enforce receipt schema constraints that datamodel-code-generator does not
/// currently express for dependent BBS fields.
fn harden_python_receipt_record(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr",
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr, model_validator",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    bbs_projection_version: Literal[\"chio.bbs-projection.receipt.v1\"] = Field(\n        \"chio.bbs-projection.receipt.v1\",\n        description=\"Receipt-body BBS projection version bound into the receipt id when bbs_signature is present.\",\n    )\n",
        "    bbs_projection_version: Literal[\"chio.bbs-projection.receipt.v1\"] | None = Field(\n        None,\n        description=\"Receipt-body BBS projection version bound into the receipt id when bbs_signature is present.\",\n    )\n",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    bbs_signature: BbsReceiptSignature | None = Field(\n        None,\n        description=\"Optional BBS signature material for selective disclosure. When present, the Ed25519 receipt signature covers this material through ChioReceiptSigningBody.\",\n    )\n    algorithm: Algorithm | None = Field(\n",
        "    bbs_signature: BbsReceiptSignature | None = Field(\n        None,\n        description=\"Optional BBS signature material for selective disclosure. When present, the Ed25519 receipt signature covers this material through ChioReceiptSigningBody.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _validate_bbs_pairing(self) -> \"ChioReceiptRecord\":\n        has_projection = self.bbs_projection_version is not None\n        has_signature = self.bbs_signature is not None\n        if has_projection != has_signature:\n            raise ValueError(\n                \"bbs_projection_version and bbs_signature must be present together\"\n            )\n        return self\n\n    algorithm: Algorithm | None = Field(\n",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

/// Inject a `model_validator` on `ChioCapabilityNegotiationV1` that
/// enforces the schema's `propertyNames` regex pattern on each feature
/// key. `datamodel-code-generator` drops `propertyNames` constraints,
/// which would let a Python peer accept negotiation payloads that the
/// Rust verifier rejects (`CapabilityNegotiation::validate`). Mirror
/// the wire-side check here so cross-language consumers fail closed
/// in the same place.
fn harden_python_capability_negotiation(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field",
        "import re\n\nfrom pydantic import BaseModel, ConfigDict, Field, model_validator",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field, model_validator\n",
        "from pydantic import BaseModel, ConfigDict, Field, model_validator\n\n_CHIO_FEATURE_NAME_RE = re.compile(r\"^[a-z0-9_.-]{1,96}$\")\n",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    features: dict[str, bool] | None = Field(\n        None,\n        description=\"String-keyed feature bitset. Peers proceed only with the intersection of true values advertised by both sides.\",\n    )\n",
        "    features: dict[str, bool] | None = Field(\n        None,\n        description=\"String-keyed feature bitset. Peers proceed only with the intersection of true values advertised by both sides.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _validate_feature_names(self) -> \"ChioCapabilityNegotiationV1\":\n        if self.features is None:\n            return self\n        for name in self.features:\n            if not _CHIO_FEATURE_NAME_RE.match(name):\n                raise ValueError(\n                    f\"capability feature name {name!r} does not match \"\n                    f\"propertyNames pattern ^[a-z0-9_.-]{{1,96}}$\"\n                )\n        return self\n",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

fn harden_python_jsonrpc_response(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, constr",
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, constr, model_validator",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    error: Error | None = Field(\n        None,\n        description=\"Error payload. Present only on failure. Mutually exclusive with `result`.\",\n    )\n\n\nclass ChioJsonRpc20Response2(BaseModel):",
        "    error: Error | None = Field(\n        None,\n        description=\"Error payload. Present only on failure. Mutually exclusive with `result`.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _success_excludes_error(self) -> \"ChioJsonRpc20Response1\":\n        if \"error\" in self.model_fields_set:\n            raise ValueError(\"JSON-RPC success response must not include error\")\n        return self\n\n\nclass ChioJsonRpc20Response2(BaseModel):",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    error: Error = Field(\n        ...,\n        description=\"Error payload. Present only on failure. Mutually exclusive with `result`.\",\n    )\n\n\nclass ChioJsonRpc20Response(RootModel[ChioJsonRpc20Response1 | ChioJsonRpc20Response2]):",
        "    error: Error = Field(\n        ...,\n        description=\"Error payload. Present only on failure. Mutually exclusive with `result`.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _error_excludes_result(self) -> \"ChioJsonRpc20Response2\":\n        if \"result\" in self.model_fields_set:\n            raise ValueError(\"JSON-RPC error response must not include result\")\n        return self\n\n\nclass ChioJsonRpc20Response(RootModel[ChioJsonRpc20Response1 | ChioJsonRpc20Response2]):",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

fn harden_python_provenance_verdict_link(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr",
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr, model_validator",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n\nclass ChioProvenanceVerdictLink2(BaseModel):",
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _allow_excludes_rejection_fields(self) -> \"ChioProvenanceVerdictLink1\":\n        if \"reason\" in self.model_fields_set or \"guard\" in self.model_fields_set:\n            raise ValueError(\"allow verdict must not include reason or guard\")\n        return self\n\n\nclass ChioProvenanceVerdictLink2(BaseModel):",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n\nclass ChioProvenanceVerdictLink4(BaseModel):",
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _cancel_excludes_guard(self) -> \"ChioProvenanceVerdictLink3\":\n        if \"guard\" in self.model_fields_set:\n            raise ValueError(\"cancel verdict must not include guard\")\n        return self\n\n\nclass ChioProvenanceVerdictLink4(BaseModel):",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n\nclass ChioProvenanceVerdictLink(",
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _incomplete_excludes_guard(self) -> \"ChioProvenanceVerdictLink4\":\n        if \"guard\" in self.model_fields_set:\n            raise ValueError(\"incomplete verdict must not include guard\")\n        return self\n\n\nclass ChioProvenanceVerdictLink(",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

fn replace_python_codegen_snippet(
    path: &Path,
    body: &mut String,
    needle: &str,
    replacement: &str,
) -> Result<(), XtaskError> {
    if !body.contains(needle) {
        return Err(XtaskError::ToolFailed(format!(
            "codegen python hardening pattern missing in {}",
            display_path(path)
        )));
    }
    *body = body.replacen(needle, replacement, 1);
    Ok(())
}

/// Per-subpackage re-export plan built by [`rewrite_python_subpackage_inits`].
///
/// Each entry is `(subpackage_dir_name, [class_name, ...])` sorted by
/// `subpackage_dir_name`. Class names are sorted within each subpackage so
/// the output is byte-stable across regenerations on different filesystems.
type PythonSubpackageExports = Vec<(String, Vec<String>)>;

fn build_python_top_init(schema_digest: &str, subpackages: &PythonSubpackageExports) -> String {
    let header = build_python_file_header(schema_digest);

    // Build the deterministic re-export block. Each line is
    // `from .<subpkg> import <Class1>, <Class2>` plus an `__all__` listing
    // every re-exported name and the SCHEMA_SHA256 constant.
    //
    // Names that collide across subpackages (e.g. `Kind` defined in both
    // `anchor` and `capability`) are imported with a `<Subpkg><Name>` alias
    // so the top-level `__init__.py` does not silently shadow one with the
    // other. Both aliases are listed in `__all__`. The unaliased name is
    // kept only when a single subpackage owns it.
    let mut name_owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (subpkg, classes) in subpackages {
        for class in classes {
            if subpkg == "agent" && class == "CapabilityToken" {
                continue;
            }
            name_owners
                .entry(class.clone())
                .or_default()
                .push(subpkg.clone());
        }
    }

    let mut imports = String::new();
    let mut all_names: Vec<String> = vec!["SCHEMA_SHA256".to_string()];
    for (subpkg, classes) in subpackages {
        let mut entries: Vec<String> = Vec::new();
        for class in classes {
            if subpkg == "agent" && class == "CapabilityToken" {
                continue;
            }
            let owners = name_owners.get(class).map(Vec::as_slice).unwrap_or(&[]);
            if owners.len() > 1 {
                // Collision across subpackages: alias as <Subpkg><Class>.
                let alias = format!("{}{}", capitalize_subpkg(subpkg), class);
                entries.push(format!("{class} as {alias}"));
                all_names.push(alias);
            } else {
                entries.push(class.clone());
                all_names.push(class.clone());
            }
        }
        if entries.is_empty() {
            continue;
        }
        imports.push_str(&format!(
            "from .{subpkg} import {names}\n",
            names = entries.join(", ")
        ));
    }
    let has_capability_v1 = subpackages.iter().any(|(subpkg, classes)| {
        subpkg == "capability" && classes.iter().any(|name| name == "ChioCapabilitytoken")
    });
    if has_capability_v1 {
        imports.push_str("\nCapabilityToken = ChioCapabilitytoken\n");
        all_names.push("CapabilityToken".to_string());
    }
    if all_names.iter().any(|name| name == "ReceiptDecision") {
        imports.push_str("Decision = ReceiptDecision\n");
        all_names.push("Decision".to_string());
    }
    for name in ["Constraint", "Operation", "PromptGrant", "ResourceGrant"] {
        if all_names.iter().any(|candidate| candidate == name) {
            let alias = format!("Capability{name}");
            imports.push_str(&format!("{alias} = {name}\n"));
            all_names.push(alias);
        }
    }
    all_names.sort();
    all_names.dedup();

    let mut all_block = String::from("__all__ = [\n");
    for name in &all_names {
        all_block.push_str(&format!("    \"{name}\",\n"));
    }
    all_block.push_str("]\n");

    format!(
        "{header}\n\
         \"\"\"Generated Pydantic v2 models for the Chio wire protocol (chio-wire/v1).\n\
         \n\
         Re-exports every subpackage so callers can write\n\
         ``from chio_sdk._generated import CapabilityToken`` for the canonical\n\
         capability token shapes without knowing the per-subpackage layout. Class\n\
         names that collide across subpackages (for example ``Kind`` defined in\n\
         both ``anchor`` and ``capability``) are re-exported under a\n\
         ``<Subpkg><Class>`` alias (``AnchorKind``, ``CapabilityKind``) so\n\
         neither definition silently shadows the other. The SCHEMA_SHA256\n\
         constant pins the schema set this build was generated from; the\n\
         spec-drift CI lane reads it to detect tampering.\n\
         \"\"\"\n\
         \n\
         from __future__ import annotations\n\
         \n\
         from pydantic import TypeAdapter\n\
         from pydantic_core import core_schema\n\
         \n\
         #: SHA-256 of the lexicographically sorted concatenation of every\n\
         #: ``spec/schemas/chio-wire/v1/**/*.schema.json`` byte stream that was\n\
         #: fed into datamodel-code-generator at build time.\n\
         SCHEMA_SHA256 = \"{schema_digest}\"\n\
         \n\
         {imports}\n\
         {all_block}"
    )
}

/// Convert a snake_case subpackage directory name (e.g. `trust_control`) into
/// a CamelCase prefix (e.g. `TrustControl`) used to disambiguate class names
/// that collide across subpackages in the top-level `__init__.py`.
fn capitalize_subpkg(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut next_upper = true;
    for ch in name.chars() {
        if ch == '_' || ch == '-' {
            next_upper = true;
            continue;
        }
        if next_upper {
            for upper in ch.to_uppercase() {
                out.push(upper);
            }
            next_upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// Walk every subpackage directory under `root_dir`, scan each `*.py` module
/// (other than `__init__.py`) for top-level `class Name(...):` declarations,
/// rewrite the subpackage's `__init__.py` to re-export those classes, and
/// return the (sorted) plan so the top-level `__init__.py` can re-export
/// each subpackage in turn.
fn rewrite_python_subpackage_inits(
    root_dir: &Path,
    schema_digest: &str,
) -> Result<PythonSubpackageExports, XtaskError> {
    let header = build_python_file_header(schema_digest);
    let mut subpackages: PythonSubpackageExports = Vec::new();
    let entries =
        fs::read_dir(root_dir).map_err(|err| XtaskError::Io(display_path(root_dir), err))?;
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(root_dir), err))?;
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        }
    }
    subdirs.sort();

    for subdir in subdirs {
        let Some(name) = subdir.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        if name.starts_with('_') {
            continue;
        }
        let mut module_classes: Vec<(String, Vec<String>)> = Vec::new();
        let module_entries =
            fs::read_dir(&subdir).map_err(|err| XtaskError::Io(display_path(&subdir), err))?;
        let mut modules: Vec<PathBuf> = Vec::new();
        for me in module_entries {
            let me = me.map_err(|err| XtaskError::Io(display_path(&subdir), err))?;
            let p = me.path();
            if !p.is_file() {
                continue;
            }
            let Some(stem) = p.file_stem().and_then(OsStr::to_str) else {
                continue;
            };
            if p.extension().and_then(OsStr::to_str) != Some("py") {
                continue;
            }
            if stem == "__init__" {
                continue;
            }
            modules.push(p);
        }
        modules.sort();

        let mut all_classes: Vec<String> = Vec::new();
        for module in &modules {
            let stem = module
                .file_stem()
                .and_then(OsStr::to_str)
                .unwrap_or_default()
                .to_string();
            let body = fs::read_to_string(module)
                .map_err(|err| XtaskError::Io(display_path(module), err))?;
            let classes = extract_top_level_python_classes(&body);
            if !classes.is_empty() {
                all_classes.extend(classes.iter().cloned());
                module_classes.push((stem, classes));
            }
        }
        all_classes.sort();
        all_classes.dedup();

        // Rewrite the subpackage __init__.py with explicit imports per
        // module and a deterministic __all__. The header is preserved so
        // the spec-drift CI lane's per-file header check still
        // passes.
        let init_path = subdir.join(PYTHON_INIT_FILE);
        let mut body = header.clone();
        body.push('\n');
        body.push_str("from __future__ import annotations\n\n");
        for (module_stem, classes) in &module_classes {
            body.push_str(&format!(
                "from .{module_stem} import {names}\n",
                names = classes.join(", ")
            ));
        }
        body.push('\n');
        body.push_str("__all__ = [\n");
        for name in &all_classes {
            body.push_str(&format!("    \"{name}\",\n"));
        }
        body.push_str("]\n");
        fs::write(&init_path, body).map_err(|err| XtaskError::Io(display_path(&init_path), err))?;

        subpackages.push((name.to_string(), all_classes));
    }
    Ok(subpackages)
}

/// Extract top-level `class Name(...):` declarations from a Python module
/// source. Datamodel-codegen output uses 4-space indentation and never
/// nests classes at the module top level beyond a single colon-suffix
/// declaration line, so a string-prefix scan is sufficient (and avoids
/// adding a Python-AST dependency to xtask).
fn extract_top_level_python_classes(body: &str) -> Vec<String> {
    let mut classes: Vec<String> = Vec::new();
    for line in body.lines() {
        // Must begin in column zero (top-level), with `class ` then the
        // identifier, optionally followed by a parenthesized base list
        // and a trailing colon.
        let Some(rest) = line.strip_prefix("class ") else {
            continue;
        };
        let mut name = String::new();
        for ch in rest.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                name.push(ch);
            } else {
                break;
            }
        }
        if name.is_empty() {
            continue;
        }
        // Skip private (leading-underscore) classes.
        if name.starts_with('_') {
            continue;
        }
        classes.push(name);
    }
    classes.sort();
    classes.dedup();
    classes
}

fn mirror_schema_tree(
    src_root: &Path,
    dst_root: &Path,
    schema_files: &[PathBuf],
) -> Result<(), XtaskError> {
    fs::create_dir_all(dst_root).map_err(|err| XtaskError::Io(display_path(dst_root), err))?;
    for path in schema_files {
        let rel = path.strip_prefix(src_root).map_err(|_| {
            XtaskError::Usage(format!(
                "codegen python: schema file {} is not under {}",
                display_path(path),
                display_path(src_root)
            ))
        })?;
        let dest = dst_root.join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|err| XtaskError::Io(display_path(parent), err))?;
        }
        fs::copy(path, &dest).map_err(|err| XtaskError::Io(display_path(&dest), err))?;
    }
    Ok(())
}

fn invoke_datamodel_codegen(
    input_dir: &Path,
    output_dir: &Path,
    header_path: &Path,
) -> Result<(), XtaskError> {
    let mut cmd = Command::new("uv");
    cmd.arg("tool")
        .arg("run")
        .arg("--from")
        .arg(PYTHON_CODEGEN_TOOL_PIN)
        .arg("datamodel-codegen")
        .arg("--input")
        .arg(input_dir)
        .arg("--input-file-type")
        .arg("jsonschema")
        .arg("--output")
        .arg(output_dir)
        .arg("--output-model-type")
        .arg("pydantic_v2.BaseModel")
        .arg("--target-python-version")
        .arg("3.11")
        .arg("--use-double-quotes")
        .arg("--use-standard-collections")
        .arg("--use-union-operator")
        .arg("--use-schema-description")
        .arg("--disable-timestamp")
        .arg("--custom-file-header-path")
        .arg(header_path);

    let output = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            XtaskError::ToolMissing(format!(
                "`uv` not found on PATH; install via https://docs.astral.sh/uv/ then rerun (underlying error: {err})"
            ))
        } else {
            XtaskError::Io("uv tool run datamodel-codegen".to_string(), err)
        }
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(XtaskError::ToolFailed(format!(
            "datamodel-codegen exited {}\nstdout: {}\nstderr: {}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )));
    }
    Ok(())
}

fn hash_schema_set(workspace_root: &Path, schema_files: &[PathBuf]) -> Result<String, XtaskError> {
    let mut hasher = Sha256::new();
    for path in schema_files {
        let rel = path.strip_prefix(workspace_root).map_err(|_| {
            XtaskError::Usage(format!(
                "codegen python: schema file {} is not under workspace root",
                display_path(path)
            ))
        })?;
        let rel_str = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        hasher.update(rel_str.as_bytes());
        hasher.update(b"\n");
        let bytes = fs::read(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
        hasher.update(&bytes);
        hasher.update(b"\n");
    }
    Ok(digest_to_hex(&hasher.finalize()))
}

fn count_python_files(dir: &Path) -> Result<usize, XtaskError> {
    let mut count = 0usize;
    walk_python_files(dir, &mut count)?;
    Ok(count)
}

fn walk_python_files(dir: &Path, count: &mut usize) -> Result<(), XtaskError> {
    if !dir.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if file_type.is_dir() {
            walk_python_files(&path, count)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext == "py" {
                    *count += 1;
                }
            }
        }
    }
    Ok(())
}

fn diff_python_trees(expected: &Path, actual: &Path) -> Result<Option<String>, XtaskError> {
    if !actual.exists() {
        return Ok(Some(format!(
            "  on-disk dir {} is missing entirely",
            display_path(actual)
        )));
    }
    let mut expected_files: Vec<PathBuf> = Vec::new();
    let mut actual_files: Vec<PathBuf> = Vec::new();
    collect_relative_files(expected, expected, &mut expected_files)?;
    collect_relative_files(actual, actual, &mut actual_files)?;
    expected_files.sort();
    actual_files.sort();

    let mut diff_lines: Vec<String> = Vec::new();
    let limit = 12usize;
    let mut differing = 0usize;

    let exp_set: std::collections::BTreeSet<_> = expected_files.iter().cloned().collect();
    let act_set: std::collections::BTreeSet<_> = actual_files.iter().cloned().collect();
    for missing in exp_set.difference(&act_set) {
        differing += 1;
        if diff_lines.len() < limit {
            diff_lines.push(format!("  + missing on disk: {}", missing.display()));
        }
    }
    for extra in act_set.difference(&exp_set) {
        differing += 1;
        if diff_lines.len() < limit {
            diff_lines.push(format!(
                "  - present on disk but not regenerated: {}",
                extra.display()
            ));
        }
    }
    for rel in exp_set.intersection(&act_set) {
        let exp_bytes = fs::read(expected.join(rel))
            .map_err(|err| XtaskError::Io(display_path(&expected.join(rel)), err))?;
        let act_bytes = fs::read(actual.join(rel))
            .map_err(|err| XtaskError::Io(display_path(&actual.join(rel)), err))?;
        if exp_bytes != act_bytes {
            differing += 1;
            if diff_lines.len() < limit {
                diff_lines.push(format!(
                    "  ! bytes differ: {} (expected {} bytes, on-disk {} bytes)",
                    rel.display(),
                    exp_bytes.len(),
                    act_bytes.len()
                ));
            }
        }
    }

    if differing == 0 {
        return Ok(None);
    }
    let mut summary = diff_lines.join("\n");
    if differing > limit {
        summary.push_str(&format!(
            "\n  ... ({} more differing entries)",
            differing - limit
        ));
    }
    Ok(Some(summary))
}

fn collect_relative_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), XtaskError> {
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if name == "__pycache__" {
            continue;
        }
        if file_type.is_dir() {
            collect_relative_files(root, &path, out)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext == "pyc" || ext == "pyo" {
                    continue;
                }
            }
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_path_buf());
            }
        }
    }
    Ok(())
}
