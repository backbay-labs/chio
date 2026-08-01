//! Content-hash guard for manual Rust-to-model mirror entries.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Component, Path};

use proc_macro2::{Delimiter, Group, TokenStream, TokenTree};
use quote::ToTokens;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use syn::{ImplItem, Item, Type};
use toml_edit::{DocumentMut, Item as TomlItem, Value as TomlValue};

use crate::{workspace_root, XtaskError};

const MANIFEST_PATH: &str = "formal/proof-manifest.toml";
const MANIFEST_SCHEMA: &str = "chio.proof-manifest.v1";

#[derive(Debug, Deserialize)]
struct ProofManifest {
    schema: String,
    #[serde(default)]
    mirror: Vec<MirrorEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct MirrorEntry {
    model_file: String,
    model_kind: ModelKind,
    relationship: MirrorRelationship,
    rust_source: String,
    rust_symbols: Vec<String>,
    normalized_sha256: String,
    symbol_sha256: Vec<RecordedSymbolDigest>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ModelKind {
    Lean,
    Tla,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MirrorRelationship {
    Transliteration,
    AbstractionAnchor,
}

#[derive(Clone, Debug, Deserialize)]
struct RecordedSymbolDigest {
    symbol: String,
    sha256: String,
}

#[derive(Clone, Debug)]
struct ComputedMirror {
    normalized_sha256: String,
    symbols: Vec<ComputedSymbolDigest>,
}

#[derive(Clone, Debug)]
struct ComputedSymbolDigest {
    symbol: String,
    sha256: String,
}

pub(crate) fn run(bless: bool) -> Result<(), XtaskError> {
    let root = workspace_root()?;
    let manifest_path = root.join(MANIFEST_PATH);
    let raw = fs::read_to_string(&manifest_path)
        .map_err(|error| XtaskError::Io(MANIFEST_PATH.to_string(), error))?;
    let entries = parse_manifest(&raw).map_err(XtaskError::FormalMirrors)?;
    validate_entries(&entries, &root).map_err(XtaskError::FormalMirrors)?;

    let mut computed = Vec::with_capacity(entries.len());
    for entry in &entries {
        computed.push(compute_entry(entry, &root).map_err(XtaskError::FormalMirrors)?);
    }

    if bless {
        let (updated, changed) =
            bless_manifest(&raw, &entries, &computed).map_err(XtaskError::FormalMirrors)?;
        if updated != raw {
            fs::write(&manifest_path, updated)
                .map_err(|error| XtaskError::Io(MANIFEST_PATH.to_string(), error))?;
        }
        println!(
            "formal-mirrors: blessed {changed} of {} mirror entries",
            entries.len()
        );
        return Ok(());
    }

    check_entries(&entries, &computed).map_err(XtaskError::FormalMirrors)?;
    println!("formal-mirrors: {} mirror entries match", entries.len());
    Ok(())
}

fn parse_manifest(raw: &str) -> Result<Vec<MirrorEntry>, String> {
    let manifest: ProofManifest =
        toml::from_str(raw).map_err(|error| format!("cannot parse {MANIFEST_PATH}: {error}"))?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(format!(
            "unsupported proof manifest schema: {}",
            manifest.schema
        ));
    }
    if manifest.mirror.is_empty() {
        return Err("proof manifest contains no mirror entries".to_string());
    }
    Ok(manifest.mirror)
}

fn validate_entries(entries: &[MirrorEntry], root: &Path) -> Result<(), String> {
    let mut pairs = BTreeSet::new();
    for entry in entries {
        let (model_prefixes, model_extension) = match entry.model_kind {
            ModelKind::Lean => (&["formal/lean4"][..], "lean"),
            ModelKind::Tla => (&["formal/tla", "formal/apalache"][..], "tla"),
        };
        validate_model_path(&entry.model_file, model_prefixes, model_extension)?;
        validate_relationship(entry)?;
        validate_relative_path(&entry.rust_source, "crates", "rust_source")?;
        if Path::new(&entry.rust_source)
            .extension()
            .and_then(|value| value.to_str())
            != Some("rs")
        {
            return Err(format!(
                "rust_source must end in .rs: {}",
                entry.rust_source
            ));
        }
        if !root.join(&entry.model_file).is_file() {
            return Err(format!("model file not found: {}", entry.model_file));
        }
        if !root.join(&entry.rust_source).is_file() {
            return Err(format!("Rust source not found: {}", entry.rust_source));
        }
        if !pairs.insert((entry.model_file.clone(), entry.rust_source.clone())) {
            return Err(format!(
                "duplicate mirror pair: {} and {}",
                entry.model_file, entry.rust_source
            ));
        }
        if entry.rust_symbols.is_empty() {
            return Err(format!(
                "mirror entry has no Rust symbols: {}",
                entry.rust_source
            ));
        }
        let mut symbols = HashSet::new();
        for symbol in &entry.rust_symbols {
            if symbol.is_empty() || !symbols.insert(symbol.as_str()) {
                return Err(format!(
                    "empty or duplicate Rust symbol in {}: {symbol}",
                    entry.rust_source
                ));
            }
        }
        let recorded_names: Vec<&str> = entry
            .symbol_sha256
            .iter()
            .map(|digest| digest.symbol.as_str())
            .collect();
        let expected_names: Vec<&str> = entry.rust_symbols.iter().map(String::as_str).collect();
        if recorded_names != expected_names {
            return Err(format!(
                "symbol_sha256 must match rust_symbols in order for {}",
                entry.rust_source
            ));
        }
    }
    Ok(())
}

fn validate_relationship(entry: &MirrorEntry) -> Result<(), String> {
    match (entry.model_kind, entry.relationship) {
        (ModelKind::Lean, MirrorRelationship::Transliteration)
        | (ModelKind::Lean, MirrorRelationship::AbstractionAnchor)
        | (ModelKind::Tla, MirrorRelationship::AbstractionAnchor) => Ok(()),
        _ => Err(format!(
            "model_kind and relationship disagree for {}",
            entry.model_file
        )),
    }
}

fn validate_model_path(path: &str, prefixes: &[&str], extension: &str) -> Result<(), String> {
    if !prefixes
        .iter()
        .any(|prefix| validate_relative_path(path, prefix, "model_file").is_ok())
    {
        return Err(format!(
            "model_file must be a normalized path under {}: {path}",
            prefixes.join(" or ")
        ));
    }
    if Path::new(path).extension().and_then(|value| value.to_str()) != Some(extension) {
        return Err(format!("model_file must end in .{extension}: {path}"));
    }
    Ok(())
}

fn validate_relative_path(path: &str, prefix: &str, field: &str) -> Result<(), String> {
    let candidate = Path::new(path);
    if candidate.is_absolute()
        || candidate
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || !candidate.starts_with(prefix)
    {
        return Err(format!(
            "{field} must be a normalized {prefix}/ path: {path}"
        ));
    }
    Ok(())
}

fn compute_entry(entry: &MirrorEntry, root: &Path) -> Result<ComputedMirror, String> {
    let source = fs::read_to_string(root.join(&entry.rust_source))
        .map_err(|error| format!("cannot read {}: {error}", entry.rust_source))?;
    compute_from_source(entry, &source).map_err(|error| format!("{error} in {}", entry.rust_source))
}

fn compute_from_source(entry: &MirrorEntry, source: &str) -> Result<ComputedMirror, String> {
    let file = syn::parse_file(source).map_err(|error| format!("Rust parse failed: {error}"))?;
    let mut rollup = Sha256::new();
    let mut symbols = Vec::with_capacity(entry.rust_symbols.len());
    for symbol in &entry.rust_symbols {
        let normalized = normalize_symbol(&file, symbol)?;
        rollup.update((normalized.len() as u64).to_be_bytes());
        rollup.update(normalized.as_bytes());
        symbols.push(ComputedSymbolDigest {
            symbol: symbol.clone(),
            sha256: sha256_hex(normalized.as_bytes()),
        });
    }
    let rollup_digest = rollup.finalize();
    Ok(ComputedMirror {
        normalized_sha256: digest_hex(&rollup_digest),
        symbols,
    })
}

fn normalize_symbol(file: &syn::File, symbol: &str) -> Result<String, String> {
    let mut matches = Vec::new();
    if let Some((type_path, method_name)) = symbol.rsplit_once("::") {
        let Some(type_name) = type_path.rsplit("::").next() else {
            return Err(format!("invalid method symbol: {symbol}"));
        };
        if type_name.is_empty() || method_name.is_empty() {
            return Err(format!("invalid method symbol: {symbol}"));
        }
        for item in &file.items {
            let Item::Impl(item_impl) = item else {
                continue;
            };
            if !matches!(impl_type_name(&item_impl.self_ty), Some(name) if name == type_name) {
                continue;
            }
            for impl_item in &item_impl.items {
                if let ImplItem::Fn(method) = impl_item {
                    if method.sig.ident == method_name {
                        let mut selected_impl = item_impl.clone();
                        selected_impl.items = vec![ImplItem::Fn(method.clone())];
                        matches.push(selected_impl.to_token_stream());
                    }
                }
            }
        }
    } else {
        for item in &file.items {
            if matches!(item_name(item), Some(name) if name == symbol) {
                matches.push(item.to_token_stream());
            }
        }
    }

    match matches.len() {
        0 => Err(format!("symbol not found: {symbol}")),
        1 => {
            let Some(tokens) = matches.pop() else {
                return Err(format!("symbol not found: {symbol}"));
            };
            Ok(strip_doc_attributes(tokens).to_string())
        }
        count => Err(format!("ambiguous symbol: {symbol} ({count} matches)")),
    }
}

fn impl_type_name(ty: &Type) -> Option<&syn::Ident> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    type_path.path.segments.last().map(|segment| &segment.ident)
}

fn item_name(item: &Item) -> Option<&syn::Ident> {
    match item {
        Item::Const(value) => Some(&value.ident),
        Item::Enum(value) => Some(&value.ident),
        Item::Fn(value) => Some(&value.sig.ident),
        Item::Static(value) => Some(&value.ident),
        Item::Struct(value) => Some(&value.ident),
        Item::Trait(value) => Some(&value.ident),
        Item::TraitAlias(value) => Some(&value.ident),
        Item::Type(value) => Some(&value.ident),
        Item::Union(value) => Some(&value.ident),
        _ => None,
    }
}

fn strip_doc_attributes(stream: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    let mut output = TokenStream::new();
    let mut index = 0usize;
    while index < tokens.len() {
        if let Some(width) = doc_attribute_width(&tokens, index) {
            index += width;
            continue;
        }
        let token = match &tokens[index] {
            TokenTree::Group(group) => {
                let mut normalized =
                    Group::new(group.delimiter(), strip_doc_attributes(group.stream()));
                normalized.set_span(group.span());
                TokenTree::Group(normalized)
            }
            token => token.clone(),
        };
        output.extend([token]);
        index += 1;
    }
    output
}

fn doc_attribute_width(tokens: &[TokenTree], index: usize) -> Option<usize> {
    if !matches!(tokens.get(index), Some(TokenTree::Punct(value)) if value.as_char() == '#') {
        return None;
    }
    let mut group_index = index + 1;
    if matches!(tokens.get(group_index), Some(TokenTree::Punct(value)) if value.as_char() == '!') {
        group_index += 1;
    }
    let Some(TokenTree::Group(group)) = tokens.get(group_index) else {
        return None;
    };
    if group.delimiter() != Delimiter::Bracket {
        return None;
    }
    let mut inner = group.stream().into_iter();
    if matches!(inner.next(), Some(TokenTree::Ident(ident)) if ident == "doc") {
        Some(group_index - index + 1)
    } else {
        None
    }
}

fn check_entries(entries: &[MirrorEntry], computed: &[ComputedMirror]) -> Result<(), String> {
    if entries.len() != computed.len() {
        return Err("internal mirror computation count mismatch".to_string());
    }
    let mut drift = Vec::new();
    for (entry, current) in entries.iter().zip(computed) {
        if !valid_sha256(&entry.normalized_sha256) {
            return Err(format!(
                "invalid normalized_sha256 for {}",
                entry.rust_source
            ));
        }
        let mut changed_symbols = Vec::new();
        for (recorded, actual) in entry.symbol_sha256.iter().zip(&current.symbols) {
            if !valid_sha256(&recorded.sha256) {
                return Err(format!(
                    "invalid symbol sha256 for {} in {}",
                    recorded.symbol, entry.rust_source
                ));
            }
            if recorded.sha256 != actual.sha256 {
                changed_symbols.push(actual.symbol.as_str());
            }
        }
        if entry.normalized_sha256 != current.normalized_sha256 || !changed_symbols.is_empty() {
            drift.push(drift_message(entry, &changed_symbols));
        }
    }
    if drift.is_empty() {
        Ok(())
    } else {
        Err(drift.join("\n\n"))
    }
}

fn drift_message(entry: &MirrorEntry, changed_symbols: &[&str]) -> String {
    let model_label = match entry.model_kind {
        ModelKind::Lean => "lean mirror",
        ModelKind::Tla => "tla model",
    };
    let mut message = format!(
        "MIRROR DRIFT in {}\n  {model_label}:     {}",
        entry.rust_source, entry.model_file
    );
    if changed_symbols.is_empty() {
        message.push_str("\n  changed symbol:  rollup hash does not match symbol hashes");
    } else {
        for symbol in changed_symbols {
            message.push_str(&format!("\n  changed symbol:  {symbol}"));
        }
    }
    match entry.relationship {
        MirrorRelationship::Transliteration => message.push_str(
            "\n  This Rust symbol is hand-transliterated into the Lean model above.\n  1. Review the Lean mirror and update it if the semantics changed.",
        ),
        MirrorRelationship::AbstractionAnchor => message.push_str(
            "\n  This Rust symbol is an implementation anchor for the model above.\n  1. Review the model abstraction and update it if the contract changed.\n  A matching hash does not claim that Rust enforces the modeled property.",
        ),
    }
    message.push_str(
        "\n  2. Run: cargo xtask check formal-mirrors --bless\n  3. Commit the proof-manifest.toml diff with the Rust change.\n  This gate records review; it does not prove semantic equivalence.",
    );
    message
}

fn bless_manifest(
    raw: &str,
    entries: &[MirrorEntry],
    computed: &[ComputedMirror],
) -> Result<(String, usize), String> {
    if entries.len() != computed.len() {
        return Err("internal mirror computation count mismatch".to_string());
    }
    let mut document = raw
        .parse::<DocumentMut>()
        .map_err(|error| format!("cannot edit {MANIFEST_PATH}: {error}"))?;
    let mirrors = document
        .get_mut("mirror")
        .and_then(TomlItem::as_array_of_tables_mut)
        .ok_or_else(|| "proof manifest mirror table is missing".to_string())?;
    if mirrors.len() != computed.len() {
        return Err("proof manifest mirror table count changed during parse".to_string());
    }

    let mut changed = 0usize;
    for ((table, entry), current) in mirrors.iter_mut().zip(entries).zip(computed) {
        let entry_changed = entry.normalized_sha256 != current.normalized_sha256
            || entry
                .symbol_sha256
                .iter()
                .zip(&current.symbols)
                .any(|(recorded, actual)| recorded.sha256 != actual.sha256);
        if entry_changed {
            changed += 1;
        }
        table["normalized_sha256"] = toml_edit::value(current.normalized_sha256.clone());
        let symbol_values = table
            .get_mut("symbol_sha256")
            .and_then(TomlItem::as_value_mut)
            .and_then(TomlValue::as_array_mut)
            .ok_or_else(|| format!("symbol_sha256 must be an array for {}", entry.rust_source))?;
        if symbol_values.len() != current.symbols.len() {
            return Err(format!(
                "symbol_sha256 count mismatch for {}",
                entry.rust_source
            ));
        }
        for (value, actual) in symbol_values.iter_mut().zip(&current.symbols) {
            let digest = value.as_inline_table_mut().ok_or_else(|| {
                format!(
                    "symbol_sha256 entries must be inline tables for {}",
                    entry.rust_source
                )
            })?;
            digest.insert("sha256", TomlValue::from(actual.sha256.clone()));
        }
    }
    Ok((document.to_string(), changed))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest_hex(&digest)
}

fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
fn hash_symbol(source: &str, symbol: &str) -> Result<String, String> {
    let file = syn::parse_file(source).map_err(|error| format!("Rust parse failed: {error}"))?;
    normalize_symbol(&file, symbol).map(|normalized| sha256_hex(normalized.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{
        bless_manifest, check_entries, compute_from_source, hash_symbol, validate_relationship,
        MirrorEntry, MirrorRelationship, ModelKind, RecordedSymbolDigest,
    };

    const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn hash(source: &str, symbol: &str) -> String {
        match hash_symbol(source, symbol) {
            Ok(value) => value,
            Err(error) => panic!("failed to hash {symbol}: {error}"),
        }
    }

    fn entry(symbols: &[&str]) -> MirrorEntry {
        MirrorEntry {
            model_file: "formal/lean4/Chio/Chio/Core/Scope.lean".to_string(),
            model_kind: ModelKind::Lean,
            relationship: MirrorRelationship::Transliteration,
            rust_source: "crates/core/chio-core-types/src/capability/scope.rs".to_string(),
            rust_symbols: symbols.iter().map(|value| (*value).to_string()).collect(),
            normalized_sha256: ZERO_HASH.to_string(),
            symbol_sha256: symbols
                .iter()
                .map(|symbol| RecordedSymbolDigest {
                    symbol: (*symbol).to_string(),
                    sha256: ZERO_HASH.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn model_kind_and_relationship_must_agree() {
        let mut mirror = entry(&["allows"]);
        mirror.model_file = "formal/apalache/ReceiptBeforeAllow.tla".to_string();
        mirror.model_kind = ModelKind::Tla;
        mirror.relationship = MirrorRelationship::Transliteration;

        let error = match validate_relationship(&mirror) {
            Ok(()) => panic!("invalid model relationship unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("model_kind and relationship disagree"));
    }

    #[test]
    fn lean_abstraction_anchor_is_explicitly_supported() {
        let mut mirror = entry(&["allows"]);
        mirror.relationship = MirrorRelationship::AbstractionAnchor;

        assert!(validate_relationship(&mirror).is_ok());
    }

    #[test]
    fn doc_comment_edit_does_not_change_hash() {
        let before = r#"
            struct Token { enabled: bool }
            impl Token {
                /// Earlier wording.
                pub fn valid(&self) -> bool { self.enabled }
            }
        "#;
        let after = r#"
            struct Token { enabled: bool }
            impl Token {
                /// Revised wording with more detail.
                pub fn valid(&self) -> bool { self.enabled }
            }
        "#;

        assert_eq!(hash(before, "Token::valid"), hash(after, "Token::valid"));
    }

    #[test]
    fn nested_doc_comment_edit_does_not_change_hash() {
        let before = r#"
            /// Token state.
            struct Token {
                /// Earlier field wording.
                enabled: bool,
            }
        "#;
        let after = r#"
            /// Revised token state wording.
            struct Token {
                /// Revised field wording.
                enabled: bool,
            }
        "#;

        assert_eq!(hash(before, "Token"), hash(after, "Token"));
    }

    #[test]
    fn whitespace_and_regular_comments_do_not_change_hash() {
        let before = "fn allows() -> bool { /* explanation */ true }";
        let after = "fn allows()->bool{true}";

        assert_eq!(hash(before, "allows"), hash(after, "allows"));
    }

    #[test]
    fn body_token_edit_changes_hash() {
        let before = "fn allows() -> bool { true }";
        let after = "fn allows() -> bool { false }";

        assert_ne!(hash(before, "allows"), hash(after, "allows"));
    }

    #[test]
    fn non_doc_attribute_edit_changes_hash() {
        let before = "#[inline] fn allows() -> bool { true }";
        let after = "#[cold] fn allows() -> bool { true }";

        assert_ne!(hash(before, "allows"), hash(after, "allows"));
    }

    #[test]
    fn same_method_name_on_different_types_resolves_by_self_type() {
        let source = r#"
            struct Parent;
            struct Child;
            impl Parent { fn valid(&self) -> bool { true } }
            impl Child { fn valid(&self) -> bool { false } }
        "#;

        assert_ne!(hash(source, "Parent::valid"), hash(source, "Child::valid"));
    }

    #[test]
    fn impl_header_edit_changes_method_hash() {
        let trait_impl = r#"
            struct Token;
            trait Valid { fn valid(&self) -> bool; }
            impl Valid for Token { fn valid(&self) -> bool { true } }
        "#;
        let inherent_impl = r#"
            struct Token;
            impl Token { fn valid(&self) -> bool { true } }
        "#;

        assert_ne!(
            hash(trait_impl, "Token::valid"),
            hash(inherent_impl, "Token::valid")
        );
    }

    #[test]
    fn ambiguous_method_is_rejected() {
        let source = r#"
            struct Token { enabled: bool }
            trait Valid { fn valid(&self) -> bool; }
            impl Token { fn valid(&self) -> bool { self.enabled } }
            impl Valid for Token { fn valid(&self) -> bool { self.enabled } }
        "#;

        let error = match hash_symbol(source, "Token::valid") {
            Ok(_) => panic!("ambiguous method unexpectedly resolved"),
            Err(error) => error,
        };
        assert!(error.contains("ambiguous symbol: Token::valid"));
    }

    #[test]
    fn missing_symbol_is_rejected() {
        let error = match hash_symbol("fn present() {}", "missing") {
            Ok(_) => panic!("missing symbol unexpectedly resolved"),
            Err(error) => error,
        };
        assert_eq!(error, "symbol not found: missing");
    }

    #[test]
    fn drift_message_names_symbol_mirror_and_bless_command() {
        let mut mirror = entry(&["allows"]);
        let before = match compute_from_source(&mirror, "fn allows() -> bool { true }") {
            Ok(value) => value,
            Err(error) => panic!("baseline computation failed: {error}"),
        };
        mirror.normalized_sha256 = before.normalized_sha256;
        mirror.symbol_sha256[0].sha256 = before.symbols[0].sha256.clone();
        let after = match compute_from_source(&mirror, "fn allows() -> bool { false }") {
            Ok(value) => value,
            Err(error) => panic!("changed computation failed: {error}"),
        };

        let error = match check_entries(&[mirror], &[after]) {
            Ok(()) => panic!("changed body unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("changed symbol:  allows"));
        assert!(error.contains("formal/lean4/Chio/Chio/Core/Scope.lean"));
        assert!(error.contains("cargo xtask check formal-mirrors --bless"));
    }

    #[test]
    fn tla_drift_message_marks_the_entry_as_an_abstraction_anchor() {
        let mut mirror = entry(&["allows"]);
        mirror.model_file = "formal/apalache/ReceiptBeforeAllow.tla".to_string();
        mirror.model_kind = ModelKind::Tla;
        mirror.relationship = MirrorRelationship::AbstractionAnchor;
        let current = match compute_from_source(&mirror, "fn allows() -> bool { true }") {
            Ok(value) => value,
            Err(error) => panic!("computation failed: {error}"),
        };

        let error = match check_entries(&[mirror], &[current]) {
            Ok(()) => panic!("unblessed TLA anchor unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("tla model:     formal/apalache/ReceiptBeforeAllow.tla"));
        assert!(error.contains("implementation anchor"));
        assert!(error.contains("does not claim that Rust enforces the modeled property"));
    }

    #[test]
    fn rollup_hash_depends_on_symbol_order() {
        let source = "fn first() -> bool { true } fn second() -> bool { false }";
        let forward = entry(&["first", "second"]);
        let reverse = entry(&["second", "first"]);
        let forward_hash = match compute_from_source(&forward, source) {
            Ok(value) => value.normalized_sha256,
            Err(error) => panic!("forward computation failed: {error}"),
        };
        let reverse_hash = match compute_from_source(&reverse, source) {
            Ok(value) => value.normalized_sha256,
            Err(error) => panic!("reverse computation failed: {error}"),
        };

        assert_ne!(forward_hash, reverse_hash);
    }

    #[test]
    fn bless_changes_only_hash_values() {
        let mirror = entry(&["allows"]);
        let computed = match compute_from_source(&mirror, "fn allows() -> bool { true }") {
            Ok(value) => value,
            Err(error) => panic!("computation failed: {error}"),
        };
        let raw = format!(
            "schema = \"chio.proof-manifest.v1\"\nnotes = [\"keep formatting\"]\n\n[[mirror]]\nmodel_file = \"{}\"\nmodel_kind = \"lean\"\nrelationship = \"transliteration\"\nrust_source = \"{}\"\nrust_symbols = [\"allows\"]\nnormalized_sha256 = \"{ZERO_HASH}\"\nsymbol_sha256 = [\n  {{ symbol = \"allows\", sha256 = \"{ZERO_HASH}\" }},\n]\n",
            mirror.model_file, mirror.rust_source
        );
        let (updated, changed) =
            match bless_manifest(&raw, &[mirror], std::slice::from_ref(&computed)) {
                Ok(result) => result,
                Err(error) => panic!("bless failed: {error}"),
            };
        assert_eq!(changed, 1);
        let redacted_before = raw.replace(ZERO_HASH, "<hash>");
        let redacted_after = updated
            .replace(&computed.normalized_sha256, "<hash>")
            .replace(&computed.symbols[0].sha256, "<hash>");
        assert_eq!(redacted_before, redacted_after);
    }
}
