# Finding Artifact Family (M0 + M1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the `chio-finding` crate (the signed `chio.finding.v1` artifact with fail-closed validation, inline signing, and a golden fixture) and register that ONE schema id, with zero kernel or market wiring. Challenge and status-feed artifacts are deliberately deferred to M5/M6 (review finding: registering wire schemas ahead of their owning milestones is speculative public surface, and the status root must carry the oracle's exact `SignedEpochRoot` rather than a divergent copy - `chio-revocation-oracle/src/epoch.rs:12`).

**Architecture:** New leaf crate `crates/economy/chio-finding` mirroring the `chio-listing` style (pure types + validation, no storage, no I/O), plus additive registration rows in `chio-core-types::signed_artifact` and `spec/schemas/`. Field semantics come from `docs/research/cognition-market/ARCHITECTURE.md` section 4; decisions from ADR-0017.

**Tech Stack:** Rust (workspace MSRV 1.93), serde + canonical JSON via `chio-core-types`, Ed25519 via `chio_core_types::crypto`, thiserror.

## Global Constraints

- No em dashes (U+2014) anywhere in code, comments, or docs (CLAUDE.md).
- Clippy `unwrap_used = "deny"`, `expect_used = "deny"` workspace-wide; integration tests may follow sibling-test idiom but prefer avoiding unwrap.
- Fail-closed: every validator rejects on any missing/malformed field; unknown JSON fields rejected (`deny_unknown_fields` on all new artifact structs).
- Canonical JSON (RFC 8785) for all signed payloads (comes free via `chio_core_types::canonical_json_bytes` and `Keypair::sign_canonical`).
- Conventional commits.
- Verification gate before declaring done: `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`.
- New enum variants on EXISTING frozen wire enums are forbidden (repo evolution rule); this plan only adds new schemas and new types.

## File Structure

- `crates/economy/chio-finding/Cargo.toml` - crate manifest (deps: chio-core-types, serde, thiserror).
- `crates/economy/chio-finding/src/lib.rs` - module wiring + re-exports.
- `crates/economy/chio-finding/src/types.rs` - `Finding`, `FindingDescriptor`, enums, the `chio.finding.v1` schema const (inline signature; no envelope alias).
- `crates/economy/chio-finding/src/validate.rs` - fail-closed validators, `compute_finding_id`, inline signing.
- `crates/economy/chio-finding/tests/finding.rs` - integration tests + golden-fixture test.
- `fixtures/proof-room/finding/verified-fix-basic/finding.json` - golden.
- `Cargo.toml` (workspace root) - members entry.
- `crates/core/chio-core-types/src/signed_artifact.rs` - 1 const + 1 SPECS row.
- `spec/schemas/chio-finding/v1/finding.schema.json` - validation schema.
- `spec/schemas/registry.json` - 1 row.
- `docs/adr/ADR-0017-cognition-market-finding-artifacts.md` - amendment verification only (the amendments were applied during PR #1025 review).

---

### Task 1: Crate scaffold

**Files:**
- Create: `crates/economy/chio-finding/Cargo.toml`
- Create: `crates/economy/chio-finding/src/lib.rs`
- Modify: `Cargo.toml` (workspace root, `members` list)

**Interfaces:**
- Consumes: workspace dependency table (`chio-core-types`, `serde`, `thiserror` must exist there; verify in step 1).
- Produces: an empty compiling crate `chio_finding` that later tasks fill.

- [ ] **Step 1: Confirm workspace deps exist**

Run: `grep -n "^chio-core-types\|^serde \|^thiserror" Cargo.toml | head`
Expected: rows for all three in `[workspace.dependencies]`. If `thiserror` is absent, add it there as `thiserror = "1"` in the same style as neighbors.

- [ ] **Step 2: Write the manifest**

```toml
[package]
name = "chio-finding"
description = "Chio cognition-market finding artifact"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
publish = false

[lib]
name = "chio_finding"

[dependencies]
chio-core-types = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }

[lints]
workspace = true
```

- [ ] **Step 3: Write minimal lib.rs**

```rust
//! Cognition-market finding artifacts for the Chio protocol.
//!
//! The signed information-good artifact (`chio.finding.v1`) with
//! fail-closed pure validation and inline signing. Challenge and
//! status-feed artifacts land with their owning milestones (M5/M6).
//! Design: docs/research/cognition-market/ARCHITECTURE.md section 4 and
//! ADR-0017. No storage, no I/O, no kernel wiring.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical_json_bytes, crypto};

mod types;
mod validate;

pub use types::*;
pub use validate::*;
```

- [ ] **Step 4: Register workspace member**

In root `Cargo.toml`, add `"crates/economy/chio-finding",` to `members` in the alphabetical position among the other `crates/economy/` entries.

- [ ] **Step 5: Verify it compiles**

Run: `cargo check -p chio-finding`
Expected: success (empty modules; if `mod types;`/`mod validate;` fail because files are missing, create both files containing only `// filled by later tasks` - then re-run).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/economy/chio-finding
git commit -m "feat(chio-finding): scaffold cognition-market artifact crate"
```

---

### Task 2: Finding types and fail-closed validation

**Files:**
- Modify: `crates/economy/chio-finding/src/types.rs`
- Modify: `crates/economy/chio-finding/src/validate.rs`
- Create: `crates/economy/chio-finding/tests/finding.rs`

**Interfaces:**
- Consumes: `chio_core_types::capability::scope::MonetaryAmount` (`{ units: u64, currency: String }`); `chio_core_types::crypto::{Keypair, PublicKey}` (PublicKey serializes as a 64-hex string, `crypto.rs:313-319`, and derives Eq); `canonical_json_bytes` (`Result<Vec<u8>>`, `canonical.rs:119`); `sha256_hex` (`crypto.rs:1197`).
- Produces (later tasks and milestones rely on these exact names):
  - `FINDING_SCHEMA_V1: &str = "chio.finding.v1"`
  - `enum FindingOutcomeClass { NullResult, VerifiedFix, PositiveResult }`
  - `enum FindingGuaranteeClass { DeterministicReplay, MeteredAttested, Asserted }`
  - `enum FindingEvidenceClass { Asserted, Observed, Verified }`
  - `struct FindingDescriptor { topic, context_sha256, outcome_class }`
  - `struct Finding { .. }` with `issuer: PublicKey` (fields exactly as coded below)
  - `enum FindingError` (all variants defined here, including `Signing` and `SignatureInvalid` used by Task 3)
  - `Finding::validate(&self) -> Result<(), FindingError>` - full structural validation INCLUDING id integrity (empty or stale `finding_id` rejects; review finding: publish paths must not accept a non-content-addressed id)
  - `compute_finding_id(&Finding) -> Result<String, FindingError>` and `Finding::verify_finding_id(&self)`

- [ ] **Step 1: Write the failing tests**

Put in `crates/economy/chio-finding/tests/finding.rs`:

```rust
//! Integration coverage for the finding artifact family.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_finding::{
    compute_finding_id,
    crypto::{Keypair, PublicKey},
    Finding, FindingDescriptor, FindingError, FindingEvidenceClass, FindingGuaranteeClass,
    FindingOutcomeClass, FINDING_SCHEMA_V1,
};

fn hex64(fill: char) -> String {
    std::iter::repeat_n(fill, 64).collect()
}

/// Draft with an EMPTY finding_id; not yet valid.
fn draft_finding_with_issuer(issuer: PublicKey) -> Finding {
    Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#test-failure".to_string(),
            context_sha256: hex64('a'),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: hex64('b'),
        payload_media_type: "text/x-diff".to_string(),
        evidence_receipt_ids: vec!["r-1".to_string()],
        evidence_checkpoint_ref: "ckpt-1".to_string(),
        evidence_cost: MonetaryAmount {
            units: 4_200,
            currency: "USD".to_string(),
        },
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Verified,
        replay_recipe_sha256: Some(hex64('c')),
        intent_commitment_receipt_id: None,
        bond_ref: "bond-req-1".to_string(),
        status_feed_ref: "finding-status/test".to_string(),
        license_ref: None,
        price_hint_ref: None,
        issuer,
        issued_at: 1_784_880_000,
        expires_at: 1_792_656_000,
        signature: String::new(),
    }
}

/// Fully constructed finding: draft plus its content-addressed id.
fn base_finding(issuer: &Keypair) -> Finding {
    let mut finding = draft_finding_with_issuer(issuer.public_key());
    finding.finding_id = compute_finding_id(&finding).unwrap_or_default();
    finding
}

#[test]
fn valid_finding_passes_validation() {
    let issuer = Keypair::generate();
    assert!(base_finding(&issuer).validate().is_ok());
}

#[test]
fn wrong_schema_is_rejected() {
    let issuer = Keypair::generate();
    let mut finding = base_finding(&issuer);
    finding.schema = "chio.finding.v999".to_string();
    assert!(matches!(
        finding.validate(),
        Err(FindingError::UnsupportedSchema(_))
    ));
}

#[test]
fn empty_finding_id_is_rejected() {
    let issuer = Keypair::generate();
    let draft = draft_finding_with_issuer(issuer.public_key());
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MalformedDigest("finding_id"))
    ));
}

#[test]
fn stale_finding_id_is_rejected() {
    let issuer = Keypair::generate();
    let mut finding = base_finding(&issuer);
    finding.descriptor.topic = "repo:backbay/chio#other-topic".to_string();
    assert!(matches!(
        finding.validate(),
        Err(FindingError::MalformedDigest("finding_id"))
    ));
}

#[test]
fn malformed_payload_digest_is_rejected() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.payload_sha256 = "not-hex".to_string();
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MalformedDigest("payload_sha256"))
    ));
}

#[test]
fn deterministic_replay_requires_recipe() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.replay_recipe_sha256 = None;
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MissingReplayRecipe)
    ));
}

#[test]
fn expiry_must_follow_issuance() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.expires_at = draft.issued_at;
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(draft.validate().is_err());
}

#[test]
fn non_asserted_evidence_requires_receipts() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.evidence_receipt_ids.clear();
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MissingEvidence)
    ));
}

#[test]
fn blank_evidence_receipt_id_is_rejected() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.evidence_receipt_ids = vec![String::new()];
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::EmptyField("evidence_receipt_ids[]"))
    ));
}

#[test]
fn attested_guarantee_requires_receipts_even_with_asserted_evidence_class() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.guarantee_class = FindingGuaranteeClass::MeteredAttested;
    draft.evidence_class = FindingEvidenceClass::Asserted;
    draft.evidence_receipt_ids.clear();
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MissingEvidence)
    ));
}

#[test]
fn non_none_runtime_tier_requires_receipts() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    // Fully asserted otherwise, but claiming Verified runtime with no
    // receipts is an unbacked attestation-quality signal.
    draft.guarantee_class = FindingGuaranteeClass::Asserted;
    draft.evidence_class = FindingEvidenceClass::Asserted;
    draft.runtime_assurance_tier = Some(RuntimeAssuranceTier::Verified);
    draft.evidence_receipt_ids.clear();
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MissingEvidence)
    ));
}

#[test]
fn blank_intent_commitment_reference_is_rejected() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.intent_commitment_receipt_id = Some(String::new());
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::EmptyField("intent_commitment_receipt_id"))
    ));
}

#[test]
fn unknown_json_fields_are_rejected() {
    let issuer = Keypair::generate();
    let mut value = serde_json::to_value(base_finding(&issuer)).unwrap_or_default();
    if let Some(map) = value.as_object_mut() {
        map.insert("surprise".to_string(), serde_json::Value::Bool(true));
    }
    assert!(serde_json::from_value::<Finding>(value).is_err());
}
```

Note: `serde_json` is needed as a dev-dependency; add to `crates/economy/chio-finding/Cargo.toml`:

```toml
[dev-dependencies]
serde_json = { workspace = true }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p chio-finding --test finding`
Expected: FAIL to compile ("cannot find type `Finding`").

- [ ] **Step 3: Implement types.rs**

```rust
//! Artifact shapes for the cognition market.
//!
//! Field semantics: docs/research/cognition-market/ARCHITECTURE.md section 4.

use chio_core_types::capability::scope::MonetaryAmount;
use serde::{Deserialize, Serialize};

/// Signed information-good artifact.
pub const FINDING_SCHEMA_V1: &str = "chio.finding.v1";

/// What kind of claim is being sold.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingOutcomeClass {
    /// "Doing X fails / has no effect": the negative result.
    NullResult,
    /// "This change makes the committed check pass": the verified fix.
    VerifiedFix,
    /// Positive measurement or artifact with a checkable predicate.
    PositiveResult,
}

/// What "verified" means for this finding, truthful to its backing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingGuaranteeClass {
    /// Claim re-checkable by deterministic re-execution of the committed
    /// recipe. Requires `replay_recipe_sha256`.
    DeterministicReplay,
    /// Execution, cost, and output digest attested by mediated receipts;
    /// claim semantics not re-checkable.
    MeteredAttested,
    /// Seller-asserted only. Never silently upgraded.
    Asserted,
}

/// Evidence-class linkage of the claim to its receipts, mirroring the
/// normative asserted/observed/verified taxonomy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingEvidenceClass {
    Asserted,
    Observed,
    Verified,
}

/// Machine-matchable statement of what question this finding answers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingDescriptor {
    /// Prefix-searchable topic key.
    pub topic: String,
    /// Digest of the full context object; the match key for buyers.
    pub context_sha256: String,
    pub outcome_class: FindingOutcomeClass,
}

/// A tradeable unit of cognition: sealed payload commitment plus the
/// metered evidence that produced it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with `finding_id`
    /// and `signature` empty. See `compute_finding_id`.
    pub finding_id: String,
    pub descriptor: FindingDescriptor,
    pub guarantee_class: FindingGuaranteeClass,
    /// Digest of the canonical reveal ENVELOPE, not of raw payload bytes:
    /// sha256_hex(canonical_json_bytes(&reveal_envelope)) where the
    /// envelope is {media_type, payload_b64}. The envelope excludes
    /// finding_id so this commitment and the content-addressed id do not
    /// form a hash cycle. Must equal the kernel's content_hash for the
    /// reveal response (ARCHITECTURE 4.5).
    pub payload_sha256: String,
    pub payload_media_type: String,
    pub evidence_receipt_ids: Vec<String>,
    pub evidence_checkpoint_ref: String,
    /// Metered production-cost rollup (bucketed for public descriptors;
    /// see the side-channel note in the threat model).
    pub evidence_cost: MonetaryAmount,
    /// Attestation-quality tier from appraisal, as the existing CLOSED
    /// vocabulary so unsupported tier names fail at parse time
    /// (chio-core-types/src/capability/runtime_attestation.rs:15-23,
    /// serde snake_case: none/basic/attested/verified). Absent means the
    /// producing runtime was not attested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_tier: Option<RuntimeAssuranceTier>,
    pub evidence_class: FindingEvidenceClass,
    /// Required when `guarantee_class` is `DeterministicReplay`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_recipe_sha256: Option<String>,
    /// Receipt id of a pre-outcome intent commitment, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_commitment_receipt_id: Option<String>,
    pub bond_ref: String,
    pub status_feed_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_hint_ref: Option<String>,
    /// Producing agent subject. A real key type, so junk issuers reject
    /// at parse time (PublicKey deserializes from 64-hex,
    /// chio-core-types/src/crypto.rs:313-319).
    pub issuer: PublicKey,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Lowercase-hex Ed25519 signature over the canonical body with
    /// `signature` cleared, verifiable against `issuer` (Task 3). Empty
    /// string = unsigned draft; published artifacts are signed. Inline
    /// signature (disclosure-family precedent, SignedLineageSubgraph)
    /// so the registered JSON schema validates the artifact as-serialized;
    /// no SignedExportEnvelope wrapper is used for this family.
    pub signature: String,
}
```

Also add to the imports at the top of `types.rs`:

```rust
use chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core_types::crypto::PublicKey;
```

- [ ] **Step 4: Implement validate.rs**

```rust
//! Fail-closed validation for finding-family artifacts.

use chio_core_types::canonical_json_bytes;
use chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core_types::crypto::sha256_hex;

use crate::types::{
    Finding, FindingEvidenceClass, FindingGuaranteeClass, FINDING_SCHEMA_V1,
};

/// Validation failures. Every variant is a rejection; there are no
/// warning-grade outcomes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FindingError {
    #[error("unsupported finding schema: {0}")]
    UnsupportedSchema(String),
    #[error("required field is empty: {0}")]
    EmptyField(&'static str),
    #[error("field is not a lowercase 64-char hex digest: {0}")]
    MalformedDigest(&'static str),
    #[error("deterministic_replay findings require replay_recipe_sha256")]
    MissingReplayRecipe,
    #[error("non-asserted evidence class requires evidence receipts")]
    MissingEvidence,
    #[error("expires_at must be strictly after issued_at")]
    InvalidValidityWindow,
    #[error("canonical JSON serialization failed")]
    Canonicalization,
    #[error("finding signing failed")]
    Signing,
    #[error("finding signature invalid")]
    SignatureInvalid,
}

pub(crate) fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), FindingError> {
    if value.trim().is_empty() {
        Err(FindingError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn require_hex64(value: &str, field: &'static str) -> Result<(), FindingError> {
    if is_hex64(value) {
        Ok(())
    } else {
        Err(FindingError::MalformedDigest(field))
    }
}

impl Finding {
    /// Structural validation. Signature and cross-artifact checks (bond
    /// existence, receipt verification, status freshness) live in later
    /// milestones; this validator is pure over the artifact alone. It is
    /// also CLOCKLESS by design: it checks the window shape
    /// (expires_at > issued_at) but not liveness - publish/search (M2)
    /// and buy (M4) must reject `now >= expires_at` themselves.
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.finding_id, "finding_id")?;
        require_non_empty(&self.descriptor.topic, "descriptor.topic")?;
        require_hex64(&self.descriptor.context_sha256, "descriptor.context_sha256")?;
        require_hex64(&self.payload_sha256, "payload_sha256")?;
        require_non_empty(&self.payload_media_type, "payload_media_type")?;
        require_non_empty(&self.evidence_checkpoint_ref, "evidence_checkpoint_ref")?;
        require_non_empty(&self.evidence_cost.currency, "evidence_cost.currency")?;
        require_non_empty(&self.bond_ref, "bond_ref")?;
        require_non_empty(&self.status_feed_ref, "status_feed_ref")?;
        if self.guarantee_class == FindingGuaranteeClass::DeterministicReplay {
            match &self.replay_recipe_sha256 {
                Some(recipe) => require_hex64(recipe, "replay_recipe_sha256")?,
                None => return Err(FindingError::MissingReplayRecipe),
            }
        } else if let Some(recipe) = &self.replay_recipe_sha256 {
            require_hex64(recipe, "replay_recipe_sha256")?;
        }
        // Any attestation-quality signal (non-asserted guarantee class,
        // non-asserted evidence class, or a non-None runtime tier) needs
        // receipts to verify against; an asserted finding claiming
        // `Verified` runtime with no receipts is exactly the D3 lie.
        let claims_attestation = self.guarantee_class != FindingGuaranteeClass::Asserted
            || self.evidence_class != FindingEvidenceClass::Asserted
            || matches!(
                self.runtime_assurance_tier,
                Some(tier) if tier != RuntimeAssuranceTier::None
            );
        if claims_attestation && self.evidence_receipt_ids.is_empty() {
            return Err(FindingError::MissingEvidence);
        }
        for receipt_id in &self.evidence_receipt_ids {
            require_non_empty(receipt_id, "evidence_receipt_ids[]")?;
        }
        if let Some(receipt_id) = &self.intent_commitment_receipt_id {
            require_non_empty(receipt_id, "intent_commitment_receipt_id")?;
        }
        if let Some(license_ref) = &self.license_ref {
            require_non_empty(license_ref, "license_ref")?;
        }
        if let Some(price_hint_ref) = &self.price_hint_ref {
            require_non_empty(price_hint_ref, "price_hint_ref")?;
        }
        if self.expires_at <= self.issued_at {
            return Err(FindingError::InvalidValidityWindow);
        }
        self.verify_finding_id()
    }

    /// Recompute and compare the content-addressed id, fail-closed.
    pub fn verify_finding_id(&self) -> Result<(), FindingError> {
        let expected = compute_finding_id(self)?;
        if expected == self.finding_id {
            Ok(())
        } else {
            Err(FindingError::MalformedDigest("finding_id"))
        }
    }
}

/// Compute the content-addressed finding id: sha256 over the canonical
/// JSON of the body with `finding_id` and `signature` cleared.
pub fn compute_finding_id(finding: &Finding) -> Result<String, FindingError> {
    let mut body = finding.clone();
    body.finding_id = String::new();
    body.signature = String::new();
    let bytes =
        canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(sha256_hex(&bytes))
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p chio-finding --test finding`
Expected: all 7 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/economy/chio-finding
git commit -m "feat(chio-finding): finding artifact type with fail-closed validation"
```

---

### Task 3: Inline artifact signing

**Files:**
- Modify: `crates/economy/chio-finding/src/validate.rs`
- Modify: `crates/economy/chio-finding/tests/finding.rs` (append tests)

**Interfaces:**
- Consumes: `chio_core_types::crypto::{Keypair, Signature}` - `Keypair::sign_canonical(&T) -> Result<(Signature, _)>` and `PublicKey::verify_canonical(&T, &Signature) -> Result<bool>` (the same pair `SignedExportEnvelope` uses, `receipt/lineage.rs:420-434`), plus `Signature::from_hex` (`crypto.rs:692`) and `Signature::to_hex` (`crypto.rs:726`).
- Produces:
  - `sign_finding(Finding, &Keypair) -> Result<Finding, FindingError>`
  - `verify_finding_signature(&Finding) -> Result<(), FindingError>`
  - `verify_finding(&Finding) -> Result<(), FindingError>` - the single
    fail-closed acceptance boundary (structure + content-addressed id +
    issuer signature) that M2's publish surface calls
- Deliberately NOT produced: no `SignedExportEnvelope` alias for this family. The registered `chio.finding.v1` schema validates the artifact exactly as serialized, so the signature is the inline `signature` field (disclosure-family precedent: `SignedLineageSubgraph`, `chio-disclosure-lineage/src/types.rs:140-163`). An envelope wrapper would serialize as `{body, signerKey, signature}` and every signed artifact would fail the registered schema.

- [ ] **Step 1: Append failing tests**

```rust
use chio_finding::{sign_finding, verify_finding, verify_finding_signature};

#[test]
fn signed_finding_roundtrip_verifies() {
    let issuer = Keypair::generate();
    let finding = base_finding(&issuer);
    let signed = match sign_finding(finding, &issuer) {
        Ok(signed) => signed,
        Err(err) => panic!("signing failed: {err}"),
    };
    assert!(!signed.signature.is_empty());
    assert!(verify_finding_signature(&signed).is_ok());
    assert!(signed.validate().is_ok());
    assert!(verify_finding(&signed).is_ok());
}

#[test]
fn tampered_signed_finding_fails_verification() {
    let issuer = Keypair::generate();
    let mut signed = match sign_finding(base_finding(&issuer), &issuer) {
        Ok(signed) => signed,
        Err(err) => panic!("signing failed: {err}"),
    };
    signed.expires_at += 1;
    assert!(matches!(
        verify_finding_signature(&signed),
        Err(FindingError::SignatureInvalid)
    ));
}

#[test]
fn non_canonical_signature_encodings_are_rejected() {
    let issuer = Keypair::generate();
    let signed = match sign_finding(base_finding(&issuer), &issuer) {
        Ok(signed) => signed,
        Err(err) => panic!("signing failed: {err}"),
    };
    let mut uppercase = signed.clone();
    uppercase.signature = uppercase.signature.to_uppercase();
    assert!(matches!(
        verify_finding_signature(&uppercase),
        Err(FindingError::SignatureInvalid)
    ));
    let mut prefixed = signed;
    prefixed.signature = format!("0x{}", prefixed.signature);
    assert!(matches!(
        verify_finding_signature(&prefixed),
        Err(FindingError::SignatureInvalid)
    ));
}

#[test]
fn signing_requires_the_issuer_key() {
    let issuer = Keypair::generate();
    let other = Keypair::generate();
    assert!(matches!(
        sign_finding(base_finding(&issuer), &other),
        Err(FindingError::Signing)
    ));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p chio-finding --test finding`
Expected: FAIL to compile ("cannot find function `sign_finding`").

- [ ] **Step 3: Implement inline signing**

Append to `validate.rs` (extend the existing crypto import to `use chio_core_types::crypto::{sha256_hex, Signature};` and add `use chio_core_types::crypto::Keypair;`):

```rust
/// Sign the finding inline: signature is over the canonical body with
/// `signature` cleared. The signer must be the artifact's issuer.
pub fn sign_finding(
    mut finding: Finding,
    keypair: &Keypair,
) -> Result<Finding, FindingError> {
    if finding.issuer != keypair.public_key() {
        return Err(FindingError::Signing);
    }
    finding.signature = String::new();
    let (signature, _) = keypair
        .sign_canonical(&finding)
        .map_err(|_| FindingError::Signing)?;
    finding.signature = signature.to_hex();
    Ok(finding)
}

pub(crate) fn is_hex128(value: &str) -> bool {
    value.len() == 128
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Verify the inline signature against the embedded issuer, fail-closed.
/// The exact-encoding precheck matters (review finding):
/// `Signature::from_hex` tolerates `0x` and algorithm prefixes that the
/// registered JSON schema rejects, and the signature field is cleared
/// before canonical verification, so without this check an alternate
/// encoding would verify here while failing the `chio.finding.v1`
/// schema - publish would accept artifacts the schema refuses.
pub fn verify_finding_signature(finding: &Finding) -> Result<(), FindingError> {
    if !is_hex128(&finding.signature) {
        return Err(FindingError::SignatureInvalid);
    }
    let signature = Signature::from_hex(&finding.signature)
        .map_err(|_| FindingError::SignatureInvalid)?;
    let mut body = finding.clone();
    body.signature = String::new();
    match finding.issuer.verify_canonical(&body, &signature) {
        Ok(true) => Ok(()),
        _ => Err(FindingError::SignatureInvalid),
    }
}

/// The full fail-closed acceptance boundary for a published finding:
/// structure + content-addressed id (validate) + issuer signature.
///
/// IMPORTANT (review finding): this operates on an ALREADY-DESERIALIZED
/// `Finding` and reserializes canonically to check the signature and id.
/// It is NOT a substitute for validating the raw request JSON against the
/// registered `chio.finding.v1` schema: `PublicKey::from_hex` tolerates
/// `0x`/uppercase and `Option` fields accept explicit `null`, so an
/// artifact whose only deviation is `issuer: "0x.."` or
/// `runtime_assurance_tier: null` would pass here (canonicalized to the
/// accepted form) while failing the schema. The M2 publish boundary MUST
/// run `chio-spec-validate` against the raw bytes BEFORE deserializing
/// and calling this.
pub fn verify_finding(finding: &Finding) -> Result<(), FindingError> {
    finding.validate()?;
    verify_finding_signature(finding)
}
```

(If `sign_canonical`'s tuple/`to_hex` shapes differ at implementation time, mirror exactly what `SignedExportEnvelope::sign`/`verify_signature` do at `receipt/lineage.rs:420-434`; that pair is the source of truth for canonical signing.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p chio-finding --test finding`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/economy/chio-finding
git commit -m "feat(chio-finding): inline artifact signing verified against the issuer"
```

---

### Deferred: challenge and status-epoch artifacts (M5/M6)

Removed from this milestone on review. When M5 defines `chio.finding.challenge.v1` it carries the `ChallengeClassMismatch` rule (replay contradictions only against `deterministic_replay` findings), `challenger: PublicKey`, and the guarantee-class gate specified in ARCHITECTURE 4.3. When M6 defines the status feed it MUST contain or reference the oracle's exact `SignedEpochRoot { root: EpochRoot, signature: RootSignature }` (`chio-revocation-oracle/src/epoch.rs:12`, `api.rs:86-98`) plus feed metadata - not a partial copy of the root. Signed-ROOT verification carries over; portable NON-inclusion does not (today's `NonInclusionProof` has no path bytes and is checked against local oracle state, `api.rs:110-114`, `sparse_merkle.rs:77-79`), so M6 adds portable sparse paths or documents a trusted-query surface, and pins the fixed domain nonce `epoch_nonce = "chio.finding.status.v1"` (ARCHITECTURE 4.4).

---

### Task 4: Schema registration (M0)

**Files:**
- Modify: `crates/core/chio-core-types/src/signed_artifact.rs`
- Create: `spec/schemas/chio-finding/v1/finding.schema.json`
- Modify: `spec/schemas/registry.json`
- Modify: `scripts/check-chio-schema-registry.sh` (add the new schema root to `checked_chio_schema_roots`)
- Modify: `spec/schemas/MANIFEST.sha256` (deterministic regeneration, step 5)

**Interfaces:**
- Consumes: `SIGNED_ARTIFACT_SCHEMA_SPECS` table syntax (rows are `(CONST, Some(("artifact_kind", "introduced-by")))`).
- Produces: `CHIO_FINDING_V1_SCHEMA` accepted by `validate_signed_artifact_schema`.

- [ ] **Step 1: Run the registry cross-check to see it pass first (baseline)**

Run: `cargo test -p chio-core-types --test signed_artifact_schema && bash scripts/check-chio-schema-registry.sh`
Expected: PASS (baseline before edits).

- [ ] **Step 2: Add consts and SPECS rows**

In `crates/core/chio-core-types/src/signed_artifact.rs`, next to the other schema consts add:

```rust
/// Cognition-market finding artifact.
pub const CHIO_FINDING_V1_SCHEMA: &str = "chio.finding.v1";
```

and in `SIGNED_ARTIFACT_SCHEMA_SPECS`, in the style of the surrounding rows:

```rust
    (
        CHIO_FINDING_V1_SCHEMA,
        Some(("finding", "finding-market-v1")),
    ),
```

- [ ] **Step 3: Run the cross-check to see it FAIL (drift detected)**

Run: `cargo test -p chio-core-types --test signed_artifact_schema`
Expected: FAIL - code lists one schema missing from `spec/schemas/registry.json`. This failure is the specification of step 4.

- [ ] **Step 4: Author the three JSON schemas and registry rows**

`spec/schemas/chio-finding/v1/finding.schema.json` (mirror the shape below; the disclosure schemas at `spec/schemas/chio-disclosure/v1/` are the local style guide):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://chio.world/schemas/chio-finding/v1/finding.schema.json",
  "title": "Chio Finding",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema", "finding_id", "descriptor", "guarantee_class",
    "payload_sha256", "payload_media_type", "evidence_receipt_ids",
    "evidence_checkpoint_ref", "evidence_cost", "evidence_class",
    "bond_ref", "status_feed_ref", "issuer", "issued_at", "expires_at",
    "signature"
  ],
  "properties": {
    "schema": { "const": "chio.finding.v1" },
    "finding_id": { "$ref": "#/$defs/sha256" },
    "descriptor": {
      "type": "object",
      "additionalProperties": false,
      "required": ["topic", "context_sha256", "outcome_class"],
      "properties": {
        "topic": { "type": "string", "minLength": 1 },
        "context_sha256": { "$ref": "#/$defs/sha256" },
        "outcome_class": {
          "enum": ["null_result", "verified_fix", "positive_result"]
        }
      }
    },
    "guarantee_class": {
      "enum": ["deterministic_replay", "metered_attested", "asserted"]
    },
    "payload_sha256": { "$ref": "#/$defs/sha256" },
    "payload_media_type": { "type": "string", "minLength": 1 },
    "evidence_receipt_ids": {
      "type": "array", "items": { "type": "string", "minLength": 1 }
    },
    "evidence_checkpoint_ref": { "type": "string", "minLength": 1 },
    "evidence_cost": {
      "type": "object",
      "additionalProperties": false,
      "required": ["units", "currency"],
      "properties": {
        "units": { "type": "integer", "minimum": 0 },
        "currency": { "type": "string", "minLength": 1 }
      }
    },
    "runtime_assurance_tier": { "enum": ["none", "basic", "attested", "verified"] },
    "evidence_class": { "enum": ["asserted", "observed", "verified"] },
    "replay_recipe_sha256": { "$ref": "#/$defs/sha256" },
    "intent_commitment_receipt_id": { "type": "string", "minLength": 1 },
    "bond_ref": { "type": "string", "minLength": 1 },
    "status_feed_ref": { "type": "string", "minLength": 1 },
    "license_ref": { "type": "string", "minLength": 1 },
    "price_hint_ref": { "type": "string", "minLength": 1 },
    "issuer": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "issued_at": { "type": "integer", "minimum": 0 },
    "expires_at": { "type": "integer", "minimum": 0 },
    "signature": { "type": "string", "pattern": "^[0-9a-f]{128}$" }
  },
  "$defs": {
    "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
  }
}
```

Also add the new schema root to the registry check script: in `scripts/check-chio-schema-registry.sh`, insert `"spec/schemas/chio-finding/",` into the `checked_chio_schema_roots` tuple in alphabetical position (after `"spec/schemas/chio-federation/",`, before `"spec/schemas/chio-lineage/",`). Without this the script does not require chio-finding schemas to be registered, weakening the gate for the new family.

Add to `spec/schemas/registry.json` `artifacts` array (keep the file's existing ordering convention):

```json
{
  "schema": "chio.finding.v1",
  "artifactKind": "finding",
  "introducedBy": "finding-market-v1",
  "schemaFile": "spec/schemas/chio-finding/v1/finding.schema.json"
}
```

- [ ] **Step 5: Regenerate the manifest deterministically, then re-run the cross-checks**

The script demands byte-exact deterministic regeneration (its own algorithm, `scripts/check-chio-schema-registry.sh:58-93`): the path set is every git-tracked `spec/schemas/**/*.schema.json` plus `registry.json`, `VERSION`, and the manifest itself, sorted by path; each line is `sha256(file)  path`; the manifest's own line's digest is the sha256 of the concatenation of all OTHER lines. Regenerate with exactly that algorithm:

```bash
python3 - <<'PY'
import hashlib, pathlib, subprocess
root = pathlib.Path('.')
manifest_rel = 'spec/schemas/MANIFEST.sha256'
tracked = subprocess.run(
    ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard',
     '--', 'spec/schemas'],
    check=True, stdout=subprocess.PIPE).stdout.decode().split('\0')
keep = sorted(
    p for p in tracked
    if p.endswith('.schema.json')
    or p in {manifest_rel, 'spec/schemas/registry.json', 'spec/schemas/VERSION'})
without_self = [
    f"{hashlib.sha256((root / p).read_bytes()).hexdigest()}  {p}\n"
    for p in keep if p != manifest_rel]
self_hash = hashlib.sha256(''.join(without_self).encode()).hexdigest()
content = ''.join(
    f"{self_hash}  {p}\n" if p == manifest_rel
    else f"{hashlib.sha256((root / p).read_bytes()).hexdigest()}  {p}\n"
    for p in keep)
(root / manifest_rel).write_text(content)
print('regenerated', manifest_rel, 'entries:', len(keep))
PY
```

Then: `cargo test -p chio-core-types --test signed_artifact_schema && bash scripts/check-chio-schema-registry.sh`
Expected: PASS, PASS. (If the script still complains, its stderr names the exact drift; fix and regenerate again - never hand-edit digest lines.)

- [ ] **Step 6: Commit**

```bash
git add crates/core/chio-core-types/src/signed_artifact.rs spec/schemas scripts/check-chio-schema-registry.sh
git commit -m "feat(chio-core-types): register chio.finding.v1 artifact family"
```

---

### Task 5: Golden fixture and schema-conformance test

**Files:**
- Create: `fixtures/proof-room/finding/verified-fix-basic/finding.json`
- Modify: `crates/economy/chio-finding/tests/finding.rs` (append)

**Interfaces:**
- Consumes: `Finding` serde shape from Task 2; golden-dir convention from `fixtures/proof-room/commerce-payments/`.

- [ ] **Step 1: Append the failing golden test**

```rust
#[test]
fn golden_verified_fix_fixture_validates() {
    let raw = include_str!(
        "../../../../fixtures/proof-room/finding/verified-fix-basic/finding.json"
    );
    let finding: Finding = match serde_json::from_str(raw) {
        Ok(finding) => finding,
        Err(err) => panic!("golden fixture failed to parse: {err}"),
    };
    assert!(chio_finding::verify_finding(&finding).is_ok());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p chio-finding --test finding golden_verified_fix_fixture_validates`
Expected: FAIL (file not found at include path - fix the `../` depth if the error says so, then missing-file failure).

- [ ] **Step 3: Generate the fixture from the crate itself**

Write a small throwaway generator as an ignored test in the same file, run it once, then keep it for regeneration:

```rust
#[test]
#[ignore = "regenerates the golden fixture; run manually"]
fn regenerate_golden_fixture() {
    // Deterministic fixture keypair via a fixed seed (review finding: a
    // test seed is not a production secret, and an unsigned golden would
    // let M1 pass its signed-artifact exit with a fixture that fails
    // signature verification). Keypair::from_seed: crypto.rs:164.
    let issuer = Keypair::from_seed(&[9u8; 32]);
    let mut finding = draft_finding_with_issuer(issuer.public_key());
    finding.finding_id = compute_finding_id(&finding).unwrap_or_default();
    let finding = match sign_finding(finding, &issuer) {
        Ok(finding) => finding,
        Err(err) => panic!("fixture signing: {err}"),
    };
    let json = serde_json::to_string_pretty(&finding).unwrap_or_default();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../fixtures/proof-room/finding/verified-fix-basic/finding.json"
    );
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, json + "\n");
}
```

Run: `cargo test -p chio-finding --test finding regenerate_golden_fixture -- --ignored`
Expected: PASS and the file exists.

- [ ] **Step 4: Validate the fixture against the JSON schema**

Run: `cargo run -p chio-spec-validate -- spec/schemas/chio-finding/v1/finding.schema.json fixtures/proof-room/finding/verified-fix-basic/finding.json`
(If the binary's CLI shape differs, check `crates/tooling/chio-spec-validate/src/main.rs` for the argument order.)
Expected: validation PASS. If the schema and struct disagree, the schema is wrong - fix the schema, not the struct, and re-run Task 4 step 5's checks.

- [ ] **Step 5: Run the golden test to verify it passes**

Run: `cargo test -p chio-finding --test finding`
Expected: all tests PASS (one ignored).

- [ ] **Step 6: Commit**

```bash
git add fixtures/proof-room/finding crates/economy/chio-finding
git commit -m "test(chio-finding): golden verified-fix fixture with schema conformance"
```

---

### Task 6: ADR-0017 amendment verification

**Files:**
- Read: `docs/adr/ADR-0017-cognition-market-finding-artifacts.md`

**Interfaces:** none (docs).

The three amendments this task originally specified were applied directly
during PR #1025 review (D1 lists findings under the existing `ToolServer`
actor kind instead of a new subject kind; D1's artifact list includes the
optional pre-outcome intent-commitment receipt reference; D4 carries the
published-rate probabilistic-audit sentence). This task is now
verification-only.

- [ ] **Step 1: Verify the amendments are present**

Run: `grep -c "ToolServer actor" docs/adr/ADR-0017-cognition-market-finding-artifacts.md && grep -c "intent-commitment receipt" docs/adr/ADR-0017-cognition-market-finding-artifacts.md && grep -c "probabilistic audits" docs/adr/ADR-0017-cognition-market-finding-artifacts.md`
Expected: three non-zero counts. If any is zero the branch predates the
review fixes; stop and rebase before continuing.

- [ ] **Step 2: Check the ADR for em dashes**

Run: `grep -c $'\u2014' docs/adr/ADR-0017-cognition-market-finding-artifacts.md`
Expected: `0` (non-zero exit from grep on zero matches is the pass signal
here).

---

### Task 7: Full verification gate

**Files:** none (verification only).

- [ ] **Step 1: Run the workspace gate**

Run: `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`
Expected: all four PASS. Fix anything that fails before proceeding (formatting fixes: `cargo fmt --all`).

- [ ] **Step 2: Run the stricter test-target lint for the new crate**

Run: `cargo clippy -p chio-finding --tests -- -D warnings`
Expected: PASS (the CI gate does not lint test targets, but new code should).

- [ ] **Step 2b: Run the v1-only release-line gate**

Run: `bash scripts/check-chio-owned-v1-only.sh`
Expected: no output naming any added file (the checker rejects chio-owned `.v2`-style strings outside the permitted `.v9x` negative-fixture convention).

- [ ] **Step 3: Commit any gate fixes**

```bash
git add -A
git commit -m "chore(chio-finding): gate fixes"
```

(Skip the commit if the tree is clean.)
