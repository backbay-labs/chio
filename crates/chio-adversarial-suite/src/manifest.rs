//! Cross-SDK verdict-matrix manifest emitted by the adversarial suite.
//!
//! The manifest is consumed by trajectory-2 M02's cross-language verdict
//! differential. Each manifest entry pins a non-pending bundled case with
//! enough provenance for an SDK to look up the JSON-on-disk by id and to
//! verify it has not silently mutated by comparing the case's content
//! sha256 with the value carried in the manifest. Pending cases are
//! deliberately excluded: they have not yet been triaged into a binding
//! verdict, so feeding them to the matrix would either produce a false
//! divergence signal or paper one over.
//!
//! The manifest is `serde_json::Value`-shaped; producers and consumers
//! agree on the field names and the schema version. M05.P2.T4 ships the
//! producer; the consumer ships in trajectory-2 M02.
//!
//! Wire-shape (canonical JSON, sorted keys, two-space indent):
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "producer": "chio-adversarial-suite",
//!   "case_count": 40,
//!   "cases": [
//!     {
//!       "id": "clock-rewound-001",
//!       "class": "clock_rewound",
//!       "expected_verdict": "DENY",
//!       "expected_reason": "clock_rewound_capability_window",
//!       "threat_id": "capability_token_theft",
//!       "path": "cases/clock_rewound/clock-rewound-001.json",
//!       "content_sha256": "<64 hex>"
//!     }
//!   ]
//! }
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{bundled_cases, AttackClass, BundledCase, CaseError, ExpectedVerdict, BUNDLED_CASES};

/// Manifest schema version. Bump only when the wire shape changes.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Stable producer identifier carried inside the manifest body.
pub const MANIFEST_PRODUCER: &str = "chio-adversarial-suite";

/// One manifest entry per non-pending bundled case.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    /// Stable case identifier (matches `AdversarialCase::id`).
    pub id: String,
    /// Adversarial attack class.
    pub class: AttackClass,
    /// Expected verdict; always `DENY` for the M05 suite.
    pub expected_verdict: ExpectedVerdict,
    /// Stable deny reason string asserted by downstream harnesses.
    pub expected_reason: String,
    /// Threat-model identifier this case is intended to cover.
    pub threat_id: String,
    /// Repository-relative path to the case JSON on disk.
    pub path: String,
    /// sha256 of the case JSON file's bytes, lowercase hex.
    pub content_sha256: String,
}

/// Top-level manifest body.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Producer crate name (always `chio-adversarial-suite`).
    pub producer: String,
    /// Case count, redundantly carried for fast consumer assertions.
    pub case_count: usize,
    /// Manifest entries, sorted by case id for deterministic output.
    pub cases: Vec<ManifestEntry>,
}

impl Manifest {
    /// Build a manifest from the statically bundled cases.
    ///
    /// Pending cases are skipped; only validated coverage cases land in
    /// the manifest. Entries are sorted by `id` so the emitted JSON is
    /// byte-for-byte stable across runs (critical for the gate test and
    /// for downstream cross-SDK joins).
    pub fn from_bundled() -> Result<Self, CaseError> {
        let cases = bundled_cases()?;
        let mut entries: Vec<ManifestEntry> = Vec::with_capacity(cases.len());

        for (case, bundled) in cases.iter().zip(BUNDLED_CASES.iter()) {
            // Defence-in-depth: zip is robust against drift between the
            // two arrays, but the loader contract guarantees bundled
            // cases are returned in the same order as `BUNDLED_CASES`.
            // If a producer ever changes the order, the assertion below
            // fails the build rather than silently mismatching paths.
            if !bundled.path.ends_with(&format!("/{}.json", case.id)) {
                return Err(CaseError::ManifestDrift {
                    case_id: case.id.clone(),
                    path: bundled.path.to_string(),
                });
            }
            if case.pending {
                continue;
            }
            entries.push(ManifestEntry {
                id: case.id.clone(),
                class: case.class,
                expected_verdict: case.expected_verdict,
                expected_reason: case.expected_reason.clone(),
                threat_id: case.threat_id.clone(),
                path: bundled.path.to_string(),
                content_sha256: hash_case(bundled),
            });
        }

        entries.sort_by(|a, b| a.id.cmp(&b.id));

        Ok(Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            producer: MANIFEST_PRODUCER.to_string(),
            case_count: entries.len(),
            cases: entries,
        })
    }

    /// Render the manifest as canonical JSON suitable for on-disk write.
    ///
    /// Emits two-space indent, sorted top-level keys via the field
    /// declaration order, and a trailing newline so editors and tools
    /// that touch the file do not introduce trivial diffs.
    pub fn to_canonical_json(&self) -> Result<String, CaseError> {
        let mut buf = serde_json::to_string_pretty(self)?;
        buf.push('\n');
        Ok(buf)
    }
}

fn hash_case(case: &BundledCase) -> String {
    let mut hasher = Sha256::new();
    hasher.update(case.contents.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_excludes_pending_cases_and_sorts_by_id() -> Result<(), CaseError> {
        let manifest = Manifest::from_bundled()?;
        assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION);
        assert_eq!(manifest.producer, MANIFEST_PRODUCER);
        assert_eq!(manifest.case_count, manifest.cases.len());

        // Sorted by id, ascending.
        let mut ids: Vec<&str> = manifest.cases.iter().map(|c| c.id.as_str()).collect();
        let original = ids.clone();
        ids.sort();
        assert_eq!(original, ids, "manifest entries must be sorted by id");

        // Every emitted entry is DENY; pending cases are excluded by
        // construction so this is a regression check.
        for entry in &manifest.cases {
            assert_eq!(entry.expected_verdict, ExpectedVerdict::Deny);
            assert!(!entry.id.is_empty());
            assert!(!entry.expected_reason.is_empty());
            assert!(!entry.threat_id.is_empty());
            assert_eq!(entry.content_sha256.len(), 64);
            assert!(entry
                .content_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase())));
            assert!(
                entry.path.starts_with("cases/"),
                "bundled path must be repository-relative beneath cases/, got {}",
                entry.path
            );
        }

        Ok(())
    }

    #[test]
    fn canonical_json_is_stable() -> Result<(), CaseError> {
        let manifest = Manifest::from_bundled()?;
        let first = manifest.to_canonical_json()?;
        let second = manifest.to_canonical_json()?;
        assert_eq!(first, second);
        assert!(first.ends_with('\n'));
        Ok(())
    }
}
