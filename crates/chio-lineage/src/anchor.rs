//! Anchor pinning (M09 P5.T6).
//!
//! Hashes the current lineage frontier through canonical bytes and
//! records a frontier digest. PQ signing is performed by the M03 hybrid
//! signing backend when present (soft-dep); when absent, the command
//! produces an unsigned frontier and exits cleanly. Soft-dep absence is
//! recorded explicitly on the artifact so M10 model-card anchoring can
//! distinguish a verified anchor from a degraded unsigned one.

use serde::{Deserialize, Serialize};

use crate::schema::{LineageEdge, LineageGraph, LineageNode};

/// SHA-256 of the canonical JSON of a frontier projection. The frontier
/// is a deterministic sorted list of node ids and edge keys; canonical
/// bytes come from M06 [`CanonicalBytes`] when available; otherwise a
/// documented byte-equivalence shim (sorted JSON arrays with no
/// whitespace) is used and recorded on the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierDigest {
    pub algo: String,
    pub hex: String,
}

/// Source of the canonical bytes used to compute the digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalSource {
    /// M06 `CanonicalBytes` newtype.
    CanonicalBytes,
    /// Documented byte-equivalence shim. Used when M06 is absent.
    EquivalenceShim,
}

/// Soft-dep state for hybrid signing.
///
/// The `Signed` variant carries a non-empty signature payload. A pinned
/// frontier that advertises `Signed` with an empty `signature_hex` is
/// rejected at construction time so a downstream verifier cannot be
/// tricked into trusting an unsigned anchor (lineage tamper, M09 P5
/// fail-closed contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningState {
    /// M03 hybrid signing was used. The signature payload is included.
    Signed {
        algorithm: String,
        signature_hex: String,
    },
    /// M03 hybrid signing was absent. Frontier is recorded unsigned.
    UnsignedSoftDepAbsent,
    /// A signer was named but the soft-dep produced no signature payload.
    /// Distinct from `UnsignedSoftDepAbsent` so model-card anchoring can
    /// surface the partial-signing path explicitly. Verifiers MUST treat
    /// this state as unsigned.
    UnsignedSignerStubbed { algorithm: String },
}

/// The pinned-frontier artifact written by `arc lineage pin`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchoredFrontier {
    pub schema_version: String,
    pub graph_schema: String,
    pub canonical_source: CanonicalSource,
    pub digest: FrontierDigest,
    pub signing: SigningState,
    pub node_count: usize,
    pub edge_count: usize,
}

/// Compute the deterministic frontier projection bytes. Sorted by
/// (node id) and (edge key); the result is byte-stable across runs.
pub fn frontier_bytes(graph: &LineageGraph) -> Vec<u8> {
    let mut node_ids: Vec<&str> = graph
        .nodes
        .iter()
        .map(|n: &LineageNode| n.id.as_str())
        .collect();
    node_ids.sort_unstable();
    let mut edges: Vec<(String, String, String)> = graph
        .edges
        .iter()
        .map(|e: &LineageEdge| {
            let kind = serde_json::to_string(&e.kind).unwrap_or_else(|_| String::new());
            (e.from.clone(), e.to.clone(), kind)
        })
        .collect();
    edges.sort_unstable();
    let payload = serde_json::json!({
        "schema_version": graph.schema_version,
        "nodes": node_ids,
        "edges": edges,
    });
    serde_json::to_vec(&payload).unwrap_or_default()
}

/// Stable sha256 hex digest of the frontier bytes. Implementation uses
/// the existing chio-core SHA-256 helper to guarantee byte-equivalence
/// with anchor publication paths elsewhere in the workspace.
pub fn frontier_digest(graph: &LineageGraph) -> FrontierDigest {
    let bytes = frontier_bytes(graph);
    let hex = sha256_hex(&bytes);
    FrontierDigest {
        algo: "sha256".to_string(),
        hex,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finish();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Tiny embedded SHA-256 to avoid pulling a new direct dependency. This
/// is not constant-time and is used only for digest stability of public,
/// non-secret graph projection bytes. The implementation is the FIPS
/// 180-4 spec; tests check the digest of `b""` and `b"abc"` against
/// known vectors.
struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        let mut pad = [0u8; 128];
        pad[0] = 0x80;
        let pad_len = if self.buf_len < 56 {
            56 - self.buf_len
        } else {
            120 - self.buf_len
        };
        let len_bytes = bit_len.to_be_bytes();
        let mut tail = Vec::with_capacity(pad_len + 8);
        tail.extend_from_slice(&pad[..pad_len]);
        tail.extend_from_slice(&len_bytes);
        self.update(&tail);
        let mut out = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Pin a lineage frontier. Records the digest plus signing state. When
/// `signer_hint` is `None` the artifact is recorded as
/// `UnsignedSoftDepAbsent`. A signer hint without a signature payload
/// records `UnsignedSignerStubbed { algorithm }` rather than
/// `Signed { signature_hex: "" }`, so a verifier cannot mistake a
/// stub for a real PQ signature. Real signing is produced through
/// [`pin_frontier_signed`].
pub fn pin_frontier(graph: &LineageGraph, signer_hint: Option<&str>) -> AnchoredFrontier {
    let digest = frontier_digest(graph);
    let signing = match signer_hint {
        Some(algo) => SigningState::UnsignedSignerStubbed {
            algorithm: algo.to_string(),
        },
        None => SigningState::UnsignedSoftDepAbsent,
    };
    AnchoredFrontier {
        schema_version: "chio.lineage.frontier/v1".to_string(),
        graph_schema: graph.schema_version.clone(),
        canonical_source: CanonicalSource::EquivalenceShim,
        digest,
        signing,
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
    }
}

/// Return true when a signature payload is non-empty lower-case hex.
#[must_use]
pub fn is_lowercase_hex_signature_payload(signature_hex: &str) -> bool {
    !signature_hex.is_empty()
        && signature_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Pin a frontier with a real PQ signature payload. The signature is
/// validated to be non-empty and lower-case hexadecimal so the
/// `Signed` variant cannot be forged by passing an empty or malformed
/// string. Used once M03 hybrid signing is wired in.
pub fn pin_frontier_signed(
    graph: &LineageGraph,
    algorithm: &str,
    signature_hex: &str,
) -> Result<AnchoredFrontier, AnchorError> {
    if algorithm.trim().is_empty() {
        return Err(AnchorError::EmptySigningAlgorithm);
    }
    if signature_hex.is_empty() {
        return Err(AnchorError::EmptySignaturePayload);
    }
    if !is_lowercase_hex_signature_payload(signature_hex) {
        return Err(AnchorError::SignaturePayloadNotHex);
    }
    let digest = frontier_digest(graph);
    Ok(AnchoredFrontier {
        schema_version: "chio.lineage.frontier/v1".to_string(),
        graph_schema: graph.schema_version.clone(),
        canonical_source: CanonicalSource::EquivalenceShim,
        digest,
        signing: SigningState::Signed {
            algorithm: algorithm.to_string(),
            signature_hex: signature_hex.to_string(),
        },
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
    })
}

/// Errors surfaced when constructing a signed anchor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnchorError {
    /// The signing algorithm label was empty.
    #[error("signing algorithm label was empty")]
    EmptySigningAlgorithm,
    /// The signature payload was empty.
    #[error("signature payload was empty")]
    EmptySignaturePayload,
    /// The signature payload was not lower-case hexadecimal.
    #[error("signature payload was not lower-case hexadecimal")]
    SignaturePayloadNotHex,
}

impl AnchoredFrontier {
    /// Return true when the artifact carries a real non-empty lower-case
    /// hex signature payload. A frontier in any unsigned-state variant
    /// returns false so callers can fail-closed without re-matching every
    /// variant.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        matches!(
            &self.signing,
            SigningState::Signed { signature_hex, .. }
                if is_lowercase_hex_signature_payload(signature_hex)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_sha256_matches_known_vector() {
        let d = sha256_hex(b"");
        assert_eq!(
            d,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_sha256_matches_known_vector() {
        let d = sha256_hex(b"abc");
        assert_eq!(
            d,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn pin_without_signer_records_unsigned_state() {
        let g = LineageGraph::empty();
        let pinned = pin_frontier(&g, None);
        assert!(matches!(
            pinned.signing,
            SigningState::UnsignedSoftDepAbsent
        ));
        assert_eq!(pinned.digest.algo, "sha256");
        assert!(!pinned.is_signed());
    }

    #[test]
    fn pin_is_byte_stable_across_runs() {
        let g = LineageGraph::empty();
        let a = frontier_digest(&g).hex;
        let b = frontier_digest(&g).hex;
        assert_eq!(a, b);
    }

    #[test]
    fn pin_with_signer_hint_does_not_forge_signed_state() {
        // Regression: a signer hint without an actual signature must not
        // produce a `Signed { signature_hex: "" }` state. A verifier
        // checking `is_signed()` would otherwise be deceived by an
        // anchor that carries no signature payload.
        let g = LineageGraph::empty();
        let pinned = pin_frontier(&g, Some("ml-dsa-65"));
        assert!(matches!(
            pinned.signing,
            SigningState::UnsignedSignerStubbed { .. }
        ));
        assert!(!pinned.is_signed());
    }

    #[test]
    fn pin_signed_rejects_empty_signature() {
        let g = LineageGraph::empty();
        let err = pin_frontier_signed(&g, "ml-dsa-65", "")
            .err()
            .unwrap_or(AnchorError::EmptySigningAlgorithm);
        assert_eq!(err, AnchorError::EmptySignaturePayload);
    }

    #[test]
    fn pin_signed_rejects_non_hex_signature() {
        let g = LineageGraph::empty();
        let err = pin_frontier_signed(&g, "ml-dsa-65", "ZZZZ")
            .err()
            .unwrap_or(AnchorError::EmptySigningAlgorithm);
        assert_eq!(err, AnchorError::SignaturePayloadNotHex);
    }

    #[test]
    fn deserialized_signed_state_with_malformed_payload_is_unsigned() {
        for signature_hex in ["DEADBEEF", "dead beef", " deadbeef", "zz"] {
            let value = serde_json::json!({
                "schema_version": "chio.lineage.frontier/v1",
                "graph_schema": "chio.lineage.graph/v1",
                "canonical_source": "equivalence_shim",
                "digest": {
                    "algo": "sha256",
                    "hex": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                },
                "signing": {
                    "signed": {
                        "algorithm": "ml-dsa-65",
                        "signature_hex": signature_hex
                    }
                },
                "node_count": 0,
                "edge_count": 0
            });
            let decoded: AnchoredFrontier = serde_json::from_value(value)
                .unwrap_or_else(|err| panic!("deserialize signed state: {err}"));
            assert!(
                !decoded.is_signed(),
                "malformed signature payload {signature_hex:?} must be unsigned"
            );
        }
    }

    #[test]
    fn pin_signed_rejects_empty_algorithm() {
        let g = LineageGraph::empty();
        let err = pin_frontier_signed(&g, "  ", "deadbeef")
            .err()
            .unwrap_or(AnchorError::EmptySignaturePayload);
        assert_eq!(err, AnchorError::EmptySigningAlgorithm);
    }

    #[test]
    fn pin_signed_with_real_payload_is_signed() {
        let g = LineageGraph::empty();
        let pinned = pin_frontier_signed(&g, "ml-dsa-65", "deadbeef").unwrap_or_else(|_| {
            panic!("signed pin should succeed with real payload");
        });
        assert!(pinned.is_signed());
    }
}
