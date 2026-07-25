//! Signed receipt envelope for the recursive `delegate` mint helper.
//!
//! `DelegationReceipt` is the recursive-delegation envelope: every
//! successful `delegate(parent, attenuation, ...)` call emits one alongside
//! the freshly-signed `DelegationLink`. The receipt records the parent
//! chain that was attenuated, the attenuation that was applied, the time
//! the receipt was minted, and a 16-byte nonce so identical attenuations
//! produced at the same `signed_at` second can still be distinguished.
//!
//! The receipt carries the `link` itself so verifiers can reconstruct the
//! full delegation chain (`parent_chain` followed by `link`) without a
//! side channel.
//!
//! # Canonical encoding
//!
//! Receipts are signed-into-existence by [`crate::capability::attenuation::delegate`].
//! Their canonical-JSON encoding is the byte-stable representation that
//! downstream verifiers (and lineage indexers) hash.
//! Use [`DelegationReceipt::canonical_bytes`] to obtain a
//! [`CanonicalBytes`] wrapper backed by the RFC 8785 serializer.
//!
//! # Trust boundary
//!
//! Receipts are produced under fail-closed semantics:
//!
//! * Scope subset: child scope MUST be a subset of the parent scope.
//! * Budget monotonicity: `max_invocations`, `max_cost_per_invocation`,
//!   and `max_total_cost` MAY only narrow; widening rejects.
//! * Expiry monotonicity: child `expires_at` MUST satisfy
//!   `child <= parent`.
//!
//! Any violation rejects at mint time with [`crate::error::Error`].

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::CanonicalBytes;
use crate::capability::aggregate_invocation::AggregateBudgetDelegationMarker;
use crate::capability::attenuation::{Attenuation, DelegationLink};
use crate::capability::cumulative_approval::CumulativeApprovalDelegationMarker;
use crate::error::Result;

/// Structured attenuation applied during a `delegate` mint.
///
/// `ScopeAttenuation` is the high-level surface accepted by
/// [`crate::capability::attenuation::delegate`]: callers describe how the parent token
/// is being narrowed, and the helper translates the request into the
/// per-link [`Attenuation`] vector that `DelegationLink` carries on the
/// wire. The two surfaces are intentionally distinct: this one is the
/// minting input (operator-supplied), `Attenuation` is the receipt-level
/// audit record (canonical-JSON-stable).
///
/// All fields are optional; an empty `ScopeAttenuation` is a valid no-op
/// attenuation that copies the parent capability shape verbatim. This is
/// the case the spec calls out as "scope subset trivially holds".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeAttenuation {
    /// Per-link attenuation vector recorded on the signed delegation link.
    /// Each entry maps onto the existing [`Attenuation`] enum, which is
    /// the audit-evidence surface.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Attenuation>,
    /// Optional shortened expiry for the delegated capability. When
    /// `Some(t)`, the child token's `expires_at` MUST be `<= t` AND
    /// `<= parent.expires_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_expires_at: Option<u64>,
    /// Optional sub-agent budget share in basis points, interpreted
    /// *parent-relative*: the child's share is a fraction of the parent's
    /// remaining/granted budget and can never exceed it. `delegate` enforces
    /// `child_share <= parent.budget_share_bps` (treating an absent parent
    /// share as the full 10000 bps) fail-closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_share_bps: Option<u16>,
}

impl ScopeAttenuation {
    /// Construct a no-op attenuation. Useful for the corner case where a
    /// caller wants to mint a delegation receipt against an unchanged
    /// scope (the chain-extension hop still records a fresh signed link).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Construct from a per-link attenuation vector with no expiry change.
    #[must_use]
    pub fn from_steps(steps: Vec<Attenuation>) -> Self {
        Self {
            steps,
            child_expires_at: None,
            budget_share_bps: None,
        }
    }
}

/// Signed-receipt envelope emitted by [`crate::capability::attenuation::delegate`].
///
/// Field semantics:
///
/// * `parent_chain` records the delegation chain leading up to (but not
///   including) the freshly-minted `link`. Verifiers reconstruct the
///   complete chain by appending `link` to `parent_chain`.
/// * `attenuation` records the operator-supplied attenuation request. The
///   on-wire per-link attenuation vector lives on `link.attenuations`;
///   this field is the high-level audit record.
/// * `signed_at` is the unix-second timestamp the receipt was minted.
/// * `nonce` is a 16-byte caller-supplied value that disambiguates
///   receipts minted at identical `signed_at` seconds with identical
///   attenuations.
/// * `link` is the freshly-signed `DelegationLink` produced by
///   `DelegationLink::sign`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegationReceipt {
    /// Parent delegation chain, copied from the parent
    /// `CapabilityToken::delegation_chain`. Empty when the parent token
    /// is a root capability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_chain: Vec<DelegationLink>,
    /// Operator-supplied attenuation request (audit record).
    pub attenuation: ScopeAttenuation,
    /// Unix-second timestamp at which the receipt was minted.
    pub signed_at: u64,
    /// Caller-supplied nonce (16 bytes, hex-encoded on-wire).
    #[serde(with = "hex_nonce")]
    pub nonce: [u8; 16],
    /// Freshly-signed delegation link. Append to `parent_chain` to obtain
    /// the complete delegation chain for the child capability.
    pub link: DelegationLink,
    /// Capability identifier of the parent token whose chain was extended.
    /// Diagnostic only: the cryptographic binding lives in `link`.
    pub parent_capability_id: String,
    /// Delegation-family budget preservation copied from the signed link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregate_budget: Option<AggregateBudgetDelegationMarker>,
    /// Cumulative approval root-binding preservation copied from the signed link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cumulative_approval: Option<CumulativeApprovalDelegationMarker>,
}

impl DelegationReceipt {
    /// RFC 8785 canonical-JSON encoding of the receipt. Byte-stable across
    /// host languages so downstream verifiers and lineage indexers can
    /// hash the receipt deterministically.
    pub fn canonical_bytes(&self) -> Result<CanonicalBytes> {
        self.validate_aggregate_budget_projection()?;
        self.validate_cumulative_approval_projection()?;
        CanonicalBytes::new(self)
    }

    pub fn validate_aggregate_budget_projection(&self) -> Result<()> {
        if self.aggregate_budget != self.link.aggregate_budget {
            return Err(crate::error::Error::AttenuationViolation {
                reason: "delegation receipt aggregate budget does not match its signed link".into(),
            });
        }
        Ok(())
    }

    pub fn validate_cumulative_approval_projection(&self) -> Result<()> {
        if let Some(marker) = self.cumulative_approval.as_ref() {
            marker.validate()?;
        }
        if self.cumulative_approval != self.link.cumulative_approval {
            return Err(crate::error::Error::AttenuationViolation {
                reason:
                    "delegation receipt cumulative approval marker does not match its signed link"
                        .into(),
            });
        }
        Ok(())
    }

    /// Reconstruct the complete delegation chain represented by this
    /// receipt: the parent chain followed by the freshly-signed link.
    /// Verifiers feed this into [`crate::capability::attenuation::validate_delegation_chain`]
    /// to check end-to-end signature continuity.
    #[must_use]
    pub fn complete_chain(&self) -> Vec<DelegationLink> {
        let mut chain = Vec::with_capacity(self.parent_chain.len() + 1);
        chain.extend(self.parent_chain.iter().cloned());
        chain.push(self.link.clone());
        chain
    }

    /// Depth of the child capability minted by this receipt: the count of
    /// links in the complete delegation chain. A receipt minted against a
    /// root capability has depth `1`.
    #[must_use]
    pub fn child_depth(&self) -> u32 {
        // `+1` cannot overflow `u32` in any practical chain (depth bound
        // is < 256 by chain-depth assumption); saturating keeps the
        // helper total without panicking.
        let parent_len = u32::try_from(self.parent_chain.len()).unwrap_or(u32::MAX);
        parent_len.saturating_add(1)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use crate::capability::{
        attenuation::{delegate, Attenuation},
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use crate::crypto::Keypair;

    fn parent_token(parent_kp: &Keypair, subject_kp: &Keypair) -> CapabilityToken {
        let scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "tool-x".to_string(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: vec![],
                max_invocations: Some(10),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        };
        let body = CapabilityTokenBody {
            id: "cap-parent".to_string(),
            issuer: parent_kp.public_key(),
            subject: subject_kp.public_key(),
            scope,
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        CapabilityToken::sign(body, parent_kp).unwrap()
    }

    fn child_scope() -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "tool-x".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(5),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        }
    }

    fn mint(nonce: [u8; 16]) -> DelegationReceipt {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let delegatee = Keypair::generate();
        let parent = parent_token(&issuer, &subject);
        delegate(
            &parent,
            &child_scope(),
            &subject,
            &delegatee.public_key(),
            ScopeAttenuation::empty(),
            1500,
            nonce,
        )
        .unwrap()
    }

    #[test]
    fn receipt_canonical_bytes_round_trip() {
        let receipt = mint([1_u8; 16]);
        let bytes = receipt.canonical_bytes().unwrap();
        let decoded: DelegationReceipt = serde_json::from_slice(bytes.as_bytes()).unwrap();
        assert_eq!(decoded.parent_capability_id, receipt.parent_capability_id);
        assert_eq!(decoded.signed_at, receipt.signed_at);
        assert_eq!(decoded.nonce, receipt.nonce);
        assert_eq!(
            decoded.link.signature.to_hex(),
            receipt.link.signature.to_hex()
        );
    }

    #[test]
    fn receipt_canonical_bytes_are_byte_stable() {
        // Two receipts that differ only in nonce must produce different
        // canonical byte strings, while two clones of the same receipt
        // must serialize identically.
        let a = mint([1_u8; 16]);
        let b = a.clone();
        assert_eq!(
            a.canonical_bytes().unwrap().as_bytes(),
            b.canonical_bytes().unwrap().as_bytes()
        );
        let c = mint([2_u8; 16]);
        assert_ne!(
            a.canonical_bytes().unwrap().as_bytes(),
            c.canonical_bytes().unwrap().as_bytes()
        );
    }

    #[test]
    fn receipt_rejects_unknown_fields() {
        let receipt = mint([3_u8; 16]);
        let mut value: serde_json::Value =
            serde_json::from_slice(receipt.canonical_bytes().unwrap().as_bytes()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("rogue".to_string(), serde_json::Value::Bool(true));
        let bytes = serde_json::to_vec(&value).unwrap();
        let parsed: core::result::Result<DelegationReceipt, serde_json::Error> =
            serde_json::from_slice(&bytes);
        assert!(
            parsed.is_err(),
            "unknown fields must reject (deny_unknown_fields)"
        );
    }

    #[test]
    fn nonce_round_trips_as_hex() {
        let receipt = mint([0xAB_u8; 16]);
        let bytes = receipt.canonical_bytes().unwrap();
        let s = core::str::from_utf8(bytes.as_bytes()).unwrap();
        // 16 bytes -> 32 hex chars.
        assert!(s.contains("\"nonce\":\"abababababababababababababababab\""));
    }

    #[test]
    fn aggregate_budget_projection_must_match_signed_link() {
        let mut receipt = mint([4_u8; 16]);
        receipt.aggregate_budget = Some(AggregateBudgetDelegationMarker {
            root_binding_digest: "00".repeat(32),
            max_invocations: 1,
        });

        assert!(receipt.canonical_bytes().is_err());
    }

    #[test]
    fn nonce_rejects_wrong_length_hex() {
        let receipt = mint([0xCD_u8; 16]);
        let mut value: serde_json::Value =
            serde_json::from_slice(receipt.canonical_bytes().unwrap().as_bytes()).unwrap();
        value.as_object_mut().unwrap().insert(
            "nonce".to_string(),
            serde_json::Value::String("dead".to_string()),
        );
        let bytes = serde_json::to_vec(&value).unwrap();
        let parsed: core::result::Result<DelegationReceipt, serde_json::Error> =
            serde_json::from_slice(&bytes);
        assert!(parsed.is_err(), "short nonce hex must reject");
    }

    #[test]
    fn complete_chain_appends_minted_link() {
        let receipt = mint([4_u8; 16]);
        let chain = receipt.complete_chain();
        assert_eq!(chain.len(), receipt.parent_chain.len() + 1);
        assert_eq!(
            chain.last().unwrap().signature.to_hex(),
            receipt.link.signature.to_hex()
        );
        assert_eq!(receipt.child_depth(), 1);
    }

    #[test]
    fn scope_attenuation_helpers_default_and_from_steps() {
        let empty = ScopeAttenuation::empty();
        assert!(empty.steps.is_empty());
        assert!(empty.child_expires_at.is_none());

        let from_steps = ScopeAttenuation::from_steps(vec![Attenuation::ShortenExpiry {
            new_expires_at: 1900,
        }]);
        assert_eq!(from_steps.steps.len(), 1);
        assert!(from_steps.child_expires_at.is_none());
    }
}

/// Hex-encoded 16-byte nonce serializer. Keeps the on-wire encoding
/// stable across `Vec<u8>` and `[u8; 16]` representations and rejects
/// any input whose length differs from 32 hex characters.
mod hex_nonce {
    use alloc::format;
    use alloc::string::String;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 16], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 16], D::Error> {
        let raw = String::deserialize(de)?;
        let mut out = [0_u8; 16];
        hex::decode_to_slice(raw.as_bytes(), &mut out).map_err(|err| {
            serde::de::Error::custom(format!("delegation receipt nonce hex decode: {err}"))
        })?;
        Ok(out)
    }
}
