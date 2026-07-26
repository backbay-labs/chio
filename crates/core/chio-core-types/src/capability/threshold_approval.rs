use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::crypto::{sha256_hex, PublicKey};

const ELIGIBLE_SET_DOMAIN: &[u8] = b"chio.approver-set.v1\0";
pub const DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS: u64 = 900;
pub const MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS: u64 = 3_600;
pub const MAX_THRESHOLD_APPROVAL_TOKENS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdApproverIdentity {
    pub identifier: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdApprovalRequirement {
    pub policy_hash: String,
    pub threshold: u32,
    pub eligible_approvers: Vec<ThresholdApproverIdentity>,
    pub eligible_set_digest: String,
    pub directory_version: String,
    pub timeout_seconds: u64,
}

impl ThresholdApprovalRequirement {
    pub fn new(
        policy_hash: String,
        threshold: u32,
        mut eligible_approvers: Vec<ThresholdApproverIdentity>,
        directory_version: String,
        timeout_seconds: u64,
    ) -> Result<Self, String> {
        if !is_sha256_digest(&policy_hash) {
            return Err("threshold approval policy hash must be lowercase SHA-256 hex".to_string());
        }
        if directory_version.trim() != directory_version || directory_version.is_empty() {
            return Err("threshold approval directory version is invalid".to_string());
        }
        if timeout_seconds == 0 || timeout_seconds > MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS {
            return Err(format!(
                "threshold approval timeout must be between 1 and {MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS} seconds"
            ));
        }
        eligible_approvers.sort_by(|left, right| {
            (&left.identifier, left.public_key.to_hex())
                .cmp(&(&right.identifier, right.public_key.to_hex()))
        });
        if eligible_approvers.iter().any(|approver| {
            approver.identifier.is_empty()
                || approver.identifier.trim() != approver.identifier
                || approver.identifier.chars().any(char::is_control)
        }) {
            return Err(
                "threshold approval identifiers must be non-empty canonical text".to_string(),
            );
        }
        if eligible_approvers
            .windows(2)
            .any(|pair| pair[0].identifier == pair[1].identifier)
        {
            return Err("threshold approval identifiers must be unique".to_string());
        }
        if eligible_approvers.len() > MAX_THRESHOLD_APPROVAL_TOKENS {
            return Err(format!(
                "threshold approval eligible set exceeds {MAX_THRESHOLD_APPROVAL_TOKENS} approvers"
            ));
        }
        let mut key_fingerprints = eligible_approvers
            .iter()
            .map(|approver| approver.public_key.to_hex())
            .collect::<Vec<_>>();
        key_fingerprints.sort();
        if key_fingerprints.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("threshold approval public keys must be unique".to_string());
        }
        let approver_count = u32::try_from(eligible_approvers.len())
            .map_err(|_| "threshold approval set is too large".to_string())?;
        if threshold == 0 || threshold > approver_count {
            return Err("threshold approval quorum is outside the eligible set".to_string());
        }
        let canonical = canonical_json_bytes(&eligible_approvers)
            .map_err(|error| format!("threshold approval set is not canonical: {error}"))?;
        let mut preimage = Vec::with_capacity(ELIGIBLE_SET_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(ELIGIBLE_SET_DOMAIN);
        preimage.extend_from_slice(&canonical);
        let eligible_set_digest = sha256_hex(&preimage);
        Ok(Self {
            policy_hash,
            threshold,
            eligible_approvers,
            eligible_set_digest,
            directory_version,
            timeout_seconds,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        let reconstructed = Self::new(
            self.policy_hash.clone(),
            self.threshold,
            self.eligible_approvers.clone(),
            self.directory_version.clone(),
            self.timeout_seconds,
        )?;
        if &reconstructed == self {
            Ok(())
        } else {
            Err("threshold approval requirement is not canonical".to_string())
        }
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn approver(identifier: &str, keypair: &Keypair) -> ThresholdApproverIdentity {
        ThresholdApproverIdentity {
            identifier: identifier.to_string(),
            public_key: keypair.public_key(),
        }
    }

    #[test]
    fn eligible_set_digest_is_order_independent() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let first = ThresholdApprovalRequirement::new(
            "a".repeat(64),
            2,
            vec![approver("bob", &bob), approver("alice", &alice)],
            "directory-v1".to_string(),
            DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS,
        )
        .unwrap();
        let second = ThresholdApprovalRequirement::new(
            "a".repeat(64),
            2,
            vec![approver("alice", &alice), approver("bob", &bob)],
            "directory-v1".to_string(),
            DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS,
        )
        .unwrap();

        assert_eq!(first, second);
        first.validate().unwrap();
    }

    #[test]
    fn duplicate_keys_and_invalid_quorums_reject() {
        let signer = Keypair::generate();
        assert!(ThresholdApprovalRequirement::new(
            "b".repeat(64),
            1,
            vec![approver("alice", &signer), approver("bob", &signer)],
            "directory-v1".to_string(),
            DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS,
        )
        .is_err());
        assert!(ThresholdApprovalRequirement::new(
            "b".repeat(64),
            2,
            vec![approver("alice", &signer)],
            "directory-v1".to_string(),
            DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS,
        )
        .is_err());
    }

    #[test]
    fn oversized_eligible_set_rejects() {
        let approvers = (0..=MAX_THRESHOLD_APPROVAL_TOKENS)
            .map(|index| {
                let keypair = Keypair::generate();
                approver(&format!("approver-{index}"), &keypair)
            })
            .collect();

        let error = ThresholdApprovalRequirement::new(
            "c".repeat(64),
            1,
            approvers,
            "directory-v1".to_string(),
            DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS,
        )
        .unwrap_err();

        assert!(error.contains("exceeds 32 approvers"));
    }
}
