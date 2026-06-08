use std::collections::BTreeSet;

use chio_federation::{bilateral_dsse::Keyid, bilateral_verifier::RevocationOracle};

#[derive(Debug, Clone)]
pub(crate) struct OfflineRevocationOracle {
    pub(crate) revoked_key_fingerprints: BTreeSet<String>,
}

impl RevocationOracle for OfflineRevocationOracle {
    fn is_active_at_epoch(&self, fingerprint: &Keyid, _epoch_height: u64) -> bool {
        !self.revoked_key_fingerprints.contains(&fingerprint.0)
    }
}
