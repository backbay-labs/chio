//! Demo-only federation helpers.
//!
//! Types in this module are for examples, fixtures, and tests only. Production
//! verifiers must wire a real [`RevocationOracle`] implementation.

use crate::bilateral_dsse::Keyid;
use crate::bilateral_verifier::RevocationOracle;

/// Demo-only revocation oracle that treats every passport key as active.
///
/// Do not use in production. Provide a real revocation source instead.
#[derive(Debug, Clone, Default)]
pub struct DemoAllowAllRevocationOracle;

impl RevocationOracle for DemoAllowAllRevocationOracle {
    fn is_active_at_epoch(&self, _fingerprint: &Keyid, _epoch_height: u64) -> bool {
        true
    }
}
