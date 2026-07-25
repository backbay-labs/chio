use super::*;

#[path = "trust/artifacts.rs"]
mod artifacts;
#[path = "trust/registry.rs"]
mod registry;
pub use artifacts::*;
pub use registry::*;

fn insert_unique<K: Ord, V>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    reason: &str,
) -> Result<(), CredentialError> {
    if map.insert(key, value).is_some() {
        return Err(authority_error(reason));
    }
    Ok(())
}

fn active_key<'a, T: HasTrustStatus>(
    entry: Option<&'a T>,
    reason: &str,
) -> Result<&'a T, CredentialError> {
    match entry {
        Some(entry) if entry.trust_status() == TrustedKeyStatusV2::Active => Ok(entry),
        _ => Err(authority_error(reason)),
    }
}

trait HasTrustStatus {
    fn trust_status(&self) -> TrustedKeyStatusV2;
}

macro_rules! impl_trust_status {
    ($($type:ty),+ $(,)?) => {
        $(impl HasTrustStatus for $type {
            fn trust_status(&self) -> TrustedKeyStatusV2 {
                self.status
            }
        })+
    };
}

impl_trust_status!(
    IssuerTrustKeyV2,
    VerifierTrustKeyV2,
    MigrationAttesterTrustKeyV2,
    LifecycleResolverTrustKeyV2,
    LifecycleGenerationAnchorTrustKeyV2,
    LifecycleHighWaterTrustKeyV2,
    LegacyIssuanceAnchorAuthorityTrustKeyV2,
);

pub(in crate::financial_authority) fn validate_epoch(
    field: &str,
    epoch: u64,
) -> Result<(), CredentialError> {
    if epoch == 0 || epoch > I_JSON_MAX_SAFE_INTEGER {
        return Err(authority_error(format!("{field} is invalid")));
    }
    Ok(())
}

fn normalize_strings(values: &mut Vec<String>, field: &str) -> Result<(), CredentialError> {
    for value in values.iter() {
        validate_text(field, value)?;
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn normalize_digests(values: &mut Vec<String>, field: &str) -> Result<(), CredentialError> {
    if values.is_empty() {
        return Err(authority_error(format!("{field} is empty")));
    }
    for value in values.iter() {
        validate_digest(field, value)?;
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn normalize_optional_digests(
    values: &mut Vec<String>,
    field: &str,
) -> Result<(), CredentialError> {
    for value in values.iter() {
        validate_digest(field, value)?;
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn validate_string_set(values: &BTreeSet<String>, field: &str) -> Result<(), CredentialError> {
    for value in values {
        validate_text(field, value)?;
    }
    Ok(())
}
