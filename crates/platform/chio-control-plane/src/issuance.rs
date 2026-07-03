mod attestation;
mod authority;
mod reputation;
mod scope;
mod types;
mod util;

pub use self::authority::wrap_capability_authority;
pub use self::reputation::{
    build_local_reputation_corpus, build_local_reputation_corpus_with_read_context,
};
pub use self::types::{
    ImportedTrustReport, LocalReputationInspection, LocalReputationTierView, ProbationaryStatus,
    ReputationScoringSource,
};

pub(crate) use self::reputation::{
    inspect_local_reputation, inspect_local_reputation_with_read_context,
};

#[cfg(test)]
use self::attestation::verify_runtime_attestation_for_issuance;
#[cfg(test)]
use self::util::unix_now;

#[cfg(test)]
mod tests;
