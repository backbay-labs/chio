//! Production finding-recovery verifier backed by durable SQLite quota and
//! lineage state.

use chio_kernel::finding_recovery::{
    FindingRecoveryContextView, FindingRecoveryVerifier, VerifiedFindingRecovery,
};
use chio_open_market::recovery::{
    mint_verified_finding_recovery_grant, verify_finding_recovery_context,
    RecoveryVerificationAuthorities, RecoveryVerificationInputs, RecoveryVerificationOutcome,
};
use chio_store_sqlite::{
    FindingRecoveryIssuanceInput, FindingRecoveryReceiptLineageInput, SqliteFindingRecoveryStore,
};

pub struct MarketFindingRecoveryVerifier {
    authorities: RecoveryVerificationAuthorities,
    store: SqliteFindingRecoveryStore,
}

impl MarketFindingRecoveryVerifier {
    #[must_use]
    pub fn new(
        authorities: RecoveryVerificationAuthorities,
        store: SqliteFindingRecoveryStore,
    ) -> Self {
        Self { authorities, store }
    }

    fn verify(
        &self,
        view: &FindingRecoveryContextView<'_>,
    ) -> Result<RecoveryVerificationOutcome, String> {
        verify_finding_recovery_context(
            &RecoveryVerificationInputs {
                marker: view.marker,
                context_b64: view.context_b64,
                recovery_subject: &view.recovery_capability.subject,
                recovery_issuer: &view.recovery_capability.issuer,
                server_id: view.server_id,
                tool_name: view.tool_name,
                arguments: view.arguments,
                expected_output_digest: view.expected_output_digest,
            },
            &self.authorities,
        )
        .map_err(|error| error.to_string())
    }

    /// Persist the deterministic issuance before returning a newly minted
    /// recovery capability. Identical re-mints preserve the first issuance;
    /// changed bindings or retry ceilings reject.
    pub fn issue_verified(
        &self,
        verified: &RecoveryVerificationOutcome,
        max_recoveries: u32,
        issued_at: u64,
    ) -> Result<(), String> {
        self.store
            .issue(&FindingRecoveryIssuanceInput {
                recovery_id: verified.recovery_id(),
                finding_id: verified.finding_id(),
                listing_id: verified.listing_id(),
                original_capability_id: verified.original_capability_id(),
                original_delivery_receipt_id: verified.original_delivery_receipt_id(),
                purchase_key: verified.purchase_key(),
                original_subject_key_hex: &verified.original_subject().to_hex(),
                max_recoveries,
                issued_at,
            })
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Persist issuance before signing and returning a capability. A signing
    /// failure leaves a harmless issuance the same deterministic re-mint can
    /// adopt; a returned token always has its shared quota already stored.
    pub fn issue_and_mint(
        &self,
        verified: &RecoveryVerificationOutcome,
        issuer: &chio_core::crypto::Keypair,
        token_id: String,
        max_recoveries: u32,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<chio_core::capability::token::CapabilityToken, String> {
        if issuer.public_key() != self.authorities.recovery_authority {
            return Err("recovery issuer is not the pinned recovery authority".to_owned());
        }
        self.issue_verified(verified, max_recoveries, issued_at)?;
        mint_verified_finding_recovery_grant(
            verified,
            issuer,
            token_id,
            max_recoveries,
            issued_at,
            expires_at,
        )
        .map_err(|error| error.to_string())
    }
}

impl FindingRecoveryVerifier for MarketFindingRecoveryVerifier {
    fn verify_recovery(
        &self,
        view: &FindingRecoveryContextView<'_>,
    ) -> Result<VerifiedFindingRecovery, String> {
        let verified = self.verify(view)?;
        Ok(VerifiedFindingRecovery {
            recovery_id: verified.recovery_id().to_owned(),
            finding_id: verified.finding_id().to_owned(),
            listing_id: verified.listing_id().to_owned(),
            payload_sha256: verified.payload_sha256().to_owned(),
            original_capability_id: verified.original_capability_id().to_owned(),
            original_delivery_receipt_id: verified.original_delivery_receipt_id().to_owned(),
            purchase_key: verified.purchase_key().to_owned(),
            original_subject_key_hex: verified.original_subject().to_hex(),
        })
    }

    fn reserve_recovery_attempt(
        &self,
        verified: &VerifiedFindingRecovery,
        request_id: &str,
        max_recoveries: u32,
        now_unix_secs: u64,
    ) -> Result<(), String> {
        self.store
            .reserve_attempt(
                &verified.recovery_id,
                request_id,
                max_recoveries,
                now_unix_secs,
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn record_recovery_receipt(
        &self,
        verified: &VerifiedFindingRecovery,
        recovery_receipt_id: &str,
        recorded_at: u64,
    ) -> Result<(), String> {
        self.store
            .record_receipt_lineage(&FindingRecoveryReceiptLineageInput {
                recovery_receipt_id,
                recovery_id: &verified.recovery_id,
                original_delivery_receipt_id: &verified.original_delivery_receipt_id,
                purchase_key: &verified.purchase_key,
                recorded_at,
            })
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}
