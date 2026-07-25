use std::sync::Arc;

use chio_core::crypto::Keypair;
use chio_fiscal::{
    FiscalGenesisPolicy, FiscalRuntimeAdapter, FiscalRuntimeAdapterRegistry,
    FiscalRuntimeReadinessBuilder, VerifiedFiscalRuntimeReadiness,
};

pub const FISCAL_TIER_LIMITS_ADAPTER_ID: &str = "fiscal.tier-limits";
pub const FISCAL_MARKETPLACE_DISCOUNT_ADAPTER_ID: &str = "fiscal.marketplace-discount";
pub const FISCAL_DECISION_PREMIUM_ADAPTER_ID: &str = "fiscal.decision-premium";
pub const FISCAL_INSURANCE_PREMIUM_ADAPTER_ID: &str = "fiscal.insurance-premium";
pub const FISCAL_OPEN_MARKET_SCHEDULE_ADAPTER_ID: &str = "fiscal.open-market-fee-bond";
pub const FISCAL_OPEN_MARKET_FEE_GATE_ID: &str = "fiscal.open-market-fee-issuance-gate";
pub const FISCAL_OPEN_MARKET_PENALTY_GATE_ID: &str = "fiscal.open-market-penalty-issuance-gate";

const REQUIRED_FISCAL_RUNTIME_INTEGRATIONS: [&str; 7] = [
    FISCAL_DECISION_PREMIUM_ADAPTER_ID,
    FISCAL_INSURANCE_PREMIUM_ADAPTER_ID,
    FISCAL_MARKETPLACE_DISCOUNT_ADAPTER_ID,
    FISCAL_OPEN_MARKET_SCHEDULE_ADAPTER_ID,
    FISCAL_OPEN_MARKET_FEE_GATE_ID,
    FISCAL_OPEN_MARKET_PENALTY_GATE_ID,
    FISCAL_TIER_LIMITS_ADAPTER_ID,
];

#[derive(Debug, thiserror::Error)]
pub enum FiscalRuntimeReadinessError {
    #[error("fiscal runtime integration set is incomplete or unexpected")]
    InvalidIntegrationSet,
    #[error("fiscal runtime integration `{id}` failed its self-test: {detail}")]
    SelfTest { id: String, detail: String },
    #[error("fiscal runtime readiness artifact is invalid: {0}")]
    Fiscal(#[from] chio_fiscal::FiscalError),
}

pub struct FiscalRuntimeIntegration {
    descriptor: FiscalRuntimeAdapter,
    self_test: Arc<dyn Fn() -> Result<(), String> + Send + Sync>,
}

impl FiscalRuntimeIntegration {
    pub fn new(
        id: impl Into<String>,
        implementation_version: impl Into<String>,
        self_test: impl Fn() -> Result<(), String> + Send + Sync + 'static,
    ) -> Result<Self, FiscalRuntimeReadinessError> {
        Ok(Self {
            descriptor: FiscalRuntimeAdapter::new(id.into(), implementation_version.into())?,
            self_test: Arc::new(self_test),
        })
    }
}

pub struct FiscalRuntimeAssembler {
    integrations: Vec<FiscalRuntimeIntegration>,
}

pub fn production_fiscal_runtime_assembler(
) -> Result<FiscalRuntimeAssembler, FiscalRuntimeReadinessError> {
    let version = env!("CARGO_PKG_VERSION");
    FiscalRuntimeAssembler::new(vec![
        FiscalRuntimeIntegration::new(FISCAL_TIER_LIMITS_ADAPTER_ID, version, || {
            chio_underwriting::self_test_fiscal_tier_limits_adapter()
        })?,
        FiscalRuntimeIntegration::new(FISCAL_MARKETPLACE_DISCOUNT_ADAPTER_ID, version, || {
            chio_appraisal::self_test_fiscal_marketplace_discount_adapter()
        })?,
        FiscalRuntimeIntegration::new(FISCAL_DECISION_PREMIUM_ADAPTER_ID, version, || {
            chio_underwriting::self_test_fiscal_decision_premium_adapter()
        })?,
        FiscalRuntimeIntegration::new(FISCAL_INSURANCE_PREMIUM_ADAPTER_ID, version, || {
            chio_underwriting::self_test_fiscal_insurance_premium_adapter()
        })?,
        FiscalRuntimeIntegration::new(FISCAL_OPEN_MARKET_SCHEDULE_ADAPTER_ID, version, || {
            chio_open_market::fiscal_adapter::self_test_fiscal_open_market_schedule_adapter()
        })?,
        FiscalRuntimeIntegration::new(FISCAL_OPEN_MARKET_FEE_GATE_ID, version, || {
            chio_open_market::fiscal_adapter::self_test_fiscal_open_market_fee_gate()
        })?,
        FiscalRuntimeIntegration::new(FISCAL_OPEN_MARKET_PENALTY_GATE_ID, version, || {
            chio_open_market::fiscal_adapter::self_test_fiscal_open_market_penalty_gate()
        })?,
    ])
}

impl FiscalRuntimeAssembler {
    pub fn new(
        mut integrations: Vec<FiscalRuntimeIntegration>,
    ) -> Result<Self, FiscalRuntimeReadinessError> {
        integrations.sort_by(|left, right| left.descriptor.id.cmp(&right.descriptor.id));
        let actual = integrations
            .iter()
            .map(|integration| integration.descriptor.id.as_str())
            .collect::<Vec<_>>();
        if actual.as_slice() != REQUIRED_FISCAL_RUNTIME_INTEGRATIONS {
            return Err(FiscalRuntimeReadinessError::InvalidIntegrationSet);
        }
        Ok(Self { integrations })
    }

    pub fn self_test_and_build_registry(
        &self,
        build_id: impl Into<String>,
        schema_version: impl Into<String>,
    ) -> Result<FiscalRuntimeAdapterRegistry, FiscalRuntimeReadinessError> {
        self.run_self_tests()?;
        Ok(FiscalRuntimeAdapterRegistry::new(
            build_id.into(),
            schema_version.into(),
            self.integrations
                .iter()
                .map(|integration| integration.descriptor.clone())
                .collect(),
        )?)
    }

    pub fn self_test_and_sign(
        &self,
        policy: &FiscalGenesisPolicy,
        anchor_key: &Keypair,
        readiness_sequence: u64,
        attested_at: u64,
        build_id: impl Into<String>,
        schema_version: impl Into<String>,
    ) -> Result<VerifiedFiscalRuntimeReadiness, FiscalRuntimeReadinessError> {
        let registry = self.self_test_and_build_registry(build_id, schema_version)?;
        let signed = FiscalRuntimeReadinessBuilder {
            readiness_sequence,
            runtime_registry: registry.clone(),
            attested_at,
        }
        .sign(policy, anchor_key)?;
        Ok(VerifiedFiscalRuntimeReadiness::verify(
            signed, policy, registry,
        )?)
    }

    fn run_self_tests(&self) -> Result<(), FiscalRuntimeReadinessError> {
        for integration in &self.integrations {
            (integration.self_test)().map_err(|detail| FiscalRuntimeReadinessError::SelfTest {
                id: integration.descriptor.id.clone(),
                detail,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chio_fiscal::FISCAL_RUNTIME_ADAPTER_COUNT;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn policy() -> TestResult<FiscalGenesisPolicy> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../spec/schemas/chio-fiscal/v1/fixtures/genesis-policy.positive.json");
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    fn integrations() -> TestResult<Vec<FiscalRuntimeIntegration>> {
        REQUIRED_FISCAL_RUNTIME_INTEGRATIONS
            .iter()
            .map(|id| FiscalRuntimeIntegration::new(*id, "1", || Ok(())).map_err(Into::into))
            .collect()
    }

    #[test]
    fn assembler_self_tests_all_seven_and_signs_the_exact_registry() -> TestResult {
        let assembler = FiscalRuntimeAssembler::new(integrations()?)?;
        let assembled =
            assembler.self_test_and_build_registry("build-1", "chio.fiscal.runtime.v1")?;
        let readiness = assembler.self_test_and_sign(
            &policy()?,
            &Keypair::from_seed(&[8; 32]),
            1,
            55,
            "build-1",
            "chio.fiscal.runtime.v1",
        )?;
        assert_eq!(
            readiness.runtime_registry().adapters().len(),
            FISCAL_RUNTIME_ADAPTER_COUNT
        );
        assert_eq!(
            readiness.body().runtime_registry_digest,
            readiness.runtime_registry().digest()?
        );
        assert_eq!(readiness.runtime_registry(), &assembled);
        Ok(())
    }

    #[test]
    fn assembler_rejects_missing_duplicate_and_failed_integrations() -> TestResult {
        let mut missing = integrations()?;
        missing.pop();
        assert!(matches!(
            FiscalRuntimeAssembler::new(missing),
            Err(FiscalRuntimeReadinessError::InvalidIntegrationSet)
        ));

        let mut duplicate = integrations()?;
        duplicate.pop();
        duplicate.push(FiscalRuntimeIntegration::new(
            REQUIRED_FISCAL_RUNTIME_INTEGRATIONS[0],
            "2",
            || Ok(()),
        )?);
        assert!(matches!(
            FiscalRuntimeAssembler::new(duplicate),
            Err(FiscalRuntimeReadinessError::InvalidIntegrationSet)
        ));

        let mut failing = integrations()?;
        let failed_id = failing[0].descriptor.id.clone();
        failing[0] = FiscalRuntimeIntegration::new(&failed_id, "1", || {
            Err("parity check failed".to_owned())
        })?;
        let assembler = FiscalRuntimeAssembler::new(failing)?;
        assert!(matches!(
            assembler.self_test_and_sign(
                &policy()?,
                &Keypair::from_seed(&[8; 32]),
                1,
                55,
                "build-1",
                "chio.fiscal.runtime.v1",
            ),
            Err(FiscalRuntimeReadinessError::SelfTest { id, .. }) if id == failed_id
        ));
        Ok(())
    }

    #[test]
    fn production_assembler_self_tests_every_installed_integration() -> TestResult {
        let registry = production_fiscal_runtime_assembler()?
            .self_test_and_build_registry("build-production", "chio.fiscal.runtime.v1")?;
        assert_eq!(
            registry
                .adapters()
                .iter()
                .map(|adapter| adapter.id.as_str())
                .collect::<Vec<_>>(),
            REQUIRED_FISCAL_RUNTIME_INTEGRATIONS
        );
        Ok(())
    }
}
