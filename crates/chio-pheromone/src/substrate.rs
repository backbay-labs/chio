use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use crate::validation::{commit_admission_state, strength_at};
use crate::{
    newcomer_discount_for_deposit, validate_deposit_for_admission, DepositQuery,
    PheromoneConcentration, PheromoneDeposit, PheromoneError, PheromoneValidationContext,
    PHEROMONE_CONCENTRATION_SCHEMA,
};

pub trait PheromoneSubstrate {
    fn deposit(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
    ) -> Result<(), PheromoneError>;

    fn query_deposits(&self, query: &DepositQuery)
        -> Result<Vec<PheromoneDeposit>, PheromoneError>;

    fn query_concentration(
        &self,
        subject_class: &str,
        subject_class_namespace: &str,
        now_unix_ms: u64,
        reputation_epoch: u64,
        context: &PheromoneValidationContext,
        peer_weight: &dyn Fn(&str, u64) -> f64,
    ) -> Result<PheromoneConcentration, PheromoneError>;

    fn gc_evaporated(&self, now_unix_ms: u64) -> Result<usize, PheromoneError>;
}

pub(crate) type ScarcityBucketKey = (u64, String, String, String, String);
pub(crate) type PairBucketKey = (u64, String, String, String, String, String, String);
pub(crate) type PassportCapKey = (u64, String, String, String, String, String);

#[derive(Debug, Default)]
pub struct InMemoryPheromoneSubstrate {
    deposits: Mutex<Vec<PheromoneDeposit>>,
    seen_nonces: Mutex<BTreeSet<(String, String, String)>>,
    scarcity_buckets: Mutex<BTreeMap<ScarcityBucketKey, u64>>,
    pair_counts: Mutex<BTreeMap<PairBucketKey, u64>>,
    passports_by_kernel_class: Mutex<BTreeMap<PassportCapKey, BTreeSet<String>>>,
}

impl InMemoryPheromoneSubstrate {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl PheromoneSubstrate for InMemoryPheromoneSubstrate {
    fn deposit(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
    ) -> Result<(), PheromoneError> {
        validate_deposit_for_admission(&deposit, context)?;
        commit_admission_state(
            &deposit,
            &self.seen_nonces,
            context,
            &self.scarcity_buckets,
            &self.pair_counts,
            &self.passports_by_kernel_class,
        )?;
        self.deposits.lock()?.push(deposit);
        Ok(())
    }

    fn query_deposits(
        &self,
        query: &DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, PheromoneError> {
        let guard = self.deposits.lock()?;
        Ok(guard
            .iter()
            .filter(|deposit| {
                query
                    .subject_class
                    .as_deref()
                    .map(|value| value == deposit.body.subject_class)
                    .unwrap_or(true)
            })
            .filter(|deposit| {
                query
                    .treaty_id
                    .as_deref()
                    .map(|value| {
                        deposit
                            .body
                            .treaty_scope
                            .iter()
                            .any(|treaty| treaty == value)
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect())
    }

    fn query_concentration(
        &self,
        subject_class: &str,
        subject_class_namespace: &str,
        now_unix_ms: u64,
        reputation_epoch: u64,
        context: &PheromoneValidationContext,
        peer_weight: &dyn Fn(&str, u64) -> f64,
    ) -> Result<PheromoneConcentration, PheromoneError> {
        if !context.known_reputation_epochs.contains(&reputation_epoch) {
            return Err(PheromoneError::UnknownReputationEpoch(reputation_epoch));
        }
        let guard = self.deposits.lock()?;
        let mut total_strength = 0.0;
        let mut unweighted_total_strength = 0.0;
        let mut peak_confidence = 0.0;
        let mut origins = BTreeSet::new();
        let mut treaties = BTreeSet::new();
        for deposit in guard.iter().filter(|deposit| {
            deposit.body.subject_class == subject_class
                && deposit.body.subject_class_namespace == subject_class_namespace
        }) {
            let strength = strength_at(deposit, now_unix_ms);
            if let Some(floor) = deposit.body.evaporation_floor {
                if strength < floor {
                    continue;
                }
            }
            let weight = peer_weight(&deposit.body.kernel_id, reputation_epoch);
            if !weight.is_finite() || !(0.0..=1.0).contains(&weight) {
                return Err(PheromoneError::WeightOutOfRange(format!(
                    "weight for {} at epoch {} was {}",
                    deposit.body.kernel_id, reputation_epoch, weight
                )));
            }
            let discount = newcomer_discount_for_deposit(
                deposit,
                context,
                reputation_epoch,
                subject_class_namespace,
                subject_class,
            )?;
            total_strength += strength * weight * discount;
            unweighted_total_strength += strength;
            if deposit.body.confidence > peak_confidence {
                peak_confidence = deposit.body.confidence;
            }
            origins.insert((
                deposit.body.kernel_id.clone(),
                deposit.body.agent_passport_key_hash.clone(),
            ));
            for treaty in &deposit.body.treaty_scope {
                treaties.insert(treaty.clone());
            }
        }
        Ok(PheromoneConcentration {
            schema: PHEROMONE_CONCENTRATION_SCHEMA.to_string(),
            subject_class: subject_class.to_string(),
            subject_class_namespace: subject_class_namespace.to_string(),
            total_strength,
            unweighted_total_strength,
            distinct_origin_pairs: origins.len() as u64,
            peak_confidence,
            reputation_epoch,
            evaluated_at_unix_ms: now_unix_ms,
            treaty_scopes: treaties.into_iter().collect(),
        })
    }

    fn gc_evaporated(&self, now_unix_ms: u64) -> Result<usize, PheromoneError> {
        let mut guard = self.deposits.lock()?;
        let before = guard.len();
        guard.retain(|deposit| {
            let floor = deposit.body.evaporation_floor.unwrap_or(0.01);
            strength_at(deposit, now_unix_ms) >= floor
        });
        Ok(before.saturating_sub(guard.len()))
    }
}
