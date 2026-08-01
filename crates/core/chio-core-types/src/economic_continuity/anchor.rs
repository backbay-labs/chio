use super::*;

mod query;
pub use query::*;
mod effect;
pub use effect::*;

pub const CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA: &str = "chio.economy.anchor-view.v1";
pub const CHIO_ECONOMIC_EFFECT_DISPATCH_COMMIT_SCHEMA: &str =
    "chio.economy.effect-dispatch-commit.v1";

const VIEW_HEADS_ROOT_DOMAIN: &str = "chio.economy.anchor-view.heads-root.v1";
const VIEW_REPLAYS_ROOT_DOMAIN: &str = "chio.economy.anchor-view.replays-root.v1";
const VIEW_SIGNING_DOMAIN: &str = "CHIO-ECONOMIC-STATE-ANCHOR-VIEW-V1";
const DISPATCH_COMMIT_ID_DOMAIN: &str = "chio.economy.effect-dispatch-commit.id.v1";
const DISPATCH_COMMIT_SIGNING_DOMAIN: &str = "CHIO-ECONOMIC-EFFECT-DISPATCH-COMMIT-V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicStateAnchorError {
    Continuity(EconomicContinuityError),
    UnsupportedSchema { field: &'static str, value: String },
    PinMismatch(&'static str),
    InvalidView(&'static str),
    InvalidSignature,
    CurrentHeadMissing(EconomicResourceKeyV1),
    CurrentAbsenceMissing(EconomicResourceKeyV1),
    CurrentRequestMissing(EconomicRequestKeyV1),
    TransitionProofRejected(EconomicResourceKeyV1),
    AuthorizationMismatch(EconomicResourceKeyV1),
    RequestReplayConflict(EconomicRequestKeyV1),
    RequestReplayRetained(EconomicRequestKeyV1),
    AdmissionHandoffRejected,
    EffectDispatchRejected(&'static str),
    EffectCancellationRejected(&'static str),
    CompletedEffectRejected(&'static str),
    TargetStatusRejected,
    IdempotentRecoveryRejected,
    Missing,
    Unavailable(String),
    Canonicalization(String),
}

impl fmt::Display for EconomicStateAnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continuity(error) => write!(formatter, "{error}"),
            Self::UnsupportedSchema { field, value } => {
                write!(
                    formatter,
                    "unsupported economic anchor {field} schema `{value}`"
                )
            }
            Self::PinMismatch(field) => {
                write!(formatter, "economic anchor pin mismatch on `{field}`")
            }
            Self::InvalidView(reason) => {
                write!(formatter, "invalid economic anchor view: {reason}")
            }
            Self::InvalidSignature => write!(formatter, "economic anchor signature is invalid"),
            Self::CurrentHeadMissing(key) => {
                write!(
                    formatter,
                    "economic anchor view omitted current head {key:?}"
                )
            }
            Self::CurrentAbsenceMissing(key) => {
                write!(
                    formatter,
                    "economic anchor view omitted absence proof {key:?}"
                )
            }
            Self::CurrentRequestMissing(key) => {
                write!(
                    formatter,
                    "economic anchor view omitted request replay proof {key:?}"
                )
            }
            Self::TransitionProofRejected(key) => {
                write!(
                    formatter,
                    "economic transition proof was rejected for {key:?}"
                )
            }
            Self::AuthorizationMismatch(key) => {
                write!(
                    formatter,
                    "economic transition authorization mismatch for {key:?}"
                )
            }
            Self::RequestReplayConflict(key) => {
                write!(formatter, "economic request replay conflicts for {key:?}")
            }
            Self::RequestReplayRetained(key) => {
                write!(
                    formatter,
                    "economic request replay is already retained for {key:?}"
                )
            }
            Self::AdmissionHandoffRejected => {
                write!(formatter, "economic admission handoff was rejected")
            }
            Self::EffectDispatchRejected(reason) => {
                write!(formatter, "economic effect dispatch was rejected: {reason}")
            }
            Self::EffectCancellationRejected(reason) => {
                write!(
                    formatter,
                    "economic effect cancellation was rejected: {reason}"
                )
            }
            Self::CompletedEffectRejected(reason) => {
                write!(
                    formatter,
                    "completed economic effect was rejected: {reason}"
                )
            }
            Self::TargetStatusRejected => write!(formatter, "economic target status was rejected"),
            Self::IdempotentRecoveryRejected => {
                write!(formatter, "economic idempotent recovery was rejected")
            }
            Self::Missing => write!(formatter, "economic anchor state is missing"),
            Self::Unavailable(error) => {
                write!(formatter, "economic anchor is unavailable: {error}")
            }
            Self::Canonicalization(error) => {
                write!(
                    formatter,
                    "economic anchor canonicalization failed: {error}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EconomicStateAnchorError {}

impl From<EconomicContinuityError> for EconomicStateAnchorError {
    fn from(error: EconomicContinuityError) -> Self {
        Self::Continuity(error)
    }
}

#[derive(Debug, Clone)]
pub struct EconomicStateAnchorPins {
    pub anchor_id: String,
    pub namespace: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub signer_public_key: PublicKey,
}

impl EconomicStateAnchorPins {
    pub fn validate(&self) -> Result<(), EconomicStateAnchorError> {
        validate_identifier("anchor_id", &self.anchor_id)?;
        validate_identifier("namespace", &self.namespace)?;
        validate_identifier("signer_key_id", &self.signer_key_id)?;
        validate_positive("signer_key_epoch", self.signer_key_epoch)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicRequestKeyV1 {
    pub request_namespace_digest: String,
    pub request_id: String,
}

impl EconomicRequestKeyV1 {
    pub fn validate(&self) -> Result<(), EconomicStateAnchorError> {
        validate_digest("request_namespace_digest", &self.request_namespace_digest)?;
        validate_text("request_id", &self.request_id, MAX_REQUEST_ID_BYTES)?;
        Ok(())
    }
}

impl EconomicRequestBindingV1 {
    pub fn key(&self) -> EconomicRequestKeyV1 {
        EconomicRequestKeyV1 {
            request_namespace_digest: self.request_namespace_digest.clone(),
            request_id: self.request_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicStateAnchorViewV1 {
    pub schema: String,
    pub anchor_id: String,
    pub namespace: String,
    pub checkpoint_sequence: u64,
    pub checkpoint_digest: String,
    pub heads_root: String,
    pub heads: Vec<EconomicResourceHeadV1>,
    pub absent_resource_keys: Vec<EconomicResourceKeyV1>,
    pub request_replays_root: String,
    pub request_replays: Vec<EconomicRequestReplayV1>,
    pub absent_request_keys: Vec<EconomicRequestKeyV1>,
    pub observed_at: u64,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub anchor_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EconomicStateAnchorViewSigningPreimage<'a> {
    schema: &'a str,
    anchor_id: &'a str,
    namespace: &'a str,
    checkpoint_sequence: u64,
    checkpoint_digest: &'a str,
    heads_root: &'a str,
    heads: &'a [EconomicResourceHeadV1],
    absent_resource_keys: &'a [EconomicResourceKeyV1],
    request_replays_root: &'a str,
    request_replays: &'a [EconomicRequestReplayV1],
    absent_request_keys: &'a [EconomicRequestKeyV1],
    observed_at: u64,
    signer_key_id: &'a str,
    signer_key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EconomicViewHeadRootEntry<'a> {
    resource_key: &'a EconomicResourceKeyV1,
    head_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EconomicViewReplayRootEntry<'a> {
    request_key: EconomicRequestKeyV1,
    request_binding_digest: &'a str,
    operation_id: &'a str,
    effect_slot_ids: &'a [String],
}

impl EconomicStateAnchorViewV1 {
    pub fn seal(&mut self, keypair: &Keypair) -> Result<(), EconomicStateAnchorError> {
        self.validate_body(false)?;
        self.heads_root = view_heads_root(&self.heads)?;
        self.request_replays_root = view_replays_root(&self.request_replays)?;
        self.anchor_signature = keypair.sign(&self.signing_bytes()?).to_hex();
        self.validate()
    }

    pub fn validate(&self) -> Result<(), EconomicStateAnchorError> {
        self.validate_body(true)?;
        validate_fixed_hex("anchor_signature", &self.anchor_signature, 128)?;
        if view_heads_root(&self.heads)? != self.heads_root {
            return Err(EconomicStateAnchorError::InvalidView("heads root mismatch"));
        }
        if view_replays_root(&self.request_replays)? != self.request_replays_root {
            return Err(EconomicStateAnchorError::InvalidView(
                "request replay root mismatch",
            ));
        }
        Ok(())
    }

    pub fn verify(&self, pins: &EconomicStateAnchorPins) -> Result<(), EconomicStateAnchorError> {
        self.validate()?;
        pins.validate()?;
        if self.anchor_id != pins.anchor_id {
            return Err(EconomicStateAnchorError::PinMismatch("anchor_id"));
        }
        if self.namespace != pins.namespace {
            return Err(EconomicStateAnchorError::PinMismatch("namespace"));
        }
        if self.signer_key_id != pins.signer_key_id {
            return Err(EconomicStateAnchorError::PinMismatch("signer_key_id"));
        }
        if self.signer_key_epoch != pins.signer_key_epoch {
            return Err(EconomicStateAnchorError::PinMismatch("signer_key_epoch"));
        }
        let signature = Signature::from_hex(&self.anchor_signature)
            .map_err(|_| EconomicStateAnchorError::InvalidSignature)?;
        if pins
            .signer_public_key
            .verify(&self.signing_bytes()?, &signature)
        {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::InvalidSignature)
        }
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, EconomicStateAnchorError> {
        prefixed_canonical(VIEW_SIGNING_DOMAIN, &self.signing_preimage()).map_err(Into::into)
    }

    pub fn head(&self, key: &EconomicResourceKeyV1) -> Option<&EconomicResourceHeadV1> {
        self.heads
            .binary_search_by(|head| head.resource_key.cmp(key))
            .ok()
            .map(|index| &self.heads[index])
    }

    pub fn proves_resource_absent(&self, key: &EconomicResourceKeyV1) -> bool {
        self.absent_resource_keys.binary_search(key).is_ok()
    }

    pub fn request_replay(&self, key: &EconomicRequestKeyV1) -> Option<&EconomicRequestReplayV1> {
        self.request_replays
            .binary_search_by(|replay| replay.request.key().cmp(key))
            .ok()
            .map(|index| &self.request_replays[index])
    }

    pub fn proves_request_absent(&self, key: &EconomicRequestKeyV1) -> bool {
        self.absent_request_keys.binary_search(key).is_ok()
    }

    fn validate_body(&self, roots_required: bool) -> Result<(), EconomicStateAnchorError> {
        if self.schema != CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA {
            return Err(EconomicStateAnchorError::UnsupportedSchema {
                field: "view",
                value: self.schema.clone(),
            });
        }
        validate_identifier("anchor_id", &self.anchor_id)?;
        validate_identifier("namespace", &self.namespace)?;
        validate_positive("checkpoint_sequence", self.checkpoint_sequence)?;
        validate_digest("checkpoint_digest", &self.checkpoint_digest)?;
        if roots_required {
            validate_digest("heads_root", &self.heads_root)?;
            validate_digest("request_replays_root", &self.request_replays_root)?;
        }
        if self.heads.len() + self.absent_resource_keys.len() > MAX_ECONOMIC_TRANSITIONS {
            return Err(EconomicStateAnchorError::InvalidView(
                "resource query exceeds the bound",
            ));
        }
        if !self
            .heads
            .windows(2)
            .all(|pair| pair[0].resource_key < pair[1].resource_key)
        {
            return Err(EconomicStateAnchorError::InvalidView(
                "heads must be sorted and unique",
            ));
        }
        if !self
            .absent_resource_keys
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(EconomicStateAnchorError::InvalidView(
                "absent resource keys must be sorted and unique",
            ));
        }
        for head in &self.heads {
            head.validate()?;
            if head.anchor_id != self.anchor_id || head.namespace != self.namespace {
                return Err(EconomicStateAnchorError::InvalidView(
                    "head anchor binding mismatch",
                ));
            }
            if self.proves_resource_absent(&head.resource_key) {
                return Err(EconomicStateAnchorError::InvalidView(
                    "resource is both present and absent",
                ));
            }
        }
        for key in &self.absent_resource_keys {
            key.validate()?;
        }
        if self.request_replays.len() + self.absent_request_keys.len() > MAX_ECONOMIC_TRANSITIONS {
            return Err(EconomicStateAnchorError::InvalidView(
                "request query exceeds the bound",
            ));
        }
        if !self
            .request_replays
            .windows(2)
            .all(|pair| pair[0].request.key() < pair[1].request.key())
        {
            return Err(EconomicStateAnchorError::InvalidView(
                "request replays must be sorted and unique",
            ));
        }
        if !self
            .absent_request_keys
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(EconomicStateAnchorError::InvalidView(
                "absent request keys must be sorted and unique",
            ));
        }
        for replay in &self.request_replays {
            replay.validate()?;
            if self.proves_request_absent(&replay.request.key()) {
                return Err(EconomicStateAnchorError::InvalidView(
                    "request is both present and absent",
                ));
            }
        }
        for key in &self.absent_request_keys {
            key.validate()?;
        }
        validate_positive("observed_at", self.observed_at)?;
        validate_identifier("signer_key_id", &self.signer_key_id)?;
        validate_positive("signer_key_epoch", self.signer_key_epoch)?;
        Ok(())
    }

    fn signing_preimage(&self) -> EconomicStateAnchorViewSigningPreimage<'_> {
        EconomicStateAnchorViewSigningPreimage {
            schema: &self.schema,
            anchor_id: &self.anchor_id,
            namespace: &self.namespace,
            checkpoint_sequence: self.checkpoint_sequence,
            checkpoint_digest: &self.checkpoint_digest,
            heads_root: &self.heads_root,
            heads: &self.heads,
            absent_resource_keys: &self.absent_resource_keys,
            request_replays_root: &self.request_replays_root,
            request_replays: &self.request_replays,
            absent_request_keys: &self.absent_request_keys,
            observed_at: self.observed_at,
            signer_key_id: &self.signer_key_id,
            signer_key_epoch: self.signer_key_epoch,
        }
    }
}

fn view_heads_root(heads: &[EconomicResourceHeadV1]) -> Result<String, EconomicStateAnchorError> {
    let entries = heads
        .iter()
        .map(|head| {
            Ok(EconomicViewHeadRootEntry {
                resource_key: &head.resource_key,
                head_digest: head.digest()?,
            })
        })
        .collect::<Result<Vec<_>, EconomicStateAnchorError>>()?;
    domain_digest(VIEW_HEADS_ROOT_DOMAIN, &entries).map_err(Into::into)
}

fn view_replays_root(
    replays: &[EconomicRequestReplayV1],
) -> Result<String, EconomicStateAnchorError> {
    let entries = replays
        .iter()
        .map(|replay| EconomicViewReplayRootEntry {
            request_key: replay.request.key(),
            request_binding_digest: &replay.request.request_binding_digest,
            operation_id: &replay.operation_id,
            effect_slot_ids: &replay.effect_slot_ids,
        })
        .collect::<Vec<_>>();
    domain_digest(VIEW_REPLAYS_ROOT_DOMAIN, &entries).map_err(Into::into)
}

#[derive(Debug, Clone)]
pub struct VerifiedEconomicStateView {
    view: EconomicStateAnchorViewV1,
}

impl VerifiedEconomicStateView {
    pub fn view(&self) -> &EconomicStateAnchorViewV1 {
        &self.view
    }
}

pub fn verify_economic_state_view(
    view: EconomicStateAnchorViewV1,
    pins: &EconomicStateAnchorPins,
) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
    view.verify(pins)?;
    Ok(VerifiedEconomicStateView { view })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicTransitionAuthorizationV1 {
    Direct,
    NOfM { frost: EconomicFrostBindingV1 },
}

pub trait EconomicTransitionProofVerifier: Send + Sync {
    fn verify_transition(
        &self,
        current: Option<&EconomicResourceHeadV1>,
        transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError>;

    fn verify_batch(
        &self,
        current: &VerifiedEconomicStateView,
        batch: &EconomicStateBatchV1,
    ) -> Result<Vec<EconomicTransitionAuthorizationV1>, EconomicStateAnchorError> {
        batch
            .transitions
            .iter()
            .map(|transition| {
                self.verify_transition(current.view().head(&transition.resource_key), transition)
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct VerifiedEconomicStateBatchAdvance {
    current: VerifiedEconomicStateView,
    batch: EconomicStateBatchV1,
}

impl VerifiedEconomicStateBatchAdvance {
    pub fn current(&self) -> &VerifiedEconomicStateView {
        &self.current
    }

    pub fn batch(&self) -> &EconomicStateBatchV1 {
        &self.batch
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QualifiedGenericEconomicStateBatchAdvance<'a> {
    advance: &'a VerifiedEconomicStateBatchAdvance,
}

impl<'a> QualifiedGenericEconomicStateBatchAdvance<'a> {
    pub const fn advance(self) -> &'a VerifiedEconomicStateBatchAdvance {
        self.advance
    }
}

pub fn qualify_generic_economic_state_batch_advance(
    advance: &VerifiedEconomicStateBatchAdvance,
) -> Result<QualifiedGenericEconomicStateBatchAdvance<'_>, EconomicStateAnchorError> {
    for transition in &advance.batch.transitions {
        if transition.resource_key.resource_family != "effect_slot" {
            continue;
        }
        let current_slot = advance
            .current
            .view
            .head(&transition.resource_key)
            .map(economic_effect_slot_from_head)
            .transpose()?;
        let next_slot = economic_effect_slot_from_head(&transition.next_head)?;
        if next_slot.state == EconomicEffectStateV1::NoEffect {
            return Err(EconomicStateAnchorError::EffectCancellationRejected(
                "no-effect transitions require the typed cancellation CAS",
            ));
        }
        if current_slot.is_some() || next_slot.state != EconomicEffectStateV1::Ready {
            return Err(EconomicStateAnchorError::EffectDispatchRejected(
                "retained effect-slot transitions require a typed CAS",
            ));
        }
    }
    Ok(QualifiedGenericEconomicStateBatchAdvance { advance })
}

#[derive(Debug, Clone, Copy)]
pub struct QualifiedEconomicEffectUnknownAdvance<'a> {
    advance: &'a VerifiedEconomicStateBatchAdvance,
}

impl<'a> QualifiedEconomicEffectUnknownAdvance<'a> {
    pub const fn advance(self) -> &'a VerifiedEconomicStateBatchAdvance {
        self.advance
    }
}

pub fn qualify_economic_effect_unknown_advance(
    advance: &VerifiedEconomicStateBatchAdvance,
) -> Result<QualifiedEconomicEffectUnknownAdvance<'_>, EconomicStateAnchorError> {
    if advance.batch.transitions.len() != 1
        || !advance.batch.effect_slots.is_empty()
        || !advance.batch.request_replays.is_empty()
        || advance.batch.transitions[0].prepared_effect.is_some()
    {
        return Err(EconomicStateAnchorError::EffectDispatchRejected(
            "unknown recovery must advance exactly one retained effect slot",
        ));
    }
    let transition = &advance.batch.transitions[0];
    if transition.resource_key.resource_family != "effect_slot" {
        return Err(EconomicStateAnchorError::EffectDispatchRejected(
            "unknown recovery transition is not an effect slot",
        ));
    }
    let current_head = advance
        .current
        .view
        .head(&transition.resource_key)
        .ok_or_else(|| {
            EconomicStateAnchorError::CurrentHeadMissing(transition.resource_key.clone())
        })?;
    let current_slot = economic_effect_slot_from_head(current_head)?;
    let next_slot = economic_effect_slot_from_head(&transition.next_head)?;
    current_slot.validate_successor(&next_slot)?;
    if current_slot.state != EconomicEffectStateV1::DispatchCommitted
        || next_slot.state != EconomicEffectStateV1::Unknown
        || transition.next_head.lifecycle_state != "unknown"
        || advance.batch.operation_id.as_deref() != Some(next_slot.operation_id.as_str())
    {
        return Err(EconomicStateAnchorError::EffectDispatchRejected(
            "effect slot did not enter unknown from dispatch_committed",
        ));
    }
    Ok(QualifiedEconomicEffectUnknownAdvance { advance })
}

pub fn verify_economic_state_batch_advance(
    current: &VerifiedEconomicStateView,
    batch: EconomicStateBatchV1,
    pins: &EconomicStateAnchorPins,
    verifier: &dyn EconomicTransitionProofVerifier,
) -> Result<VerifiedEconomicStateBatchAdvance, EconomicStateAnchorError> {
    current.view.verify(pins)?;
    batch.verify_signature(&pins.signer_public_key)?;
    verify_batch_pins(&batch, pins)?;
    let expected_sequence = current.view.checkpoint_sequence.checked_add(1).ok_or(
        EconomicStateAnchorError::InvalidView("checkpoint sequence overflow"),
    )?;
    if batch.checkpoint_sequence != expected_sequence
        || batch.previous_checkpoint_digest.as_deref()
            != Some(current.view.checkpoint_digest.as_str())
    {
        return Err(EconomicStateAnchorError::InvalidView(
            "batch checkpoint predecessor mismatch",
        ));
    }
    for transition in &batch.transitions {
        let prior = current.view.head(&transition.resource_key);
        match (prior, transition.expected_head_digest.as_deref()) {
            (Some(head), Some(expected)) => {
                if head.digest()? != expected {
                    return Err(EconomicStateAnchorError::CurrentHeadMissing(
                        transition.resource_key.clone(),
                    ));
                }
                head.validate_successor(&transition.next_head)?;
            }
            (None, None)
                if current
                    .view
                    .proves_resource_absent(&transition.resource_key) => {}
            (None, None) => {
                return Err(EconomicStateAnchorError::CurrentAbsenceMissing(
                    transition.resource_key.clone(),
                ))
            }
            _ => {
                return Err(EconomicStateAnchorError::CurrentHeadMissing(
                    transition.resource_key.clone(),
                ))
            }
        }
    }
    let authorizations = verifier.verify_batch(current, &batch)?;
    if authorizations.len() != batch.transitions.len() {
        return Err(EconomicStateAnchorError::InvalidView(
            "transition authorization count mismatch",
        ));
    }
    for (transition, authorization) in batch.transitions.iter().zip(&authorizations) {
        verify_transition_authorization(transition, authorization)?;
    }
    for replay in &batch.request_replays {
        if matches!(
            verify_economic_request_replay(current, replay)?,
            EconomicRequestReplayDisposition::Retained(_)
        ) {
            return Err(EconomicStateAnchorError::RequestReplayRetained(
                replay.request.key(),
            ));
        }
    }
    Ok(VerifiedEconomicStateBatchAdvance {
        current: current.clone(),
        batch,
    })
}

pub fn reverify_economic_state_batch_advance(
    advance: &VerifiedEconomicStateBatchAdvance,
    pins: &EconomicStateAnchorPins,
    verifier: &dyn EconomicTransitionProofVerifier,
) -> Result<(), EconomicStateAnchorError> {
    verify_economic_state_batch_advance(
        advance.current(),
        advance.batch().clone(),
        pins,
        verifier,
    )?;
    Ok(())
}

pub fn verify_economic_state_batch_commit(
    advance: &VerifiedEconomicStateBatchAdvance,
    committed: &VerifiedEconomicStateView,
    pins: &EconomicStateAnchorPins,
) -> Result<(), EconomicStateAnchorError> {
    committed.view.verify(pins)?;
    if committed.view.checkpoint_sequence != advance.batch.checkpoint_sequence
        || committed.view.checkpoint_digest != advance.batch.checkpoint_digest
    {
        return Err(EconomicStateAnchorError::InvalidView(
            "committed checkpoint does not match the batch",
        ));
    }
    for transition in &advance.batch.transitions {
        let committed_digest = committed
            .view
            .head(&transition.resource_key)
            .map(EconomicResourceHeadV1::digest)
            .transpose()?;
        if committed_digest.as_deref() != Some(transition.next_head.digest()?.as_str()) {
            return Err(EconomicStateAnchorError::InvalidView(
                "committed head does not match the batch",
            ));
        }
    }
    for replay in &advance.batch.request_replays {
        if committed.view.request_replay(&replay.request.key()) != Some(replay) {
            return Err(EconomicStateAnchorError::InvalidView(
                "committed request replay does not match the batch",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicRequestReplayDisposition {
    New,
    Retained(EconomicRequestReplayV1),
}

pub fn verify_economic_request_replay(
    current: &VerifiedEconomicStateView,
    replay: &EconomicRequestReplayV1,
) -> Result<EconomicRequestReplayDisposition, EconomicStateAnchorError> {
    replay.validate()?;
    let key = replay.request.key();
    if let Some(retained) = current.view.request_replay(&key) {
        if retained == replay {
            return Ok(EconomicRequestReplayDisposition::Retained(retained.clone()));
        }
        return Err(EconomicStateAnchorError::RequestReplayConflict(key));
    }
    if !current.view.proves_request_absent(&key) {
        return Err(EconomicStateAnchorError::CurrentRequestMissing(key));
    }
    Ok(EconomicRequestReplayDisposition::New)
}

fn verify_batch_pins(
    batch: &EconomicStateBatchV1,
    pins: &EconomicStateAnchorPins,
) -> Result<(), EconomicStateAnchorError> {
    if batch.anchor_id != pins.anchor_id {
        return Err(EconomicStateAnchorError::PinMismatch("anchor_id"));
    }
    if batch.namespace != pins.namespace {
        return Err(EconomicStateAnchorError::PinMismatch("namespace"));
    }
    if batch.signer_key_id != pins.signer_key_id {
        return Err(EconomicStateAnchorError::PinMismatch("signer_key_id"));
    }
    if batch.signer_key_epoch != pins.signer_key_epoch {
        return Err(EconomicStateAnchorError::PinMismatch("signer_key_epoch"));
    }
    Ok(())
}

fn verify_transition_authorization(
    transition: &EconomicStateTransitionV1,
    authorization: &EconomicTransitionAuthorizationV1,
) -> Result<(), EconomicStateAnchorError> {
    match (authorization, transition.next_head.frost.as_ref()) {
        (EconomicTransitionAuthorizationV1::Direct, None) => Ok(()),
        (EconomicTransitionAuthorizationV1::NOfM { frost: verified }, Some(frost))
            if frost == verified =>
        {
            verified.validate()?;
            Ok(())
        }
        _ => Err(EconomicStateAnchorError::AuthorizationMismatch(
            transition.resource_key.clone(),
        )),
    }
}

pub trait EconomicAdmissionHandoffVerifier: Send + Sync {
    fn verify_operation_active(&self, operation_id: &str) -> Result<(), EconomicStateAnchorError>;

    fn verify_prepared_effect(
        &self,
        _slot: &EconomicEffectSlotV1,
    ) -> Result<(), EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::AdmissionHandoffRejected)
    }

    fn verify_handoff(
        &self,
        operation_id: &str,
        handoff: &EconomicAdmissionHandoffV1,
    ) -> Result<(), EconomicStateAnchorError>;
}

pub fn verify_economic_admission_batch(
    advance: &VerifiedEconomicStateBatchAdvance,
    admission: &dyn EconomicAdmissionHandoffVerifier,
) -> Result<(), EconomicStateAnchorError> {
    if advance.batch.effect_slots.is_empty() {
        if let Some(operation_id) = advance.batch.operation_id.as_deref() {
            admission.verify_operation_active(operation_id)?;
        }
    } else {
        for slot in &advance.batch.effect_slots {
            admission.verify_prepared_effect(slot)?;
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct VerifiedEconomicEffectDispatchAdvance {
    advance: VerifiedEconomicStateBatchAdvance,
    slot: EconomicEffectSlotV1,
}

impl VerifiedEconomicEffectDispatchAdvance {
    pub fn state_advance(&self) -> &VerifiedEconomicStateBatchAdvance {
        &self.advance
    }

    pub fn batch(&self) -> &EconomicStateBatchV1 {
        self.advance.batch()
    }

    pub fn slot(&self) -> &EconomicEffectSlotV1 {
        &self.slot
    }
}

pub fn verify_economic_effect_dispatch_advance(
    advance: VerifiedEconomicStateBatchAdvance,
    admission: &dyn EconomicAdmissionHandoffVerifier,
) -> Result<VerifiedEconomicEffectDispatchAdvance, EconomicStateAnchorError> {
    if advance.batch.transitions.len() != 1
        || !advance.batch.effect_slots.is_empty()
        || !advance.batch.request_replays.is_empty()
        || advance.batch.transitions[0].prepared_effect.is_some()
    {
        return Err(EconomicStateAnchorError::EffectDispatchRejected(
            "dispatch must advance exactly one retained effect slot",
        ));
    }
    let transition = &advance.batch.transitions[0];
    if transition.resource_key.resource_family != "effect_slot" {
        return Err(EconomicStateAnchorError::EffectDispatchRejected(
            "transition is not an effect slot",
        ));
    }
    let current_head = advance
        .current
        .view
        .head(&transition.resource_key)
        .ok_or_else(|| {
            EconomicStateAnchorError::CurrentHeadMissing(transition.resource_key.clone())
        })?;
    let current_slot = economic_effect_slot_from_head(current_head)?;
    let next_slot = economic_effect_slot_from_head(&transition.next_head)?;
    current_slot.validate_successor(&next_slot)?;
    let target_head = advance
        .current
        .view
        .head(&next_slot.resource_key)
        .ok_or_else(|| {
            EconomicStateAnchorError::CurrentHeadMissing(next_slot.resource_key.clone())
        })?;
    if target_head.digest()?.as_str() != next_slot.resource_head_digest.as_str() {
        return Err(EconomicStateAnchorError::EffectDispatchRejected(
            "effect slot target resource head changed",
        ));
    }
    if current_slot.state != EconomicEffectStateV1::Ready
        || next_slot.state != EconomicEffectStateV1::DispatchCommitted
        || transition.next_head.lifecycle_state != "dispatch_committed"
        || advance.batch.operation_id.as_deref() != Some(next_slot.operation_id.as_str())
    {
        return Err(EconomicStateAnchorError::EffectDispatchRejected(
            "effect slot did not enter dispatch_committed",
        ));
    }
    admission.verify_handoff(&next_slot.operation_id, &next_slot.admission_handoff)?;
    Ok(VerifiedEconomicEffectDispatchAdvance {
        advance,
        slot: next_slot,
    })
}

pub fn reverify_economic_effect_dispatch_advance(
    advance: &VerifiedEconomicEffectDispatchAdvance,
    pins: &EconomicStateAnchorPins,
    transition_verifier: &dyn EconomicTransitionProofVerifier,
    admission_verifier: &dyn EconomicAdmissionHandoffVerifier,
) -> Result<(), EconomicStateAnchorError> {
    let verified = verify_economic_state_batch_advance(
        advance.advance.current(),
        advance.batch().clone(),
        pins,
        transition_verifier,
    )?;
    let dispatch = verify_economic_effect_dispatch_advance(verified, admission_verifier)?;
    if dispatch.slot != advance.slot {
        return Err(EconomicStateAnchorError::EffectDispatchRejected(
            "reverified effect slot changed",
        ));
    }
    Ok(())
}

pub fn economic_effect_slot_from_head(
    head: &EconomicResourceHeadV1,
) -> Result<EconomicEffectSlotV1, EconomicStateAnchorError> {
    let EconomicContentV1::Inline { value } = &head.state else {
        return Err(EconomicStateAnchorError::EffectDispatchRejected(
            "effect slot state is not retained inline",
        ));
    };
    let slot = serde_json::from_value::<EconomicEffectSlotV1>(value.clone())
        .map_err(|error| EconomicStateAnchorError::Canonicalization(error.to_string()))?;
    slot.validate()?;
    let expected_lifecycle_state = match slot.state {
        EconomicEffectStateV1::Ready => "ready",
        EconomicEffectStateV1::DispatchCommitted => "dispatch_committed",
        EconomicEffectStateV1::Completed => "completed",
        EconomicEffectStateV1::NoEffect => "no_effect",
        EconomicEffectStateV1::Unknown => "unknown",
    };
    if slot.anchor_id != head.anchor_id
        || slot.namespace != head.namespace
        || slot.resource_head_key() != head.resource_key
        || head.lifecycle_state != expected_lifecycle_state
        || head.operation_id.as_deref() != Some(slot.operation_id.as_str())
        || head.effect_idempotency_key.as_deref() != Some(slot.idempotency_key.as_str())
        || head.frost.as_ref() != slot.frost.as_ref()
    {
        return Err(EconomicStateAnchorError::EffectDispatchRejected(
            "effect slot head binding mismatch",
        ));
    }
    Ok(slot)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicEffectDispatchCommitV1 {
    pub schema: String,
    pub commit_id: String,
    pub anchor_id: String,
    pub namespace: String,
    pub previous_checkpoint_digest: String,
    pub committed_checkpoint_digest: String,
    pub effect_slot_id: String,
    pub effect_head_digest: String,
    pub cas_nonce_digest: String,
    pub committed_at: u64,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub anchor_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EconomicEffectDispatchCommitIdPreimage<'a> {
    schema: &'a str,
    anchor_id: &'a str,
    namespace: &'a str,
    previous_checkpoint_digest: &'a str,
    committed_checkpoint_digest: &'a str,
    effect_slot_id: &'a str,
    effect_head_digest: &'a str,
    cas_nonce_digest: &'a str,
    committed_at: u64,
    signer_key_id: &'a str,
    signer_key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EconomicEffectDispatchCommitSigningPreimage<'a> {
    #[serde(flatten)]
    body: EconomicEffectDispatchCommitIdPreimage<'a>,
    commit_id: &'a str,
}

impl EconomicEffectDispatchCommitV1 {
    pub fn sign(
        advance: &VerifiedEconomicEffectDispatchAdvance,
        committed: &VerifiedEconomicStateView,
        cas_nonce_digest: String,
        committed_at: u64,
        signer_key_id: impl Into<String>,
        signer_key_epoch: u64,
        keypair: &Keypair,
    ) -> Result<Self, EconomicStateAnchorError> {
        let transition = &advance.batch().transitions[0];
        let mut commit = Self {
            schema: CHIO_ECONOMIC_EFFECT_DISPATCH_COMMIT_SCHEMA.to_string(),
            commit_id: String::new(),
            anchor_id: advance.batch().anchor_id.clone(),
            namespace: advance.batch().namespace.clone(),
            previous_checkpoint_digest: advance.batch().previous_checkpoint_digest.clone().ok_or(
                EconomicStateAnchorError::EffectDispatchRejected(
                    "dispatch batch has no predecessor",
                ),
            )?,
            committed_checkpoint_digest: committed.view.checkpoint_digest.clone(),
            effect_slot_id: advance.slot.slot_id.clone(),
            effect_head_digest: transition.next_head.digest()?,
            cas_nonce_digest,
            committed_at,
            signer_key_id: signer_key_id.into(),
            signer_key_epoch,
            anchor_signature: String::new(),
        };
        commit.commit_id = commit.recompute_commit_id()?;
        commit.anchor_signature = keypair.sign(&commit.signing_bytes()?).to_hex();
        commit.validate()?;
        Ok(commit)
    }

    pub fn validate(&self) -> Result<(), EconomicStateAnchorError> {
        if self.schema != CHIO_ECONOMIC_EFFECT_DISPATCH_COMMIT_SCHEMA {
            return Err(EconomicStateAnchorError::UnsupportedSchema {
                field: "dispatch_commit",
                value: self.schema.clone(),
            });
        }
        validate_digest("dispatch_commit_id", &self.commit_id)?;
        validate_identifier("anchor_id", &self.anchor_id)?;
        validate_identifier("namespace", &self.namespace)?;
        validate_digest(
            "previous_checkpoint_digest",
            &self.previous_checkpoint_digest,
        )?;
        validate_digest(
            "committed_checkpoint_digest",
            &self.committed_checkpoint_digest,
        )?;
        validate_digest("effect_slot_id", &self.effect_slot_id)?;
        validate_digest("effect_head_digest", &self.effect_head_digest)?;
        validate_digest("cas_nonce_digest", &self.cas_nonce_digest)?;
        validate_positive("committed_at", self.committed_at)?;
        validate_identifier("signer_key_id", &self.signer_key_id)?;
        validate_positive("signer_key_epoch", self.signer_key_epoch)?;
        validate_fixed_hex("anchor_signature", &self.anchor_signature, 128)?;
        if self.recompute_commit_id()? != self.commit_id {
            return Err(EconomicStateAnchorError::EffectDispatchRejected(
                "dispatch commit id mismatch",
            ));
        }
        Ok(())
    }

    pub fn verify(&self, pins: &EconomicStateAnchorPins) -> Result<(), EconomicStateAnchorError> {
        self.validate()?;
        if self.anchor_id != pins.anchor_id
            || self.namespace != pins.namespace
            || self.signer_key_id != pins.signer_key_id
            || self.signer_key_epoch != pins.signer_key_epoch
        {
            return Err(EconomicStateAnchorError::PinMismatch("dispatch_commit"));
        }
        let signature = Signature::from_hex(&self.anchor_signature)
            .map_err(|_| EconomicStateAnchorError::InvalidSignature)?;
        if pins
            .signer_public_key
            .verify(&self.signing_bytes()?, &signature)
        {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::InvalidSignature)
        }
    }

    fn recompute_commit_id(&self) -> Result<String, EconomicStateAnchorError> {
        domain_digest(DISPATCH_COMMIT_ID_DOMAIN, &self.id_preimage()).map_err(Into::into)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, EconomicStateAnchorError> {
        prefixed_canonical(DISPATCH_COMMIT_SIGNING_DOMAIN, &self.signing_preimage())
            .map_err(Into::into)
    }

    fn id_preimage(&self) -> EconomicEffectDispatchCommitIdPreimage<'_> {
        EconomicEffectDispatchCommitIdPreimage {
            schema: &self.schema,
            anchor_id: &self.anchor_id,
            namespace: &self.namespace,
            previous_checkpoint_digest: &self.previous_checkpoint_digest,
            committed_checkpoint_digest: &self.committed_checkpoint_digest,
            effect_slot_id: &self.effect_slot_id,
            effect_head_digest: &self.effect_head_digest,
            cas_nonce_digest: &self.cas_nonce_digest,
            committed_at: self.committed_at,
            signer_key_id: &self.signer_key_id,
            signer_key_epoch: self.signer_key_epoch,
        }
    }

    fn signing_preimage(&self) -> EconomicEffectDispatchCommitSigningPreimage<'_> {
        EconomicEffectDispatchCommitSigningPreimage {
            body: self.id_preimage(),
            commit_id: &self.commit_id,
        }
    }
}

#[derive(Debug)]
pub struct VerifiedEconomicEffectDispatch {
    slot: EconomicEffectSlotV1,
    commit_id: String,
}

impl VerifiedEconomicEffectDispatch {
    pub fn slot(&self) -> &EconomicEffectSlotV1 {
        &self.slot
    }

    pub fn commit_id(&self) -> &str {
        &self.commit_id
    }
}

pub fn verify_economic_effect_dispatch_commit(
    advance: VerifiedEconomicEffectDispatchAdvance,
    committed: &VerifiedEconomicStateView,
    commit: EconomicEffectDispatchCommitV1,
    pins: &EconomicStateAnchorPins,
) -> Result<VerifiedEconomicEffectDispatch, EconomicStateAnchorError> {
    committed.view.verify(pins)?;
    commit.verify(pins)?;
    let transition = &advance.batch().transitions[0];
    let expected_head_digest = transition.next_head.digest()?;
    let target_head_digest = committed
        .view
        .head(&advance.slot.resource_key)
        .map(EconomicResourceHeadV1::digest)
        .transpose()?;
    if committed.view.checkpoint_sequence != advance.batch().checkpoint_sequence
        || committed.view.checkpoint_digest != advance.batch().checkpoint_digest
        || committed
            .view
            .head(&transition.resource_key)
            .map(EconomicResourceHeadV1::digest)
            .transpose()?
            .as_deref()
            != Some(expected_head_digest.as_str())
        || target_head_digest.as_deref() != Some(advance.slot.resource_head_digest.as_str())
        || commit.previous_checkpoint_digest
            != advance
                .batch()
                .previous_checkpoint_digest
                .as_deref()
                .unwrap_or_default()
        || commit.committed_checkpoint_digest != advance.batch().checkpoint_digest
        || commit.effect_slot_id != advance.slot.slot_id
        || commit.effect_head_digest != expected_head_digest
    {
        return Err(EconomicStateAnchorError::EffectDispatchRejected(
            "signed CAS commit does not match the effect advance",
        ));
    }
    Ok(VerifiedEconomicEffectDispatch {
        slot: advance.slot,
        commit_id: commit.commit_id,
    })
}

pub trait EconomicTargetStatusVerifier: Send + Sync {
    fn verify_status(
        &self,
        slot: &EconomicEffectSlotV1,
        evidence_digest: &str,
    ) -> Result<EconomicEffectTerminalV1, EconomicStateAnchorError>;
}

#[derive(Debug)]
pub struct VerifiedEconomicTargetStatus {
    next_slot: EconomicEffectSlotV1,
    evidence_digest: String,
}

impl VerifiedEconomicTargetStatus {
    pub fn next_slot(&self) -> &EconomicEffectSlotV1 {
        &self.next_slot
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
}

pub fn verify_economic_target_status(
    slot: &EconomicEffectSlotV1,
    evidence_digest: &str,
    verifier: &dyn EconomicTargetStatusVerifier,
) -> Result<VerifiedEconomicTargetStatus, EconomicStateAnchorError> {
    validate_digest("target_status_evidence_digest", evidence_digest)?;
    let terminal = verifier.verify_status(slot, evidence_digest)?;
    let mut next_slot = slot.clone();
    next_slot.state = terminal.state();
    next_slot.terminal = Some(terminal);
    slot.validate_successor(&next_slot)?;
    Ok(VerifiedEconomicTargetStatus {
        next_slot,
        evidence_digest: evidence_digest.to_string(),
    })
}

#[derive(Debug, Clone)]
pub struct VerifiedEconomicCompletedEffect {
    slot: EconomicEffectSlotV1,
    checkpoint_digest: String,
    effect_head_digest: String,
    observed_at: u64,
}

impl VerifiedEconomicCompletedEffect {
    pub fn slot(&self) -> &EconomicEffectSlotV1 {
        &self.slot
    }

    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }

    pub fn effect_head_digest(&self) -> &str {
        &self.effect_head_digest
    }

    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }
}

pub fn verify_economic_completed_effect(
    view: &VerifiedEconomicStateView,
    expected: &EconomicEffectSlotV1,
) -> Result<VerifiedEconomicCompletedEffect, EconomicStateAnchorError> {
    expected.validate()?;
    let terminal_result = match (&expected.state, expected.terminal.as_ref()) {
        (
            EconomicEffectStateV1::Completed,
            Some(EconomicEffectTerminalV1::Completed {
                result_id,
                result_digest,
                result,
            }),
        ) => EconomicTerminalResultV1 {
            result_id: result_id.clone(),
            result_digest: result_digest.clone(),
            result: result.clone(),
        },
        _ => {
            return Err(EconomicStateAnchorError::CompletedEffectRejected(
                "expected slot is not completed",
            ))
        }
    };
    let key = expected.resource_head_key();
    let head = view
        .view
        .head(&key)
        .ok_or_else(|| EconomicStateAnchorError::CurrentHeadMissing(key.clone()))?;
    let anchored = economic_effect_slot_from_head(head)?;
    if anchored != *expected
        || head.lifecycle_state != "completed"
        || head.terminal_result.as_ref() != Some(&terminal_result)
    {
        return Err(EconomicStateAnchorError::CompletedEffectRejected(
            "anchored head does not contain the exact completed slot",
        ));
    }
    Ok(VerifiedEconomicCompletedEffect {
        slot: anchored,
        checkpoint_digest: view.view.checkpoint_digest.clone(),
        effect_head_digest: head.digest()?,
        observed_at: view.view.observed_at,
    })
}

pub trait EconomicIdempotentTargetVerifier: Send + Sync {
    fn verify_qualification(
        &self,
        target: &EconomicEffectTargetV1,
        idempotency_key: &str,
    ) -> Result<(), EconomicStateAnchorError>;
}

#[derive(Debug)]
pub struct VerifiedEconomicIdempotentRecovery {
    slot: EconomicEffectSlotV1,
}

impl VerifiedEconomicIdempotentRecovery {
    pub fn slot(&self) -> &EconomicEffectSlotV1 {
        &self.slot
    }

    pub fn target(&self) -> &EconomicEffectTargetV1 {
        &self.slot.target
    }

    pub fn idempotency_key(&self) -> &str {
        &self.slot.idempotency_key
    }
}

pub fn verify_economic_idempotent_recovery(
    slot: &EconomicEffectSlotV1,
    verifier: &dyn EconomicIdempotentTargetVerifier,
) -> Result<VerifiedEconomicIdempotentRecovery, EconomicStateAnchorError> {
    slot.validate()?;
    if !matches!(
        slot.state,
        EconomicEffectStateV1::DispatchCommitted | EconomicEffectStateV1::Unknown
    ) {
        return Err(EconomicStateAnchorError::IdempotentRecoveryRejected);
    }
    verifier.verify_qualification(&slot.target, &slot.idempotency_key)?;
    Ok(VerifiedEconomicIdempotentRecovery { slot: slot.clone() })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicExpectedHead {
    pub resource_key: EconomicResourceKeyV1,
    pub head_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicStateReadinessExpectation {
    pub checkpoint_sequence: u64,
    pub checkpoint_digest: String,
    pub heads: Vec<EconomicExpectedHead>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EconomicStateReadiness {
    Ready,
    Missing,
    Unavailable,
    Untrusted,
    Behind,
    Ahead,
    Divergent,
}

impl EconomicStateReadiness {
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

pub fn assess_economic_state_readiness(
    current: &VerifiedEconomicStateView,
    expectation: &EconomicStateReadinessExpectation,
) -> Result<EconomicStateReadiness, EconomicStateAnchorError> {
    validate_positive(
        "expected_checkpoint_sequence",
        expectation.checkpoint_sequence,
    )?;
    validate_digest("expected_checkpoint_digest", &expectation.checkpoint_digest)?;
    if expectation.heads.len() > MAX_ECONOMIC_TRANSITIONS {
        return Err(EconomicStateAnchorError::InvalidView(
            "expected heads exceed the bound",
        ));
    }
    if !expectation
        .heads
        .windows(2)
        .all(|pair| pair[0].resource_key < pair[1].resource_key)
    {
        return Err(EconomicStateAnchorError::InvalidView(
            "expected heads must be sorted and unique",
        ));
    }
    if current.view.checkpoint_sequence < expectation.checkpoint_sequence {
        return Ok(EconomicStateReadiness::Behind);
    }
    if current.view.checkpoint_sequence > expectation.checkpoint_sequence {
        return Ok(EconomicStateReadiness::Ahead);
    }
    if current.view.checkpoint_digest != expectation.checkpoint_digest {
        return Ok(EconomicStateReadiness::Divergent);
    }
    for expected in &expectation.heads {
        expected.resource_key.validate()?;
        validate_digest("expected_head_digest", &expected.head_digest)?;
        let Some(head) = current.view.head(&expected.resource_key) else {
            return Ok(EconomicStateReadiness::Missing);
        };
        if head.digest()? != expected.head_digest {
            return Ok(EconomicStateReadiness::Divergent);
        }
    }
    Ok(EconomicStateReadiness::Ready)
}

pub trait EconomicStateAnchor: Send + Sync {
    fn read_state(
        &self,
        query: &EconomicStateReadQuery,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError>;

    fn read_checkpoint_state(
        &self,
        query: &EconomicCheckpointReadQuery,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError>;

    fn compare_and_swap_batch(
        &self,
        advance: QualifiedGenericEconomicStateBatchAdvance<'_>,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError>;

    fn compare_and_swap_effect_dispatch(
        &self,
        advance: VerifiedEconomicEffectDispatchAdvance,
    ) -> Result<VerifiedEconomicEffectDispatch, EconomicStateAnchorError>;

    fn compare_and_swap_effect_unknown(
        &self,
        _advance: QualifiedEconomicEffectUnknownAdvance<'_>,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::Unavailable(
            "economic effect unknown recovery is not configured".to_string(),
        ))
    }

    fn compare_and_swap_effect_cancellation(
        &self,
        _advance: VerifiedEconomicEffectCancellationAdvance,
    ) -> Result<VerifiedEconomicEffectNotDispatched, EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::Unavailable(
            "economic effect cancellation is not configured".to_string(),
        ))
    }
}
