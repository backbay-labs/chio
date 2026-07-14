# chio-pheromone

Defines Chio's pheromone deposit schema and the receiver-owned validation that
admits a deposit: signature and passport checks, replay and treaty-scope
enforcement, scarcity-policy resolution, and observation-cost commitment
verification. Also provides `InMemoryPheromoneSubstrate`, a local admission
store that turns those checks into enforced scarcity, diversity, and
passport-cap accounting. The crate performs no I/O.

Reach for this crate directly to validate a deposit or hold it in memory.
Durable local storage belongs to `chio-pheromone-runtime`; moving deposits
between kernels over the network belongs to `chio-pheromone-relay`.

## Responsibilities

- Define the deposit wire schema (`PheromoneDeposit`, `PheromoneDepositBody`)
  and sign a deposit body over its canonical JSON (`sign_deposit`).
- Admit a deposit fail-closed (`validate_deposit_for_admission`): schema and
  field shape, passport resolution (rejects kernel-signed, unknown, revoked, or
  expired passports), signature verification, treaty-scope match, replay-window
  and future-timestamp bounds, and a required observation-cost commitment where
  the subject-class policy demands one.
- Resolve receiver-owned scarcity policy per treaty
  (`scarcity_admissions_for_deposit`, `scarcity_admissions_for_deposit_treaty`):
  select the single active window, recompute its deterministic `window_id` and
  `policy_sha256` to detect tampering (`validate_scarcity_policy_material`), and
  reject overlapping windows (`reject_overlapping_scarcity_windows`).
- Verify observation-cost commitments when a scarcity policy requires one:
  statement-to-deposit binding, a trusted and non-revoked verifier root,
  commitment signature, and Merkle inclusion against the verifier's telemetry
  root.
- Hold admitted deposits in memory (`InMemoryPheromoneSubstrate`) and enforce
  scarcity-bucket capacity, per-origin-pair diversity caps, and a
  sqrt(active-peers) cap on distinct passports per kernel, treaty, and window.
- Answer concentration queries with peer-weighted, half-life confidence decay
  and a newcomer discount, and garbage-collect deposits once decayed below
  their evaporation floor.

## Public API

- **Deposit lifecycle** - `sign_deposit`, `validate_deposit_for_admission`,
  `PheromoneDeposit`, `PheromoneDepositBody`, `DepositQuery`.
- **Scarcity policy** - `scarcity_admissions_for_deposit`,
  `scarcity_admissions_for_deposit_treaty`, `validate_scarcity_policy_material`,
  `reject_overlapping_scarcity_windows`, `scarcity_window_id`,
  `scarcity_policy_sha256`, `PheromoneScarcityPolicy`, `PheromoneScarcityAdmission`.
- **Observation-cost evidence** - `PheromoneCostCommitment`,
  `PheromoneObservationCostStatement`, `PheromoneObservationCostTelemetryRoot`,
  `PheromoneObservationCostLeaf`, `PheromoneObservationCostVerifierRoot`,
  `CostCommitmentPolicy`, `ObservationCostVerificationMode`.
- **Concentration and decay** - `newcomer_discount_for_deposit`,
  `default_newcomer_discount_horizon_epochs`, `PheromoneConcentration`.
- **Local substrate** - `PheromoneSubstrate` trait (`deposit`, `query_deposits`,
  `query_concentration`, `gc_evaporated`) and `InMemoryPheromoneSubstrate`.
- **Identity and context** - `agent_passport_key_hash`,
  `agent_passport_jwk_thumbprint`, `PassportAdmission`, `SubjectClassPolicy`,
  `PheromoneValidationContext`, `PheromoneWorkflowContext`,
  `PheromoneRuntimeTrustFloorState`, `PheromoneRuntimeTrustFloorEntry`.
- **Errors** - `PheromoneError` (stable `.code()` string per variant), `Severity`.

Each artifact carries a `..._SCHEMA` constant (`PHEROMONE_DEPOSIT_SCHEMA`,
`PHEROMONE_SCARCITY_POLICY_SCHEMA`, `PHEROMONE_WORKFLOW_CONTEXT_SCHEMA`, and
others) checked before the payload is trusted.

## Testing

`cargo test -p chio-pheromone`. `tests/public_surface.rs` guards against
re-exporting `CHIO_*_SCHEMA` constants that other crates own.

## See also

- `chio-pheromone-runtime` - durable local receiver runtime built on this crate.
- `chio-pheromone-relay` - networked relay service that moves deposits between
  kernels, built on `chio-pheromone` and `chio-pheromone-runtime`.
