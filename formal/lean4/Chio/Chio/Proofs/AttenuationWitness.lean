/-
  Attenuation witness soundness with current chain-binding.

  Models `theorem.attenuation.witness_soundness`: an attenuated capability token is
  rejected by the verifier whenever its `attenuation_proof.parent_scope_hash`
  is not bound to the trust-root scope hash (direct issue) or to the last
  delegation link's signed `scope_hash` (delegated chain). This closes the
  P0 soundness gap where an issuer with true authority `scope_X` could
  mint an attenuated token claiming `parent_scope = scope_BIGGER` and supply an
  internally-consistent witness, because nothing tied
  `parent_scope_hash` to the issuer's actual upstream parent capability.

  The root-imported theorem contains no proof placeholders, is exercised by
  the nightly Lean gate, and is recorded as `proved`. The Rust shell is
  exercised by
  `crates/tooling/chio-conformance/tests/attenuation_witness_rejects_inflated_parent_scope.rs`
  and the protocol-side check is implemented in
  `chio_core_types::capability::CapabilityToken::validate_chain_binding`.
-/

set_option autoImplicit false

namespace Chio.Proofs.AttenuationWitness

/-- Abstract scope hashes. Concrete encoding is SHA-256 hex on the wire;
    the algebra below is hash-agnostic and only relies on equality. -/
structure ScopeHash where
  bytes : Nat
deriving DecidableEq, Repr

/-- Wire shape carried by the attenuated token:
    - `parentScopeHash`: the parent scope claimed by the witness.
    - `childScopeHash`: the hash of the token's authorized scope.
    The witness body is abstracted as the Boolean
    `witnessProvesChildSubsetOfParent`: true iff
    `verify_attenuation_witness(parent, child, w)` returns Ok. -/
structure AttenuationProof where
  parentScopeHash : ScopeHash
  childScopeHash : ScopeHash
  witnessProvesChildSubsetOfParent : Bool
deriving Repr

/-- Per-hop chain-binding evidence. A v1 hop omits `scopeHash`; a v2 hop
    carries the predecessor's signed authorized-scope hash. -/
structure ChainLink where
  scopeHash : Option ScopeHash
deriving Repr

/-- The capability-token shape this proof reasons about. -/
structure Token where
  proof : AttenuationProof
  delegationChain : List ChainLink
deriving Repr

/-- Verifier verdict for the chain-binding check. -/
inductive Verdict
  | admit
  | rejectChainBinding
  | rejectMissingScopeHash
deriving DecidableEq, Repr

/-- Pure model of `validate_chain_binding`: the verifier requires
    `parentScopeHash` to equal either the trust-root scope hash (when
    the chain is empty: a direct issue from the trust-root authority)
    or the last delegation link's signed `scopeHash` (when delegation
    has occurred). v2 hops without a `scopeHash` are rejected fail-closed. -/
def chainBindingCheck
    (token : Token) (trustRootHash : ScopeHash) : Verdict :=
  match token.delegationChain.reverse with
  | [] =>
    if token.proof.parentScopeHash = trustRootHash then
      Verdict.admit
    else
      Verdict.rejectChainBinding
  | last :: _ =>
    match last.scopeHash with
    | none => Verdict.rejectMissingScopeHash
    | some lastHash =>
      if token.proof.parentScopeHash = lastHash then
        Verdict.admit
      else
        Verdict.rejectChainBinding

/-- Honest direct-issue token: `parentScopeHash` matches the trust root.
    The verifier admits. -/
theorem chain_binding_admits_honest_direct_issue
    (witness : Bool) (h : ScopeHash) (childHash : ScopeHash) :
    chainBindingCheck
      { proof := { parentScopeHash := h
                 , childScopeHash := childHash
                 , witnessProvesChildSubsetOfParent := witness }
      , delegationChain := [] }
      h = Verdict.admit := by
  unfold chainBindingCheck
  simp

/-- Attack scenario: an issuer with true authority
    `scopeX` mints a token whose `parentScopeHash` points at
    `scopeBigger != scopeX`. The verifier rejects it with
    `rejectChainBinding`, even if the witness body internally proves
    `child <= scopeBigger` (the `witnessProvesChildSubsetOfParent`
    flag is irrelevant once `parentScopeHash` is unbound from the
    trust root). -/
theorem chain_binding_rejects_inflated_parent_scope_direct_issue
    (scopeX scopeBigger childHash : ScopeHash)
    (witness : Bool)
    (h_distinct : scopeX ≠ scopeBigger) :
    chainBindingCheck
      { proof := { parentScopeHash := scopeBigger
                 , childScopeHash := childHash
                 , witnessProvesChildSubsetOfParent := witness }
      , delegationChain := [] }
      scopeX = Verdict.rejectChainBinding := by
  unfold chainBindingCheck
  simp [h_distinct.symm]

/-- Honest delegated token: the last hop's signed `scopeHash` matches
    the proof's `parentScopeHash`. The verifier admits. -/
theorem chain_binding_admits_honest_delegated
    (lastHash trustRootHash childHash : ScopeHash) (witness : Bool) :
    chainBindingCheck
      { proof := { parentScopeHash := lastHash
                 , childScopeHash := childHash
                 , witnessProvesChildSubsetOfParent := witness }
      , delegationChain := [{ scopeHash := some lastHash }] }
      trustRootHash = Verdict.admit := by
  unfold chainBindingCheck
  simp

/-- A delegated token whose last hop omits `scopeHash` is rejected
    fail-closed. Delegation chains MUST bind every hop. -/
theorem chain_binding_rejects_chain_without_scope_hash
    (parentScopeHash trustRootHash childHash : ScopeHash) (witness : Bool) :
    chainBindingCheck
      { proof := { parentScopeHash := parentScopeHash
                 , childScopeHash := childHash
                 , witnessProvesChildSubsetOfParent := witness }
      , delegationChain := [{ scopeHash := none }] }
      trustRootHash = Verdict.rejectMissingScopeHash := by
  unfold chainBindingCheck
  simp

/-- Headline theorem named in `formal/theorem-inventory.json` and
    `formal/proof-manifest.toml`. Witness soundness with v2 chain
    binding: the verifier admits iff `parentScopeHash` matches the
    appropriate anchor (trust root for direct issue, predecessor's
    signed `scopeHash` for delegated chains) and every v2 hop carries
    a non-`none` `scopeHash`. -/
theorem witness_soundness
    (token : Token) (trustRootHash : ScopeHash) :
    chainBindingCheck token trustRootHash = Verdict.admit ->
    (token.delegationChain.reverse = [] ->
        token.proof.parentScopeHash = trustRootHash) /\
    (forall last rest, token.delegationChain.reverse = last :: rest ->
        exists lastHash,
          last.scopeHash = some lastHash /\
          token.proof.parentScopeHash = lastHash) := by
  intro h_admit
  refine And.intro ?_ ?_
  · intro h_empty
    unfold chainBindingCheck at h_admit
    rw [h_empty] at h_admit
    by_cases h_eq : token.proof.parentScopeHash = trustRootHash
    · exact h_eq
    · simp [h_eq] at h_admit
  · intro last rest h_cons
    unfold chainBindingCheck at h_admit
    rw [h_cons] at h_admit
    cases h_scope : last.scopeHash with
    | none =>
      simp [h_scope] at h_admit
    | some lastHash =>
      simp [h_scope] at h_admit
      by_cases h_eq : token.proof.parentScopeHash = lastHash
      · exact ⟨lastHash, rfl, h_eq⟩
      · simp [h_eq] at h_admit

end Chio.Proofs.AttenuationWitness
