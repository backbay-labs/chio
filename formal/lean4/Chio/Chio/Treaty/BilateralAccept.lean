/-
  Freestanding accept-set model for the bilateral-DSSE short paper.

  This file is intentionally self-contained at the module level: it
  imports `Chio.Treaty.PredicateLang` for the `Predicate` type and
  `denote` interpreter but does not depend on the wider Chio polity
  model (no `SyntacticConstitution`, no anchor-quorum machinery, no
  treaty intersection), so the structural claim can be audited end to
  end from this module alone.

  The load-bearing structural theorem is
  `freestanding_accept_set_theorem`: a bilateral envelope is
  accepted by a verifier iff three independent conjuncts hold (issuer
  key in trust store, kernel key in trust store, scope predicate
  denotes on the receipt). The bi-conditional is the named claim that
  no hidden side channel can sneak admission past these three gates.
-/

import Chio.Treaty.PredicateLang

set_option autoImplicit false

namespace Chio.Treaty.BilateralAccept

/-- Opaque key identifier (sha256 fingerprint, hex, etc.). -/
abbrev KeyId := String

/-- Opaque signature byte string. The freestanding theorem does not
    inspect signature bytes; signature validity is treated abstractly
    via the trust store. -/
abbrev SignatureBytes := String

/-- An issuer-side signature slice in a bilateral DSSE envelope. -/
structure IssuerSig where
  keyId : KeyId
  sig : SignatureBytes
  deriving Repr, BEq, DecidableEq, Inhabited

/-- A kernel-side signature slice in a bilateral DSSE envelope. -/
structure KernelSig where
  keyId : KeyId
  sig : SignatureBytes
  deriving Repr, BEq, DecidableEq, Inhabited

/-- A bilateral DSSE envelope: a bounded receipt view, a scope predicate, and
    two signature slices (one issuer-side, one kernel-side). The
    model treats `scope` as the policy that gates this envelope. -/
structure BilateralEnvelope where
  receipt : PredicateLang.ReceiptView
  scope : PredicateLang.Predicate
  issuerSig : IssuerSig
  kernelSig : KernelSig
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Trust store: declared allowlists of issuer keys and kernel keys. -/
structure TrustStore where
  issuerKeys : List KeyId
  kernelKeys : List KeyId
  deriving Repr, BEq, DecidableEq, Inhabited

/--
  Freestanding bilateral verifier: accept iff
  (i) the envelope's issuer key id is in the trust store's issuer
      allowlist,
  (ii) the envelope's kernel key id is in the trust store's kernel
       allowlist, and
    (iii) the scope predicate denotes true on the bounded receipt view.

  Signature byte validity is abstracted away: the trust-store membership
  conjuncts encode "we have a valid signature under a key we recognize",
  which is what a deployed verifier checks before reaching the predicate
  layer.
-/
def accept
    (store : TrustStore) (env : BilateralEnvelope) : Bool :=
  decide (env.issuerSig.keyId ∈ store.issuerKeys) &&
  decide (env.kernelSig.keyId ∈ store.kernelKeys) &&
  PredicateLang.denote env.scope env.receipt

/--
  Freestanding accept-set theorem (short-paper §4): a bilateral
  envelope is accepted by the verifier iff three independent
  conjuncts hold. The bi-conditional is the load-bearing structural
  claim that no hidden side channel can sneak admission past the
  three gates.
-/
theorem freestanding_accept_set_theorem
    (store : TrustStore) (env : BilateralEnvelope) :
    accept store env = true ↔
    (env.issuerSig.keyId ∈ store.issuerKeys ∧
     env.kernelSig.keyId ∈ store.kernelKeys ∧
     PredicateLang.denote env.scope env.receipt = true) := by
  unfold accept
  simp [Bool.and_eq_true, and_assoc]

/--
  Corollary 1: accept-set monotonicity in the trust store. Extending
  the issuer allowlist (resp. kernel allowlist) can only preserve or
  expand the accept set. The short paper uses this to argue that
  adding a co-signing counterparty never invalidates a prior accept.
-/
theorem accept_monotone_in_issuer_store
    (store store' : TrustStore) (env : BilateralEnvelope)
    (hExt : forall k, k ∈ store.issuerKeys -> k ∈ store'.issuerKeys)
    (hKernEq : store.kernelKeys = store'.kernelKeys)
    (hAccept : accept store env = true) :
    accept store' env = true := by
  rw [freestanding_accept_set_theorem] at hAccept ⊢
  refine ⟨hExt _ hAccept.1, ?_, hAccept.2.2⟩
  rw [← hKernEq]
  exact hAccept.2.1

/--
  Corollary 2: accept-set conjunction over scope predicates. If an
  envelope with a scope of `conj p q` is accepted, then the issuer
  and kernel key conjuncts hold and both scope predicates denote true
  for the same receipt view. This states the freestanding predicate
  decomposition without pretending the original signatures can be
  reused for a byte-distinct rebound envelope.
-/
theorem accept_conj_scope_decompose
    (store : TrustStore) (env : BilateralEnvelope)
    (p q : PredicateLang.Predicate)
    (hScope : env.scope = .conj p q)
    (hAccept : accept store env = true) :
    env.issuerSig.keyId ∈ store.issuerKeys ∧
    env.kernelSig.keyId ∈ store.kernelKeys ∧
    PredicateLang.denote p env.receipt = true ∧
    PredicateLang.denote q env.receipt = true := by
  rw [freestanding_accept_set_theorem] at hAccept
  have hIssuer : env.issuerSig.keyId ∈ store.issuerKeys := hAccept.1
  have hKernel : env.kernelSig.keyId ∈ store.kernelKeys := hAccept.2.1
  rw [hScope] at hAccept
  have hConj : PredicateLang.denote (.conj p q) env.receipt = true := hAccept.2.2
  simp [PredicateLang.denote] at hConj
  exact ⟨hIssuer, hKernel, hConj.1, hConj.2⟩

/--
  Corollary 3: rejection on missing issuer key. An envelope whose
  issuer key id is not in the trust store is rejected, regardless of
  the kernel key and scope. The contrapositive names the attacker's
  move: any accepted envelope must have an issuer key in the store.
-/
theorem accept_requires_issuer_key
    (store : TrustStore) (env : BilateralEnvelope)
    (hMissing : env.issuerSig.keyId ∉ store.issuerKeys) :
    accept store env = false := by
  cases h : accept store env
  · rfl
  · rw [freestanding_accept_set_theorem] at h
    exact absurd h.1 hMissing

end Chio.Treaty.BilateralAccept
