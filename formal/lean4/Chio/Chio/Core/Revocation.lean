/-
  Revocation store model and delegation chain validation.
  Mirrors: crates/kernel/chio-kernel/src/kernel/validation.rs,
  crates/core/chio-core-types/src/capability/attenuation.rs, and
  crates/kernel/chio-kernel-core/src/evaluate.rs.
  Enforced by the matching [[mirror]] entries in formal/proof-manifest.toml.
-/

import Chio.Core.Capability

set_option autoImplicit false

namespace Chio.Core

/-- Abstract revocation store: a set of revoked capability IDs. -/
abbrev RevocationStore := List CapabilityId

def RevocationStore.isRevoked (store : RevocationStore) (capId : CapabilityId) : Bool :=
  store.any (fun id => id == capId)

def RevocationStore.revoke (store : RevocationStore) (capId : CapabilityId) : RevocationStore :=
  if store.isRevoked capId then store else capId :: store

/-- Mirrors: Verdict handling in crates/kernel/chio-kernel-core/src/evaluate.rs. -/
inductive Decision where
  | allow
  | deny (reason : String)
  deriving Repr, BEq

/-- Abstract signature verification model.
    The Rust implementation verifies the capability signature bytes before
    treating the issuer as authenticated; the Lean model has no signature
    field, so trusted issuer membership is the concrete, total predicate
    exposed to the proofs. -/
def verifyCapabilitySignature (cap : CapabilityToken) (trustedKeys : List PublicKeyHex) : Bool :=
  trustedKeys.any (fun key => key == cap.issuer)

/-- Check time bounds: issued_at <= now < expires_at. -/
def checkTimeBounds (cap : CapabilityToken) (now : Timestamp) : Except String Unit :=
  if now < cap.issuedAt then
    .error "capability not yet valid"
  else if now ≥ cap.expiresAt then
    .error "capability expired"
  else
    .ok ()

/-- Check revocation of the token and its entire delegation chain.
    Mirrors: ChioKernel::check_revocation in
    crates/kernel/chio-kernel/src/kernel/validation.rs. -/
def checkRevocation (store : RevocationStore) (cap : CapabilityToken) : Except String Unit :=
  if store.isRevoked cap.id then
    .error s!"capability {cap.id} is revoked"
  else if cap.delegationChain.any (fun link => store.isRevoked link.delegator) then
    .error "delegation chain contains revoked ancestor"
  else
    .ok ()

/-- Check whether the requested tool is within the capability's scope. -/
def checkScope (cap : CapabilityToken) (toolName : ToolName) (serverId : ServerId) : Bool :=
  cap.scope.grants.any (fun g =>
    g.serverId == serverId
    && (g.toolName == toolName || g.toolName == "*")
    && g.operations.any (fun op => op == .invoke))

/-- Validate delegation chain connectivity: adjacent links must be connected
    (link[i].delegatee == link[i+1].delegator). -/
def chainConnected : List DelegationLink → Bool
  | [] => true
  | [_] => true
  | a :: b :: rest => a.delegatee == b.delegator && chainConnected (b :: rest)

/-- Validate that timestamps are non-decreasing in the delegation chain. -/
def chainTimestampsMonotone : List DelegationLink → Bool
  | [] => true
  | [_] => true
  | a :: b :: rest => b.timestamp ≥ a.timestamp && chainTimestampsMonotone (b :: rest)

/-- Check delegation depth against the configured maximum. -/
def chainWithinDepth (chain : List DelegationLink) (maxDepth : Nat) : Bool :=
  chain.length ≤ maxDepth

/-- Full delegation chain validation.
    Mirrors: validate_delegation_chain in
    crates/core/chio-core-types/src/capability/attenuation.rs. -/
def validateDelegationChain (chain : List DelegationLink) (maxDepth : Option Nat)
    : Except String Unit :=
  match maxDepth with
  | some max =>
    if !chainWithinDepth chain max then
      .error s!"delegation depth {chain.length} exceeds maximum {max}"
    else if !chainConnected chain then
      .error "delegation chain connectivity broken"
    else if !chainTimestampsMonotone chain then
      .error "delegation chain timestamps not monotone"
    else
      .ok ()
  | none =>
    if !chainConnected chain then
      .error "delegation chain connectivity broken"
    else if !chainTimestampsMonotone chain then
      .error "delegation chain timestamps not monotone"
    else
      .ok ()

/-- Simplified kernel evaluation pipeline.
    Every path returns a Decision. Errors map to deny.
    Mirrors: evaluate in crates/kernel/chio-kernel-core/src/evaluate.rs. -/
noncomputable def evalToolCall
    (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName)
    (serverId : ServerId)
    (now : Timestamp)
    : Decision :=
  -- Step 1: Signature
  if !verifyCapabilitySignature cap trustedKeys then
    .deny "invalid capability signature"
  -- Step 2: Time bounds
  else if now < cap.issuedAt then
    .deny "capability not yet valid"
  else if now ≥ cap.expiresAt then
    .deny "capability expired"
  -- Step 3: Revocation
  else if store.isRevoked cap.id then
    .deny s!"capability {cap.id} is revoked"
  else if cap.delegationChain.any (fun link => store.isRevoked link.delegator) then
    .deny "delegation chain revoked"
  -- Step 4: Scope
  else if !checkScope cap toolName serverId then
    .deny s!"tool {toolName} on {serverId} not in scope"
  -- If all checks pass
  else
    .allow

end Chio.Core
