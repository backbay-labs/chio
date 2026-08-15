/-
  Core type definitions: CapabilityToken, ChioScope, ToolGrant, Operation,
  Constraint, DelegationLink, Attenuation.
  Mirrors: crates/core/chio-core-types/src/capability/token.rs,
  crates/core/chio-core-types/src/capability/scope.rs, and
  crates/core/chio-core-types/src/capability/attenuation.rs.
  Enforced by the matching [[mirror]] entries in formal/proof-manifest.toml.
-/

set_option autoImplicit false

namespace Chio.Core

abbrev ServerId := String
abbrev ToolName := String
abbrev ConstraintValue := String
abbrev PublicKeyHex := String
abbrev CapabilityId := String
abbrev Timestamp := Nat

/-- Mirrors: Operation in crates/core/chio-core-types/src/capability/scope.rs. -/
inductive Operation where
  | invoke
  | readResult
  | delegate
  deriving Repr, BEq, DecidableEq, Inhabited, ReflBEq, LawfulBEq

/-- Mirrors: Constraint in crates/core/chio-core-types/src/capability/scope.rs. -/
inductive Constraint where
  | pathPrefix : String → Constraint
  | domainExact : String → Constraint
  | domainGlob : String → Constraint
  | regexMatch : String → Constraint
  | maxLength : Nat → Constraint
  | custom : String → String → Constraint
  | outputDigestSha256 : String → Constraint
  | requireFindingPurchase : String → String → String → Constraint
  | requireFindingRecovery : String → String → String → String → String → String → Nat → Constraint
  deriving Repr, BEq, DecidableEq, ReflBEq, LawfulBEq

/-- Mirrors: ToolGrant in crates/core/chio-core-types/src/capability/scope.rs. -/
structure ToolGrant where
  serverId : ServerId
  toolName : ToolName
  operations : List Operation
  constraints : List Constraint
  maxInvocations : Option Nat
  deriving Repr, BEq, ReflBEq, LawfulBEq

/-- Mirrors: ChioScope in crates/core/chio-core-types/src/capability/scope.rs. -/
structure ChioScope where
  grants : List ToolGrant
  deriving Repr, BEq, ReflBEq, LawfulBEq

/-- Mirrors: Attenuation in crates/core/chio-core-types/src/capability/attenuation.rs. -/
inductive Attenuation where
  | removeTool : ServerId → ToolName → Attenuation
  | removeOperation : ServerId → ToolName → Operation → Attenuation
  | addConstraint : ServerId → ToolName → Constraint → Attenuation
  | reduceBudget : ServerId → ToolName → Nat → Attenuation
  | shortenExpiry : Timestamp → Attenuation
  deriving Repr, BEq, ReflBEq, LawfulBEq

/-- Mirrors: DelegationLink in crates/core/chio-core-types/src/capability/attenuation.rs (signature opaque). -/
structure DelegationLink where
  delegator : PublicKeyHex
  delegatee : PublicKeyHex
  attenuations : List Attenuation
  timestamp : Timestamp
  deriving Repr, BEq, ReflBEq, LawfulBEq

/-- Mirrors: CapabilityToken in crates/core/chio-core-types/src/capability/token.rs.
    Signature and cryptographic fields are axiomatized in Crypto. -/
structure CapabilityToken where
  id : CapabilityId
  issuer : PublicKeyHex
  subject : PublicKeyHex
  scope : ChioScope
  issuedAt : Timestamp
  expiresAt : Timestamp
  delegationChain : List DelegationLink
  deriving Repr, BEq, ReflBEq, LawfulBEq

/-- Mirrors: CapabilityToken::is_valid_at in crates/core/chio-core-types/src/capability/token.rs. -/
def CapabilityToken.isValidAt (cap : CapabilityToken) (now : Timestamp) : Bool :=
  now ≥ cap.issuedAt && now < cap.expiresAt

/-- Mirrors: CapabilityToken::is_expired_at in crates/core/chio-core-types/src/capability/token.rs. -/
def CapabilityToken.isExpiredAt (cap : CapabilityToken) (now : Timestamp) : Bool :=
  now ≥ cap.expiresAt

/-- Mirrors: KernelConfig.max_delegation_depth (default). -/
def maxDelegationDepth : Nat := 32

end Chio.Core
