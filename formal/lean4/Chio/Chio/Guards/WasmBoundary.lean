/-
  Bounded model of the core-module wasm guard decision boundary.

  Rust grounding table (line numbers are pinned to this revision):

  GuestOutput                Producer                                      Consumer
  verdictAllow               wasmtime_backend.rs L45-L50, L715-L716         guard.rs L369-L378
  verdictDeny (some reason)  wasmtime_backend.rs L45-L50, L717-L730         guard.rs L379-L398
  verdictDeny none           wasmtime_backend.rs L778-L815                  guard.rs L379-L398
  verdictUnknown code        wasmtime_backend.rs L45-L50, L732-L737         guard.rs L400-L416
  trap                       wasmtime_backend.rs L689-L708                  guard.rs L400-L416
  fuelExhausted              wasmtime_backend.rs L689-L704                  guard.rs L400-L416
  memoryExhausted            host.rs L96-L121                              guard.rs L400-L416

  Host-side malformed action extraction does not execute guest code and
  denies at runtime/guard.rs L332-L340. Load-layer errors leave this model and
  enter the existing pipeline error path at runtime/guard.rs L353-L358.

  This is a model of Chio's dispatch logic. It assumes that wasmtime enforces
  its documented i32 return, trap, fuel, and memory-limiter semantics. It does
  not verify the wasmtime interpreter, compiler, JIT, or sandbox, and it does
  not establish full engine information-flow non-interference. Host imports
  and reentry remain empirically exercised by the wasm escape fuzz target.
-/

import Chio.Proofs.Protocol

set_option autoImplicit false

namespace Chio.Guards.WasmBoundary

open Chio.Core

structure HostInputs where
  coreAuthorized : Bool
  advisory : Bool
  deriving Repr, BEq

/-
  Field-for-field shape of the serialized GuardRequest. argumentsJson is an
  uninterpreted encoding in this model because no theorem inspects guest arguments.
-/
structure GuestVisible where
  toolName : String
  serverId : String
  agentId : String
  argumentsJson : String
  scopes : List String
  actionType : Option String
  extractedPath : Option String
  extractedTarget : Option String
  filesystemRoots : List String
  matchedGrantIndex : Option Nat
  deriving Repr, BEq

inductive GuestOutput where
  | verdictAllow
  | verdictDeny (reason : Option String)
  | verdictUnknown (code : Int)
  | trap
  | fuelExhausted
  | memoryExhausted
  deriving Repr, BEq

def interpret (host : HostInputs) : GuestOutput -> GuardResult
  | .verdictAllow => .allow
  | .verdictDeny _ => if host.advisory then .allow else .deny
  | .verdictUnknown _ => if host.advisory then .allow else .deny
  | .trap => if host.advisory then .allow else .deny
  | .fuelExhausted => if host.advisory then .allow else .deny
  | .memoryExhausted => if host.advisory then .allow else .deny

def evaluateBoundary
    (host : HostInputs)
    (visible : GuestVisible)
    (before after : List GuardResult)
    (decode : GuestVisible → GuestOutput) : Bool :=
  guardPipelineAllows host.coreAuthorized
    (before ++ [interpret host (decode visible)] ++ after)

theorem guest_output_confinement
    (host : HostInputs)
    (visible₁ visible₂ : GuestVisible)
    (before after : List GuardResult)
    (decode₁ decode₂ : GuestVisible → GuestOutput)
    (h_output : decode₁ visible₁ = decode₂ visible₂) :
    evaluateBoundary host visible₁ before after decode₁ =
      evaluateBoundary host visible₂ before after decode₂ := by
  simp [evaluateBoundary, h_output]

theorem malformed_deny_reason_preserves_decision
    (host : HostInputs)
    (reason : String) :
    interpret host (.verdictDeny none) =
      interpret host (.verdictDeny (some reason)) := by
  simp [interpret]

theorem blocking_unknown_verdict_denies
    (host : HostInputs)
    (code : Int) :
    interpret { host with advisory := false } (.verdictUnknown code) = .deny := by
  simp [interpret]

theorem no_allow_amplification
    (host : HostInputs)
    (visible : GuestVisible)
    (output : GuestOutput)
    (guestInterpret : HostInputs → GuestVisible → GuestOutput → GuardResult)
    (before after : List GuardResult) :
    guardPipelineAllows false
      (before ++ [guestInterpret host visible output] ++ after) = false := by
  simp [guardPipelineAllows]

theorem resource_exhaustion_fail_closed
    (host : HostInputs)
    (h_blocking : host.advisory = false) :
    interpret host .fuelExhausted = .deny ∧
      interpret host .memoryExhausted = .deny ∧
      interpret host .trap = .deny := by
  simp [interpret, h_blocking]

theorem advisory_mode_is_nonblocking_by_design
    (host : HostInputs)
    (output : GuestOutput) :
    interpret { host with advisory := true } output = .allow := by
  cases output <;> simp [interpret]

end Chio.Guards.WasmBoundary
