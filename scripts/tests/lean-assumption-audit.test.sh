#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

cat >"${tmp_dir}/CleanSyntax.lean" <<'LEAN'
import Lean

open Lean Elab Command

set_option linter.unusedVariables false

def commandQuote : MacroM (TSyntax `command) := `(namespace Chio.Json)
def nestedQuote : MacroM (TSyntax `command) :=
  `(def quoted : MacroM (TSyntax `command) := `(namespace Wrong))

syntax "namespace" ident : term
macro_rules
  | `(namespace $name) => `(0)

def termDecoy := namespace Chio.Json

def interpolationComment := s!"{by
  /- { -/
  exact 1
}"
def nestedInterpolation := s!"outer {s!"inner {by
  /- { } -/
  exact 1
}"} tail"
def rawInterpolation := s!"outer {r#"{ not interpolation }"#} tail"

syntax "namespace_tactic" ident : tactic
macro_rules
  | `(tactic| namespace_tactic $name) => `(tactic| exact True.intro)

theorem tacticDecoy : True := by
  namespace_tactic Chio.Json

@[inline]
def attributeDecoy := 0

namespace SameLine def sameLineDecoy := 0 end SameLine
LEAN

cat >"${tmp_dir}/AuditMalicious.lean" <<'LEAN'
import Lean

open Lean Elab Command

set_option linter.unusedVariables false

def commandQuote : MacroM (TSyntax `command) := `(namespace Chio.Json)

syntax "namespace" ident : term
macro_rules
  | `(namespace $name) => `(0)

def termDecoy := namespace Chio.Json

axiom hash_collision_resistant : Prop
axiom
  multilineWitness : Prop
private axiom privateWitness : Prop
@[simp] axiom attributedWitness : True
namespace SameLine axiom sameLineWitness : Prop end SameLine

opaque publicOpaque : Nat := 0
private opaque privateOpaque : Nat := 0

elab "emitOpaque " name:ident : command => do
  elabCommand (← `(opaque $name : Nat := 0))

elab "emitPrivateOpaque " name:ident : command => do
  elabCommand (← `(private opaque $name : Nat := 0))

emitOpaque generatedOpaque
emitPrivateOpaque generatedPrivateOpaque
LEAN

lean_root="formal/lean4/Chio"
helper="$(pwd)/scripts/lean-assumption-audit.lean"

(
  cd "${lean_root}"
  lake env lean -R "${tmp_dir}" \
    -o "${tmp_dir}/CleanSyntax.olean" "${tmp_dir}/CleanSyntax.lean"
  lake env lean -R "${tmp_dir}" \
    -o "${tmp_dir}/AuditMalicious.olean" "${tmp_dir}/AuditMalicious.lean"
)

run_audit() {
  local module="$1"
  (
    cd "${lean_root}"
    LEAN_PATH="${tmp_dir}:${LEAN_PATH:-}" \
      lake env lean --run "${helper}" "${module}" -- "${module}"
  )
}

clean_output="$(run_audit CleanSyntax)"
if [[ -n "${clean_output}" ]]; then
  echo "syntax decoys produced environment assumptions: ${clean_output}" >&2
  exit 1
fi

expected_output="$(cat <<'ROWS'
axiom	AuditMalicious	SameLine.sameLineWitness
axiom	AuditMalicious	_private.AuditMalicious.0.privateWitness
axiom	AuditMalicious	attributedWitness
axiom	AuditMalicious	hash_collision_resistant
axiom	AuditMalicious	multilineWitness
opaque	AuditMalicious	_private.AuditMalicious.0.generatedPrivateOpaque
opaque	AuditMalicious	_private.AuditMalicious.0.privateOpaque
opaque	AuditMalicious	generatedOpaque
opaque	AuditMalicious	publicOpaque
ROWS
)"
malicious_output="$(run_audit AuditMalicious)"
if [[ "${malicious_output}" != "${expected_output}" ]]; then
  printf 'unexpected malicious audit output:\n%s\n' "${malicious_output}" >&2
  exit 1
fi

set +e
missing_separator_output="$(
  cd "${lean_root}"
  lake env lean --run "${helper}" CleanSyntax 2>&1
)"
missing_separator_exit=$?
set -e
if [[ "${missing_separator_exit}" -eq 0 ]] || \
    ! grep -Fq "expected root imports, --, then audited modules" \
      <<<"${missing_separator_output}"; then
  echo "invalid audit arguments did not fail closed with their exact cause" >&2
  exit 1
fi

echo "PASS: elaborated Lean assumptions include public, private, and generated declarations"
