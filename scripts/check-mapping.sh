#!/usr/bin/env bash
# scripts/check-mapping.sh
#
# Cross-reference gate for formal/MAPPING.md. Asserts that every named
# TLA+ safety/liveness invariant in the revocation propagation models,
# every required leaf invariant in its model's aggregate SafetyInv,
# every drop-guard invariant in formal/apalache/PostAdmissionDropGuard.tla,
# every #[kani::proof] harness in
# crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs, every registered
# Loom model, and every deterministic simulation harness has a corresponding
# row in formal/MAPPING.md. Exits non-zero with a human-readable diff if any
# property is unmapped.

set -euo pipefail

# --- Repo root ---------------------------------------------------------------
# Resolve to the repo root regardless of where the script is invoked from.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

mapping="formal/MAPPING.md"
tla="formal/tla/RevocationPropagation.tla"
distributed_tla="formal/tla/DistributedRevocation.tla"
distributed_temporal_tla="formal/tla/DistributedRevocationTemporal.tla"
drop_guard_tla="formal/apalache/PostAdmissionDropGuard.tla"
kani="crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs"
loom_manifest=".loom/harnesses.toml"
loom_runner="scripts/run-loom-manifest.sh"
dst_manifest=".dst/harnesses.toml"
dst_runner="scripts/run-dst.sh"
required_model_files=(
  "formal/tla/RevocationPropagation.tla"
  "formal/apalache/ReceiptBeforeAllow.tla"
  "formal/apalache/RevocationCutCompleteness.tla"
)
required_model_invariants=(
  "RevocationStateCoupled"
  "AllowReceiptsBudgetChecked"
  "DirectParentInClosure"
)

# --- Sanity: source files must exist ----------------------------------------
missing_inputs=0
for f in "${mapping}" "${tla}" "${distributed_tla}" "${drop_guard_tla}" "${kani}" "${loom_manifest}" "${loom_runner}" "${dst_manifest}" "${dst_runner}" "${required_model_files[@]}"; do
  if [[ ! -f "${f}" ]]; then
    echo "check-mapping: required input is missing: ${f}" >&2
    missing_inputs=1
  fi
done
if [[ "${missing_inputs}" -ne 0 ]]; then
  exit 1
fi

# --- Concurrency registries -------------------------------------------------
registry_mapping_lists() {
  local runner="$1"
  local heading="$2"
  local registry_list mapping_list
  registry_list="$(bash "${runner}" --lane all --list | sed 's/.*:://' | LC_ALL=C sort)"
  if [[ -z "${registry_list}" ]]; then
    echo "check-mapping: ${heading} registry produced no harnesses" >&2
    return 1
  fi
  if [[ -n "$(printf '%s\n' "${registry_list}" | uniq -d)" ]]; then
    echo "check-mapping: ${heading} registry has duplicate short names" >&2
    return 1
  fi
  mapping_list="$(
    awk -v heading="## ${heading}" '
      $0 == heading { inside = 1; next }
      /^## / && inside { exit }
      inside && /^[[:space:]]*\|[[:space:]]*`/ {
        line = $0
        sub(/^[[:space:]]*\|[[:space:]]*`/, "", line)
        sub(/`.*/, "", line)
        print line
      }
    ' "${mapping}" | LC_ALL=C sort
  )"
  printf '%s\034%s\n' "${registry_list}" "${mapping_list}"
}

loom_lists="$(registry_mapping_lists "${loom_runner}" "Loom interleaving harnesses")"
loom_harness_list="${loom_lists%%$'\034'*}"
loom_mapping_list="${loom_lists#*$'\034'}"
dst_lists="$(registry_mapping_lists "${dst_runner}" "Deterministic simulation harnesses")"
dst_harness_list="${dst_lists%%$'\034'*}"
dst_mapping_list="${dst_lists#*$'\034'}"

unmapped_loom="$(LC_ALL=C comm -23 <(printf '%s\n' "${loom_harness_list}") <(printf '%s\n' "${loom_mapping_list}"))"
extra_loom_mapping="$(LC_ALL=C comm -13 <(printf '%s\n' "${loom_harness_list}") <(printf '%s\n' "${loom_mapping_list}"))"
unmapped_dst="$(LC_ALL=C comm -23 <(printf '%s\n' "${dst_harness_list}") <(printf '%s\n' "${dst_mapping_list}"))"
extra_dst_mapping="$(LC_ALL=C comm -13 <(printf '%s\n' "${dst_harness_list}") <(printf '%s\n' "${dst_mapping_list}"))"

# --- Required model leaf invariants -----------------------------------------
# These leaves are part of the release evidence contract. Unlike the legacy
# whitelists below, they are mandatory: deleting a definition or dropping it
# from SafetyInv must fail even if the mapping row remains.
safety_inv_contains() {
  local source_file="$1"
  local invariant_name="$2"

  awk '
    /^SafetyInv[[:space:]]*==/ { in_safety_inv = 1; next }
    in_safety_inv && /^[[:alpha:]_][[:alnum:]_]*[[:space:]]*==/ { exit }
    in_safety_inv && /^=+[[:space:]]*$/ { exit }
    in_safety_inv { print }
  ' "${source_file}" \
    | grep -qE "^[[:space:]]*/\\\\[[:space:]]+${invariant_name}[[:space:]]*$"
}

missing_model_definitions=()
missing_safety_conjuncts=()
for index in "${!required_model_invariants[@]}"; do
  name="${required_model_invariants[${index}]}"
  source_file="${required_model_files[${index}]}"
  if ! grep -qE "^${name}[[:space:]]*==" "${source_file}"; then
    missing_model_definitions+=("${name} (${source_file})")
  fi
  if ! safety_inv_contains "${source_file}" "${name}"; then
    missing_safety_conjuncts+=("${name} (${source_file})")
  fi
done

# --- TLA+ named invariants ---------------------------------------------------
# The named-invariants whitelist below is the canonical set of safety /
# liveness invariants for RevocationPropagation. We require: any whitelisted name
# that is *defined* in the .tla file (top-level `<Name> ==`) must appear as
# a row in MAPPING.md. Undefined whitelist entries are not enforced.
#
# Helper definitions like DomainsOK, States, Verdicts, ProcSet, CapSet,
# DEPTH_MAX, Init, Next, Spec, vars, Receipt, Message, Attenuate, Revoke,
# Propagate, Evaluate, and the aggregate SafetyInv are intentionally NOT
# enforced: they are not the named invariants the formal mapping doc and the
# Apalache .cfg cite. The aggregate SafetyInv is the conjunction the .cfg
# checks; the leaf-named invariants below are the unit of cross-reference.
named_tla_invariants=(
  "NoAllowAfterRevoke"
  "MonotoneLog"
  "AttenuationPreserving"
  "RevocationEventuallySeen"
  "RevocationFreshness"
  "DistributedDomainsOK"
  "ClockSkewBound"
  "SignerPinnedHighWater"
  "NoAllowAfterRevokeDistributed"
  "StaleEvaluationDenied"
  "RejectedRawEvaluationCountBound"
  "PartitionSuspendResume"
  "RevocationEventuallyObservedDistributed"
)

defined_tla_invariants=()
for name in "${named_tla_invariants[@]}"; do
  # Match a top-level definition `<name> ==` (allowing whitespace before ==).
  # Does NOT match references inside other definitions because the regex is
  # anchored at the start of the line.
  if grep -qE "^${name}[[:space:]]*==" "${tla}" || \
     grep -qE "^${name}[[:space:]]*==" "${distributed_tla}" || \
     grep -qE "^${name}[[:space:]]*==" "${distributed_temporal_tla}"; then
    defined_tla_invariants+=("${name}")
  fi
done

named_drop_guard_invariants=(
  "ReservationConservation"
  "TerminalReceiptExactlyOne"
  "ChildReceiptsFlushed"
  "RetainedIffAborted"
)

defined_drop_guard_invariants=()
for name in "${named_drop_guard_invariants[@]}"; do
  if grep -qE "^${name}[[:space:]]*==" "${drop_guard_tla}"; then
    defined_drop_guard_invariants+=("${name}")
  fi
done

# --- Kani #[kani::proof] harnesses ------------------------------------------
# Extract the function name on the first `fn <ident>(` line that follows
# each #[kani::proof] attribute. The harness body and helper functions are
# intentionally ignored.
#
# The parser tolerates blank lines, comments (`//`, `/* */`), and stacked
# attributes (e.g. `#[kani::unwind(N)]`) between the `#[kani::proof]`
# attribute and the `fn` declaration, so a harness whose declaration is
# preceded by such intervening lines is not dropped from the gate.
#
# Portability: this script targets bash 3.2 (default macOS) and BSD awk.
# That rules out `mapfile` and the gawk-only 3-arg `match()`. We use a
# state machine in awk and sub() to strip everything except the identifier.
kani_harness_list="$(
  awk '
    /^#\[kani::proof\]/ { want = 1; next }
    want {
      line = $0
      # Strip leading whitespace.
      sub(/^[[:space:]]+/, "", line)
      # Skip blank lines, line comments, block-comment openers, and stacked
      # attributes - keep `want = 1` until we actually see a `fn` line.
      if (line == "") { next }
      if (line ~ /^\/\//) { next }
      if (line ~ /^\/\*/) { next }
      if (line ~ /^\*/) { next }
      if (line ~ /^#\[/) { next }
      # We expect `fn <ident>(...)` or `pub fn <ident>(...)`. Anything
      # else means the attribute was not followed by a function
      # definition; reset and continue scanning. Harnesses are usually
      # `pub fn`; the parser tolerates either visibility.
      if (line ~ /^pub[[:space:]]+/) { sub(/^pub[[:space:]]+/, "", line) }
      if (line !~ /^fn[[:space:]]+/) { want = 0; next }
      sub(/^fn[[:space:]]+/, "", line)
      # Strip everything from the first `(` or `<` onward (generic params).
      sub(/[(<].*/, "", line)
      # Strip any residual whitespace.
      sub(/[[:space:]]+$/, "", line)
      if (line != "") {
        print line
      }
      want = 0
    }
  ' "${kani}" | LC_ALL=C sort
)"

kani_harnesses=()
if [[ -n "${kani_harness_list}" ]]; then
  while IFS= read -r line; do
    kani_harnesses+=("${line}")
  done <<< "${kani_harness_list}"
fi

# --- Mapping presence check --------------------------------------------------
# For each enforced name, require it to appear as `<name>` (backtick-wrapped)
# inside a markdown TABLE ROW in formal/MAPPING.md. Table rows begin with
# `|` (after optional leading whitespace); the table-header separator row
# (`| ----- | ----- |`) is filtered out below. Prose mentions, bullet
# lists, and code-fence excerpts are NOT counted - they are not the unit
# of cross-reference the gate is asserting. Without this scoping the gate
# fail-opens whenever the author drops a backtick mention of a property name
# into prose.
table_rows="$(grep -E '^[[:space:]]*\|' "${mapping}" \
    | grep -v -E '^[[:space:]]*\|[[:space:]]*-+' || true)"

unmapped_tla=()
for name in "${defined_tla_invariants[@]}"; do
  if ! grep -qF "\`${name}\`" <<< "${table_rows}"; then
    unmapped_tla+=("${name}")
  fi
done

unmapped_drop_guard=()
for name in "${defined_drop_guard_invariants[@]}"; do
  if ! grep -qF "\`${name}\`" <<< "${table_rows}"; then
    unmapped_drop_guard+=("${name}")
  fi
done

unmapped_required_model=()
for name in "${required_model_invariants[@]}"; do
  if ! grep -qF "\`${name}\`" <<< "${table_rows}"; then
    unmapped_required_model+=("${name}")
  fi
done

unmapped_kani=()
# bash 3.2 / `set -u` rejects expansion of empty arrays via `${arr[@]}`.
# Guard the loop so an empty harness list does not crash the script.
if [[ "${#kani_harnesses[@]}" -gt 0 ]]; then
  for name in "${kani_harnesses[@]}"; do
    # Skip empty entries that can arise if the file has no harnesses.
    if [[ -z "${name}" ]]; then
      continue
    fi
    if ! grep -qF "\`${name}\`" <<< "${table_rows}"; then
      unmapped_kani+=("${name}")
    fi
  done
fi

# --- Reporting ---------------------------------------------------------------
echo "check-mapping: scanning ${mapping}"
echo "  Required model leaf invariants enforced (${#required_model_invariants[@]}):"
for index in "${!required_model_invariants[@]}"; do
  echo "    - ${required_model_invariants[${index}]} (${required_model_files[${index}]})"
done
echo "  TLA+ invariants enforced (${#defined_tla_invariants[@]} of ${#named_tla_invariants[@]} whitelisted across the revocation models):"
for name in "${defined_tla_invariants[@]}"; do
  echo "    - ${name}"
done
echo "  Drop-guard invariants enforced (${#defined_drop_guard_invariants[@]} of ${#named_drop_guard_invariants[@]} whitelisted defined in ${drop_guard_tla}):"
for name in "${defined_drop_guard_invariants[@]}"; do
  echo "    - ${name}"
done
echo "  Kani harnesses enforced (${#kani_harnesses[@]} from ${kani}):"
for name in "${kani_harnesses[@]}"; do
  if [[ -n "${name}" ]]; then
    echo "    - ${name}"
  fi
done
echo "  Loom harnesses enforced ($(printf '%s\n' "${loom_harness_list}" | awk 'NF { count++ } END { print count + 0 }') from ${loom_manifest}):"
printf '%s\n' "${loom_harness_list}" | sed 's/^/    - /'
echo "  DST harnesses enforced ($(printf '%s\n' "${dst_harness_list}" | awk 'NF { count++ } END { print count + 0 }') from ${dst_manifest}):"
printf '%s\n' "${dst_harness_list}" | sed 's/^/    - /'

failures=0

if [[ "${#missing_model_definitions[@]}" -gt 0 ]]; then
  failures=$((failures + ${#missing_model_definitions[@]}))
  echo "" >&2
  echo "check-mapping: FAIL - ${#missing_model_definitions[@]} required model invariant definition(s) missing:" >&2
  for entry in "${missing_model_definitions[@]}"; do
    echo "  - ${entry}" >&2
  done
fi

if [[ "${#missing_safety_conjuncts[@]}" -gt 0 ]]; then
  failures=$((failures + ${#missing_safety_conjuncts[@]}))
  echo "" >&2
  echo "check-mapping: FAIL - ${#missing_safety_conjuncts[@]} required invariant(s) missing from SafetyInv:" >&2
  for entry in "${missing_safety_conjuncts[@]}"; do
    echo "  - ${entry}" >&2
  done
fi

if [[ "${#unmapped_required_model[@]}" -gt 0 ]]; then
  failures=$((failures + ${#unmapped_required_model[@]}))
  echo "" >&2
  echo "check-mapping: FAIL - ${#unmapped_required_model[@]} required model invariant(s) not cited in ${mapping}:" >&2
  for name in "${unmapped_required_model[@]}"; do
    echo "  - ${name}" >&2
  done
  echo "" >&2
  echo "  Add a table row containing the exact backtick-wrapped invariant name." >&2
fi

if [[ "${#unmapped_tla[@]}" -gt 0 ]]; then
  failures=$((failures + ${#unmapped_tla[@]}))
  echo ""
  echo "check-mapping: FAIL - ${#unmapped_tla[@]} TLA+ invariant(s) defined in ${tla} but not cited in ${mapping}:" >&2
  for name in "${unmapped_tla[@]}"; do
    echo "  - ${name}" >&2
  done
  echo "" >&2
  echo "  Add a row to the 'TLA+ named invariants' table in ${mapping}." >&2
  echo "  The literal token must appear as \`${unmapped_tla[0]}\` (backtick-wrapped)." >&2
fi

if [[ "${#unmapped_drop_guard[@]}" -gt 0 ]]; then
  failures=$((failures + ${#unmapped_drop_guard[@]}))
  echo ""
  echo "check-mapping: FAIL - ${#unmapped_drop_guard[@]} invariant(s) defined in ${drop_guard_tla} but not cited in ${mapping}:" >&2
  for name in "${unmapped_drop_guard[@]}"; do
    echo "  - ${name}" >&2
  done
  echo "" >&2
  echo "  Add a row to the 'Apalache named invariants' table in ${mapping}." >&2
  echo "  The literal token must appear as \`${unmapped_drop_guard[0]}\` (backtick-wrapped)." >&2
fi

if [[ "${#unmapped_kani[@]}" -gt 0 ]]; then
  failures=$((failures + ${#unmapped_kani[@]}))
  echo ""
  echo "check-mapping: FAIL - ${#unmapped_kani[@]} Kani harness(es) defined in ${kani} but not cited in ${mapping}:" >&2
  for name in "${unmapped_kani[@]}"; do
    echo "  - ${name}" >&2
  done
  echo "" >&2
  echo "  Add a row to the 'Kani public harnesses' table in ${mapping}." >&2
  echo "  The literal token must appear as \`${unmapped_kani[0]}\` (backtick-wrapped)." >&2
fi

for registry in loom dst; do
  if [[ "${registry}" == "loom" ]]; then
    label="Loom"
    missing="${unmapped_loom}"
    extra="${extra_loom_mapping}"
  else
    label="DST"
    missing="${unmapped_dst}"
    extra="${extra_dst_mapping}"
  fi
  if [[ -n "${missing}" ]]; then
    count="$(printf '%s\n' "${missing}" | awk 'NF { count++ } END { print count + 0 }')"
    failures=$((failures + count))
    echo "" >&2
    echo "check-mapping: FAIL - ${count} registered ${label} harness(es) are not mapped:" >&2
    printf '%s\n' "${missing}" | sed 's/^/  - /' >&2
  fi
  if [[ -n "${extra}" ]]; then
    count="$(printf '%s\n' "${extra}" | awk 'NF { count++ } END { print count + 0 }')"
    failures=$((failures + count))
    echo "" >&2
    echo "check-mapping: FAIL - ${count} ${label} mapping row(s) are not registered:" >&2
    printf '%s\n' "${extra}" | sed 's/^/  - /' >&2
  fi
done

if [[ "${failures}" -ne 0 ]]; then
  echo "" >&2
  echo "check-mapping: ${failures} unmapped property(ies). Failing closed." >&2
  exit 1
fi

echo ""
echo "check-mapping: OK - every enforced property is mapped."
exit 0
