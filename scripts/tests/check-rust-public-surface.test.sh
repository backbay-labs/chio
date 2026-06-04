#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-rust-public-surface.py"

work="$(mktemp -d -t chio-rust-public-surface-XXXXXX)"
trap 'rm -rf "$work"' EXIT

write_member() {
  local dir="$1" name="$2" readme="${3:-README.md}"
  mkdir -p "$dir"
  mkdir -p "$dir/src"
  cat > "$dir/Cargo.toml" <<EOF
[package]
name = "$name"
description = "Synthetic public crate for gate tests"
version = "0.1.0"
edition = "2021"
publish = false
readme = "$readme"
EOF
  printf '# %s\n' "$name" > "$dir/$readme"
  printf 'pub fn marker() {}\n' > "$dir/src/lib.rs"
}

mark_public_entrypoint() {
  local manifest="$1"
  cat >> "$manifest" <<'EOF'

[package.metadata.chio]
public_entrypoint = true
EOF
}

unmark_public_entrypoint() {
  local manifest="$1"
  python3 - "$manifest" <<'PY'
from pathlib import Path
import sys

manifest = Path(sys.argv[1])
text = manifest.read_text(encoding="utf-8")
text = text.replace("\n[package.metadata.chio]\npublic_entrypoint = true\n", "\n")
manifest.write_text(text, encoding="utf-8")
PY
}

write_workspace() {
  local root="$1"
  shift
  mkdir -p "$root/crates"
  write_member "$root/crates/chio-cli" "chio-cli"
  write_member "$root/crates/chio-core" "chio-core"
  mark_public_entrypoint "$root/crates/chio-cli/Cargo.toml"
  mark_public_entrypoint "$root/crates/chio-core/Cargo.toml"
  cat > "$root/Cargo.toml" <<EOF
[workspace]
members = [
    "crates/chio-cli",
    "crates/chio-core",
]

[workspace.metadata.chio]
rust_public_entrypoints = [
$*
]
rust_registry_public_crates = []
EOF
}

run_checker() {
  local manifest="$1" stdout="$2" stderr="$3"
  local rc=0
  python3 "$CHECKER" --workspace-manifest "$manifest" >"$stdout" 2>"$stderr" || rc=$?
  echo "$rc"
}

assert_rc() {
  local got="$1" want="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $label: got rc=$got, want rc=$want" >&2
    exit 1
  fi
  echo "ok: $label (rc=$got)"
}

good="$work/good"
write_workspace "$good" '    "chio-cli",' '    "chio-core",'
assert_rc "$(run_checker "$good/Cargo.toml" "$work/good.out" "$work/good.err")" 0 \
  "valid synthetic workspace passes"

missing_root_entrypoints="$work/missing-root-entrypoints"
write_workspace "$missing_root_entrypoints" '    "chio-cli",' '    "chio-core",'
python3 - "$missing_root_entrypoints/Cargo.toml" <<'PY'
from pathlib import Path
import sys

workspace = Path(sys.argv[1])
text = workspace.read_text(encoding="utf-8")
start = text.index("rust_public_entrypoints = [")
end = text.index("]\n", start) + 2
workspace.write_text(text[:start] + text[end:], encoding="utf-8")
PY
assert_rc "$(run_checker "$missing_root_entrypoints/Cargo.toml" "$work/missing-root-entrypoints.out" "$work/missing-root-entrypoints.err")" 1 \
  "missing root public entrypoint list fails"
grep -F "workspace.metadata.chio.rust_public_entrypoints must be declared." \
  "$work/missing-root-entrypoints.err" >/dev/null

missing_registry_list="$work/missing-registry-list"
write_workspace "$missing_registry_list" '    "chio-cli",' '    "chio-core",'
python3 - "$missing_registry_list/Cargo.toml" <<'PY'
from pathlib import Path
import sys

workspace = Path(sys.argv[1])
workspace.write_text(
    workspace.read_text(encoding="utf-8").replace(
        "rust_registry_public_crates = []\n",
        "",
    ),
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$missing_registry_list/Cargo.toml" "$work/missing-registry-list.out" "$work/missing-registry-list.err")" 1 \
  "missing registry-public list fails"
grep -F "workspace.metadata.chio.rust_registry_public_crates must be declared." \
  "$work/missing-registry-list.err" >/dev/null

root_only_public_entrypoint="$work/root-only-public-entrypoint"
write_workspace "$root_only_public_entrypoint" '    "chio-cli",' '    "chio-core",'
unmark_public_entrypoint "$root_only_public_entrypoint/crates/chio-core/Cargo.toml"
assert_rc "$(run_checker "$root_only_public_entrypoint/Cargo.toml" "$work/root-only-public-entrypoint.out" "$work/root-only-public-entrypoint.err")" 1 \
  "root-listed public entrypoint without package marker fails"
grep -F "crates/chio-core/Cargo.toml is listed in workspace.metadata.chio.rust_public_entrypoints but does not declare package.metadata.chio.public_entrypoint = true." \
  "$work/root-only-public-entrypoint.err" >/dev/null

duplicate="$work/duplicate"
write_workspace "$duplicate" '    "chio-cli",' '    "chio-core",' '    "chio-core",'
assert_rc "$(run_checker "$duplicate/Cargo.toml" "$work/duplicate.out" "$work/duplicate.err")" 1 \
  "duplicate public entrypoint fails"
grep -F "duplicate rust_public_entrypoints entries: chio-core" "$work/duplicate.err" >/dev/null

unsorted="$work/unsorted"
write_workspace "$unsorted" '    "chio-core",' '    "chio-cli",'
assert_rc "$(run_checker "$unsorted/Cargo.toml" "$work/unsorted.out" "$work/unsorted.err")" 1 \
  "unsorted public entrypoints fail"
grep -F "rust_public_entrypoints must be sorted lexicographically" "$work/unsorted.err" >/dev/null

unknown="$work/unknown"
write_workspace "$unknown" '    "chio-cli",' '    "chio-core",' '    "chio-missing",'
assert_rc "$(run_checker "$unknown/Cargo.toml" "$work/unknown.out" "$work/unknown.err")" 1 \
  "unknown public entrypoint fails"
grep -F "references unknown crates: chio-missing" "$work/unknown.err" >/dev/null

padded_root_entrypoint="$work/padded-root-entrypoint"
write_workspace "$padded_root_entrypoint" '    " chio-core",' '    "chio-cli",'
assert_rc "$(run_checker "$padded_root_entrypoint/Cargo.toml" "$work/padded-root-entrypoint.out" "$work/padded-root-entrypoint.err")" 1 \
  "padded root public entrypoint fails"
grep -F "workspace.metadata.chio.rust_public_entrypoints[0] must not include leading or trailing whitespace." \
  "$work/padded-root-entrypoint.err" >/dev/null

blank_registry_entry="$work/blank-registry-entry"
write_workspace "$blank_registry_entry" '    "chio-cli",' '    "chio-core",'
python3 - "$blank_registry_entry/Cargo.toml" <<'PY'
from pathlib import Path
import sys

workspace = Path(sys.argv[1])
workspace.write_text(
    workspace.read_text(encoding="utf-8").replace(
        "rust_registry_public_crates = []\n",
        'rust_registry_public_crates = [\n    "",\n]\n',
    ),
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$blank_registry_entry/Cargo.toml" "$work/blank-registry-entry.out" "$work/blank-registry-entry.err")" 1 \
  "blank root registry-public crate fails"
grep -F "workspace.metadata.chio.rust_registry_public_crates[0] must not be empty." \
  "$work/blank-registry-entry.err" >/dev/null

missing_member_manifest="$work/missing-member-manifest"
write_workspace "$missing_member_manifest" '    "chio-cli",' '    "chio-core",'
python3 - "$missing_member_manifest/Cargo.toml" <<'PY'
from pathlib import Path
import sys

workspace = Path(sys.argv[1])
workspace.write_text(
    workspace.read_text(encoding="utf-8").replace(
        '    "crates/chio-core",\n]',
        '    "crates/chio-core",\n    "crates/chio-missing",\n]',
    ),
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$missing_member_manifest/Cargo.toml" "$work/missing-member-manifest.out" "$work/missing-member-manifest.err")" 1 \
  "missing workspace member manifest fails"
grep -F "workspace member 'crates/chio-missing' points to missing manifest crates/chio-missing/Cargo.toml." \
  "$work/missing-member-manifest.err" >/dev/null

invalid_member_manifest="$work/invalid-member-manifest"
write_workspace "$invalid_member_manifest" '    "chio-cli",' '    "chio-core",'
printf '[package\n' > "$invalid_member_manifest/crates/chio-core/Cargo.toml"
assert_rc "$(run_checker "$invalid_member_manifest/Cargo.toml" "$work/invalid-member-manifest.out" "$work/invalid-member-manifest.err")" 1 \
  "invalid workspace member manifest fails"
grep -F "workspace member 'crates/chio-core' has invalid TOML:" \
  "$work/invalid-member-manifest.err" >/dev/null

missing_package_table="$work/missing-package-table"
write_workspace "$missing_package_table" '    "chio-cli",' '    "chio-core",'
printf '[lib]\npath = \"src/lib.rs\"\n' > "$missing_package_table/crates/chio-core/Cargo.toml"
assert_rc "$(run_checker "$missing_package_table/Cargo.toml" "$work/missing-package-table.out" "$work/missing-package-table.err")" 1 \
  "workspace member without package table fails"
grep -F "crates/chio-core/Cargo.toml does not declare a [package] table." \
  "$work/missing-package-table.err" >/dev/null

missing_package_name="$work/missing-package-name"
write_workspace "$missing_package_name" '    "chio-cli",' '    "chio-core",'
python3 - "$missing_package_name/crates/chio-core/Cargo.toml" <<'PY'
from pathlib import Path
import sys

manifest = Path(sys.argv[1])
manifest.write_text(
    "\n".join(
        line
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if not line.startswith("name = ")
    )
    + "\n",
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$missing_package_name/Cargo.toml" "$work/missing-package-name.out" "$work/missing-package-name.err")" 1 \
  "workspace member without package name fails"
grep -F "crates/chio-core/Cargo.toml does not declare a non-empty package name." \
  "$work/missing-package-name.err" >/dev/null

duplicate_package_name="$work/duplicate-package-name"
write_workspace "$duplicate_package_name" '    "chio-cli",' '    "chio-core",'
python3 - "$duplicate_package_name/crates/chio-core/Cargo.toml" <<'PY'
from pathlib import Path
import sys

manifest = Path(sys.argv[1])
manifest.write_text(
    manifest.read_text(encoding="utf-8").replace(
        'name = "chio-core"',
        'name = "chio-cli"',
    ),
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$duplicate_package_name/Cargo.toml" "$work/duplicate-package-name.out" "$work/duplicate-package-name.err")" 1 \
  "duplicate workspace package names fail"
grep -F "workspace package name 'chio-cli' appears in multiple member manifests: crates/chio-cli/Cargo.toml, crates/chio-core/Cargo.toml." \
  "$work/duplicate-package-name.err" >/dev/null

unlisted_publishable="$work/unlisted-publishable"
write_workspace "$unlisted_publishable" '    "chio-cli",' '    "chio-core",'
write_member "$unlisted_publishable/crates/chio-leaky" "chio-leaky"
python3 - "$unlisted_publishable/Cargo.toml" "$unlisted_publishable/crates/chio-leaky/Cargo.toml" <<'PY'
from pathlib import Path
import sys

workspace = Path(sys.argv[1])
workspace.write_text(
    workspace.read_text(encoding="utf-8").replace(
        '    "crates/chio-core",\n]',
        '    "crates/chio-core",\n    "crates/chio-leaky",\n]',
    ),
    encoding="utf-8",
)

manifest = Path(sys.argv[2])
manifest.write_text(
    manifest.read_text(encoding="utf-8").replace("publish = false\n", ""),
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$unlisted_publishable/Cargo.toml" "$work/unlisted-publishable.out" "$work/unlisted-publishable.err")" 1 \
  "unlisted publishable crate fails"
grep -F "crates/chio-leaky/Cargo.toml must set publish = false or be listed in workspace.metadata.chio.rust_registry_public_crates." \
  "$work/unlisted-publishable.err" >/dev/null

registry_private_dep="$work/registry-private-dep"
write_workspace "$registry_private_dep" '    "chio-cli",' '    "chio-core",'
write_member "$registry_private_dep/crates/chio-harness" "chio-harness"
python3 - "$registry_private_dep/Cargo.toml" "$registry_private_dep/crates/chio-harness/Cargo.toml" <<'PY'
from pathlib import Path
import sys

workspace = Path(sys.argv[1])
workspace.write_text(
    workspace.read_text(encoding="utf-8")
    .replace(
        '    "crates/chio-core",\n]',
        '    "crates/chio-core",\n    "crates/chio-harness",\n]',
    )
    .replace(
        "rust_registry_public_crates = []\n",
        'rust_registry_public_crates = [\n    "chio-harness",\n]\n',
    ),
    encoding="utf-8",
)

manifest = Path(sys.argv[2])
manifest.write_text(
    manifest.read_text(encoding="utf-8").replace("publish = false\n", "")
    + '\n[dependencies]\nchio-core = { version = "0.1.0", path = "../chio-core" }\n',
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$registry_private_dep/Cargo.toml" "$work/registry-private-dep.out" "$work/registry-private-dep.err")" 1 \
  "registry-public crate depending on private workspace crate fails"
grep -F 'crates/chio-harness/Cargo.toml is registry-public but dependency `chio-core` points at workspace crate `chio-core`, which is not listed in workspace.metadata.chio.rust_registry_public_crates.' \
  "$work/registry-private-dep.err" >/dev/null

missing_readme="$work/missing-readme"
write_workspace "$missing_readme" '    "chio-cli",' '    "chio-core",'
rm "$missing_readme/crates/chio-core/README.md"
assert_rc "$(run_checker "$missing_readme/Cargo.toml" "$work/missing-readme.out" "$work/missing-readme.err")" 1 \
  "missing public entrypoint README fails"
grep -F "crates/chio-core/Cargo.toml points to missing README 'README.md'" \
  "$work/missing-readme.err" >/dev/null

escaped_readme="$work/escaped-readme"
write_workspace "$escaped_readme" '    "chio-cli",' '    "chio-core",'
printf '# shared\n' > "$escaped_readme/crates/README.md"
python3 - "$escaped_readme/crates/chio-core/Cargo.toml" <<'PY'
from pathlib import Path
import sys

manifest = Path(sys.argv[1])
manifest.write_text(
    manifest.read_text(encoding="utf-8").replace(
        'readme = "README.md"',
        'readme = "../README.md"',
    ),
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$escaped_readme/Cargo.toml" "$work/escaped-readme.out" "$work/escaped-readme.err")" 1 \
  "public entrypoint README escaping crate root fails"
grep -F "crates/chio-core/Cargo.toml declares README '../README.md' outside the package directory." \
  "$work/escaped-readme.err" >/dev/null

directory_readme="$work/directory-readme"
write_workspace "$directory_readme" '    "chio-cli",' '    "chio-core",'
python3 - "$directory_readme/crates/chio-core/Cargo.toml" <<'PY'
from pathlib import Path
import sys

manifest = Path(sys.argv[1])
manifest.write_text(
    manifest.read_text(encoding="utf-8").replace(
        'readme = "README.md"',
        'readme = "src"',
    ),
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$directory_readme/Cargo.toml" "$work/directory-readme.out" "$work/directory-readme.err")" 1 \
  "public entrypoint README directory fails"
grep -F "crates/chio-core/Cargo.toml declares README 'src' but it is not a file." \
  "$work/directory-readme.err" >/dev/null

missing_description="$work/missing-description"
write_workspace "$missing_description" '    "chio-cli",' '    "chio-core",'
python3 - "$missing_description/crates/chio-core/Cargo.toml" <<'PY'
from pathlib import Path
import sys

manifest = Path(sys.argv[1])
manifest.write_text(
    "\n".join(
        line
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if not line.startswith("description = ")
    )
    + "\n",
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$missing_description/Cargo.toml" "$work/missing-description.out" "$work/missing-description.err")" 1 \
  "missing public entrypoint description fails"
grep -F "crates/chio-core/Cargo.toml is a public entrypoint but does not declare a non-empty package description." \
  "$work/missing-description.err" >/dev/null

missing_target="$work/missing-target"
write_workspace "$missing_target" '    "chio-cli",' '    "chio-core",'
rm "$missing_target/crates/chio-core/src/lib.rs"
assert_rc "$(run_checker "$missing_target/Cargo.toml" "$work/missing-target.out" "$work/missing-target.err")" 1 \
  "missing public entrypoint implementation target fails"
grep -F "crates/chio-core/Cargo.toml is a public entrypoint but does not declare an existing lib or bin target." \
  "$work/missing-target.err" >/dev/null

local_public_marker="$work/local-public-marker"
write_workspace "$local_public_marker" '    "chio-cli",'
assert_rc "$(run_checker "$local_public_marker/Cargo.toml" "$work/local-public-marker.out" "$work/local-public-marker.err")" 1 \
  "package-local public entrypoint marker missing from root list fails"
grep -F "crates/chio-core/Cargo.toml declares package.metadata.chio.public_entrypoint = true but is missing from workspace.metadata.chio.rust_public_entrypoints." \
  "$work/local-public-marker.err" >/dev/null

echo "check-rust-public-surface.test.sh: all assertions passed"
