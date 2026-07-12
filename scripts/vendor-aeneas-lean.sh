#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

release_tag="build-2026.04.22.215158-38d10a22642d75d051e14006cc6e45055381f10e"
revision="38d10a22642d75d051e14006cc6e45055381f10e"
archive_sha256="3ff189e5ec2e7d9c8bacfbb72ea4540542e1ddf09a36ab615e8bb02a9b54dc6d"
mathlib_revision="8f9d9cff6bd728b17a24e163c9402775d9e6a365"
lean_toolchain="leanprover/lean4:v4.28.0"
vendor_dir="formal/lean4/vendor/aeneas"
archive_url="https://github.com/AeneasVerif/aeneas/archive/${revision}.tar.gz"

temporary_dir="$(mktemp -d)"
trap 'rm -rf "${temporary_dir}"' EXIT

archive="${temporary_dir}/aeneas.tar.gz"
curl -fsSL "${archive_url}" -o "${archive}"
echo "${archive_sha256}  ${archive}" | sha256sum -c -

tar -xzf "${archive}" -C "${temporary_dir}"
upstream="${temporary_dir}/aeneas-${revision}"
staging="${temporary_dir}/vendor"
mkdir -p "${staging}"

cp "${upstream}/LICENSE.md" "${staging}/LICENSE.md"

python3 - "${upstream}/backends/lean" "${staging}" <<'PY'
import re
import shutil
import sys
from pathlib import Path

source_root = Path(sys.argv[1])
staging = Path(sys.argv[2])
support_roots = [
    "Aeneas.Std.Primitives",
    "Aeneas.Std.Core.Core",
    "Aeneas.Std.Core.Fmt",
    "Aeneas.Std.Core.Default",
    "Aeneas.Std.Core.Cmp",
    "Aeneas.Std.Core.Marker",
    "Aeneas.Std.Core.Ops",
    "Aeneas.Std.Scalar.Core",
    "Aeneas.Std.Scalar.Elab",
    "Aeneas.Std.Scalar.EqOrd",
    "Aeneas.Std.Scalar.Default",
    "Aeneas.Std.Scalar.CloneCopy",
    "Aeneas.Std.Scalar.Casts",
    "Aeneas.Std.Scalar.CheckedOps",
    "Aeneas.Std.Scalar.Ops.Sub",
    "Aeneas.Std.Scalar.SaturatingOps",
    "Aeneas.Std.Scalar.Fmt",
    "Aeneas.Tactic.RustAttributes",
]

modules = set()
pending = list(support_roots)
while pending:
    module = pending.pop()
    if module in modules:
        continue
    source = source_root / (module.replace(".", "/") + ".lean")
    if not source.is_file():
        raise SystemExit(f"Aeneas support module missing: {module}")
    modules.add(module)
    for line in source.read_text(encoding="utf-8").splitlines():
        if not line.startswith("import "):
            continue
        pending.extend(
            re.findall(r"\b(?:Aeneas|AeneasMeta)(?:\.[A-Za-z0-9_]+)+\b", line)
        )

for module in sorted(modules):
    relative = Path(module.replace(".", "/") + ".lean")
    destination = staging / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_root / relative, destination)

(staging / "Aeneas.lean").write_text(
    "\n".join(f"import {module}" for module in support_roots) + "\n",
    encoding="utf-8",
)
(staging / "AeneasMeta.lean").write_text(
    "\n".join(
        f"import {module}"
        for module in sorted(module for module in modules if module.startswith("AeneasMeta."))
    ) + "\n",
    encoding="utf-8",
)
PY

python3 - \
  "${staging}" \
  "${release_tag}" \
  "${revision}" \
  "${archive_url}" \
  "${archive_sha256}" \
  "${mathlib_revision}" \
  "${lean_toolchain}" <<'PY'
import hashlib
import re
import sys
from pathlib import Path

(
    staging_arg,
    release_tag,
    revision,
    archive_url,
    archive_sha256,
    mathlib_revision,
    lean_toolchain,
) = sys.argv[1:]
staging = Path(staging_arg)

(staging / "lakefile.lean").write_text(
    """import Lake
open Lake DSL

require mathlib from git
  \"https://github.com/leanprover-community/mathlib4.git\" @ \"%s\"

package aeneas {}

@[default_target] lean_lib Aeneas {}

@[default_target] lean_lib AeneasMeta {}
""" % mathlib_revision,
    encoding="utf-8",
)
(staging / "lean-toolchain").write_text(lean_toolchain + "\n", encoding="utf-8")

for path in sorted(staging.rglob("*.lean")):
    source = path.read_text(encoding="utf-8")
    normalized = source.replace("\N{EM DASH}", "-")
    path.write_text(normalized, encoding="utf-8")

digest = hashlib.sha256()
for path in sorted(path for path in staging.rglob("*") if path.is_file()):
    relative_path = path.relative_to(staging)
    if path.name == "lake-manifest.json" or ".lake" in relative_path.parts:
        continue
    relative = relative_path.as_posix().encode("utf-8")
    digest.update(relative)
    digest.update(b"\0")
    digest.update(path.read_bytes())
    digest.update(b"\0")

(staging / "VENDOR.toml").write_text(
    f'''schema = "chio.aeneas-vendor.v1"
upstream = "https://github.com/AeneasVerif/aeneas"
release_tag = "{release_tag}"
revision = "{revision}"
archive_url = "{archive_url}"
archive_sha256 = "{archive_sha256}"
content_sha256 = "{digest.hexdigest()}"
content_hash_scope = "All vendored files except VENDOR.toml, lake-manifest.json, and .lake build state."
upstream_lean_toolchain = "leanprover/lean4:v4.28.0-rc1"
host_lean_toolchain = "{lean_toolchain}"
mathlib_revision = "{mathlib_revision}"
license = "Apache-2.0"
package_metadata_policy = "The generated program support closure is selected from explicit roots; host Lean and Mathlib pins replace upstream package metadata; Lean sources receive deterministic ASCII punctuation normalization."
upstream_meta_policy = "Only AeneasMeta modules required by the selected support closure are vendored. Equivalence theorem axiom reports must not depend on upstream placeholder axioms."
''',
    encoding="utf-8",
)
PY

rm -rf "${vendor_dir}"
mkdir -p "$(dirname "${vendor_dir}")"
mv "${staging}" "${vendor_dir}"

echo "Vendored Aeneas Lean support from ${release_tag}"
