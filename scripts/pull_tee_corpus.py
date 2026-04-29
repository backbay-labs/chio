#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any
import urllib.error
import urllib.request
import tomllib


DEFAULT_PINS = Path("tests/replay/corpus_pins.toml")
DEFAULT_OUT = Path("target/tee-corpus")
DEFAULT_PUBLIC_KEY = Path("tests/replay/keys/chio-tee-corpus.pub")
DEFAULT_REPO = "bb-connor/arc"
GITHUB_API = "https://api.github.com"
RELEASE_TAG_RE = re.compile(r"^tee-corpus-[0-9]{4}-[0-9]{2}-[0-9]{2}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
PLACEHOLDER_SHA256 = "0" * 64


class CorpusError(Exception):
    """Fail-closed corpus pull error."""


def fail(message: str) -> int:
    print(f"pull_tee_corpus.py: ERROR: {message}", file=sys.stderr)
    return 1


def load_pins(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise CorpusError(f"pin file not found: {path}")

    try:
        pins = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise CorpusError(f"failed to parse {path}: {exc}") from exc

    if pins.get("schema_version") != "1":
        raise CorpusError(f"{path} must set schema_version = \"1\"")

    artifacts = pins.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise CorpusError(f"{path} must contain at least one [[artifacts]] entry")

    validated: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, artifact in enumerate(artifacts, start=1):
        if not isinstance(artifact, dict):
            raise CorpusError(f"artifacts[{index}] must be a table")

        name = artifact.get("name")
        release_tag = artifact.get("release_tag")
        sha256 = artifact.get("sha256")
        size_bytes = artifact.get("size_bytes")
        min_schema_version = artifact.get("min_schema_version")
        published = artifact.get("published", True)

        if not isinstance(name, str) or not name:
            raise CorpusError(f"artifacts[{index}].name must be a non-empty string")
        if "/" in name or name in {".", ".."}:
            raise CorpusError(f"artifacts[{index}].name must be a single file name: {name}")
        if not isinstance(release_tag, str) or not RELEASE_TAG_RE.match(release_tag):
            raise CorpusError(
                f"artifacts[{index}].release_tag must match tee-corpus-YYYY-MM-DD"
            )
        if not isinstance(sha256, str) or not SHA256_RE.match(sha256):
            raise CorpusError(f"artifacts[{index}].sha256 must be 64 hex characters")
        if not isinstance(size_bytes, int) or size_bytes <= 0:
            raise CorpusError(f"artifacts[{index}].size_bytes must be a positive integer")
        if min_schema_version is not None and not isinstance(min_schema_version, str):
            raise CorpusError(f"artifacts[{index}].min_schema_version must be a string")
        if not isinstance(published, bool):
            raise CorpusError(f"artifacts[{index}].published must be a boolean")
        if published and sha256.lower() == PLACEHOLDER_SHA256:
            raise CorpusError(
                f"artifacts[{index}].sha256 is a placeholder; set published = false "
                "until the release asset is cut and pinned"
            )
        if not published and sha256.lower() != PLACEHOLDER_SHA256:
            raise CorpusError(
                f"artifacts[{index}].sha256 must remain the all-zero placeholder "
                "while published = false"
            )

        key = (release_tag, name)
        if key in seen:
            raise CorpusError(f"duplicate artifact pin for {release_tag}/{name}")
        seen.add(key)

        normalized = dict(artifact)
        normalized["sha256"] = sha256.lower()
        normalized["published"] = published
        validated.append(normalized)

    return validated


def auth_header() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def api_request(url: str, *, accept: str = "application/vnd.github+json") -> bytes:
    headers = {
        "Accept": accept,
        "User-Agent": "chio-tee-corpus-puller",
        "X-GitHub-Api-Version": "2022-11-28",
        **auth_header(),
    }
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise CorpusError(f"GitHub request failed ({exc.code}) for {url}: {body}") from exc
    except urllib.error.URLError as exc:
        raise CorpusError(f"GitHub request failed for {url}: {exc}") from exc


def get_release(repo: str, tag: str) -> dict[str, Any]:
    url = f"{GITHUB_API}/repos/{repo}/releases/tags/{tag}"
    try:
        body = api_request(url)
    except CorpusError as exc:
        if "(404)" in str(exc):
            raise CorpusError(f"required release tag does not exist: {tag}") from exc
        raise

    release = json.loads(body.decode("utf-8"))
    if not isinstance(release, dict):
        raise CorpusError(f"unexpected GitHub release response for {tag}")
    return release


def assets_by_name(release: dict[str, Any], tag: str) -> dict[str, dict[str, Any]]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise CorpusError(f"release {tag} response did not include assets")

    by_name: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        if isinstance(name, str):
            by_name[name] = asset
    return by_name


def download_asset(asset: dict[str, Any], path: Path) -> None:
    url = asset.get("url")
    name = asset.get("name", "<unknown>")
    if not isinstance(url, str):
        raise CorpusError(f"asset {name} did not include an API download URL")

    path.parent.mkdir(parents=True, exist_ok=True)
    data = api_request(url, accept="application/octet-stream")
    path.write_bytes(data)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def decode_signature(path: Path) -> bytes:
    raw = path.read_bytes()
    stripped = b"".join(raw.split())
    if len(raw) == 64:
        return raw
    if re.fullmatch(rb"[0-9a-fA-F]{128}", stripped):
        return bytes.fromhex(stripped.decode("ascii"))
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (ValueError, binascii.Error):
        decoded = b""
    if len(decoded) == 64:
        return decoded
    raise CorpusError(
        f"{path} must contain a raw, hex, or base64 encoded 64-byte Ed25519 signature"
    )


def verify_manifest_signature(manifest_path: Path, sig_path: Path, public_key_path: Path) -> None:
    if not public_key_path.is_file():
        raise CorpusError(f"public key not found: {public_key_path}")
    openssl = shutil.which("openssl")
    if openssl is None:
        raise CorpusError("openssl is required to verify MANIFEST.toml.sig")

    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise CorpusError(f"failed to parse {manifest_path}: {exc}") from exc

    with tempfile.TemporaryDirectory(prefix="chio-tee-corpus-verify-") as tmp:
        tmpdir = Path(tmp)
        canonical_path = tmpdir / "manifest.canonical.json"
        sig_raw_path = tmpdir / "MANIFEST.toml.sig.raw"
        canonical_path.write_bytes(canonical_json_bytes(manifest))
        sig_raw_path.write_bytes(decode_signature(sig_path))

        result = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-rawin",
                "-in",
                str(canonical_path),
                "-sigfile",
                str(sig_raw_path),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip()
        detail = f": {stderr}" if stderr else ""
        raise CorpusError(f"MANIFEST.toml.sig verification failed for {manifest_path}{detail}")


def manifest_artifacts(manifest_path: Path) -> dict[str, dict[str, Any]]:
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise CorpusError(f"failed to parse {manifest_path}: {exc}") from exc

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise CorpusError(f"{manifest_path} must contain [[artifacts]] entries")

    by_name: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        name = artifact.get("name")
        if isinstance(name, str):
            by_name[name] = artifact
    return by_name


def verify_manifest_pin(manifest_path: Path, pin: dict[str, Any]) -> None:
    manifest_index = manifest_artifacts(manifest_path)
    name = pin["name"]
    manifest_pin = manifest_index.get(name)
    if manifest_pin is None:
        raise CorpusError(f"{manifest_path} does not list pinned artifact {name}")

    manifest_sha = manifest_pin.get("sha256")
    if isinstance(manifest_sha, str):
        manifest_sha = manifest_sha.lower()
    if manifest_sha != pin["sha256"]:
        raise CorpusError(
            f"{manifest_path} sha256 for {name} is {manifest_sha}, expected {pin['sha256']}"
        )

    manifest_size = manifest_pin.get("size_bytes")
    if manifest_size != pin["size_bytes"]:
        raise CorpusError(
            f"{manifest_path} size_bytes for {name} is {manifest_size}, "
            f"expected {pin['size_bytes']}"
        )


def grouped_by_release(artifacts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for artifact in artifacts:
        grouped.setdefault(artifact["release_tag"], []).append(artifact)
    return grouped


def pull(args: argparse.Namespace) -> int:
    artifacts = load_pins(args.pins)
    unpublished = [artifact for artifact in artifacts if not artifact["published"]]
    published = [artifact for artifact in artifacts if artifact["published"]]
    release_count = len(grouped_by_release(published))

    if unpublished and not args.allow_unpublished_placeholders:
        names = ", ".join(f"{artifact['release_tag']}/{artifact['name']}" for artifact in unpublished)
        raise CorpusError(
            "unpublished placeholder artifact pins are present; "
            f"pass --allow-unpublished-placeholders only in pre-publication CI paths: {names}"
        )

    if args.verify_manifest_sig and not args.public_key.is_file():
        raise CorpusError(f"public key not found: {args.public_key}")

    if args.dry_run:
        print(
            "dry-run: validated "
            f"{len(artifacts)} pinned artifact(s) across {release_count} release(s); "
            "network, download, sha256, and signature checks skipped"
        )
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    repo = args.repo or os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPO

    for artifact in unpublished:
        print(
            "skipping unpublished placeholder "
            f"{artifact['release_tag']}/{artifact['name']} (published = false)"
        )

    for release_tag, pins in grouped_by_release(published).items():
        release = get_release(repo, release_tag)
        assets = assets_by_name(release, release_tag)

        manifest_asset = assets.get("MANIFEST.toml")
        sig_asset = assets.get("MANIFEST.toml.sig")
        if manifest_asset is None:
            raise CorpusError(f"release {release_tag} is missing MANIFEST.toml")
        if args.verify_manifest_sig and sig_asset is None:
            raise CorpusError(f"release {release_tag} is missing MANIFEST.toml.sig")

        release_dir = args.out / release_tag
        manifest_path = release_dir / "MANIFEST.toml"
        sig_path = release_dir / "MANIFEST.toml.sig"
        download_asset(manifest_asset, manifest_path)
        if sig_asset is not None:
            download_asset(sig_asset, sig_path)

        if args.verify_manifest_sig:
            verify_manifest_signature(manifest_path, sig_path, args.public_key)

        for pin in pins:
            asset = assets.get(pin["name"])
            if asset is None:
                raise CorpusError(f"release {release_tag} is missing artifact {pin['name']}")

            out_path = release_dir / pin["name"]
            download_asset(asset, out_path)
            if args.verify_sha256:
                actual = sha256_file(out_path)
                if actual != pin["sha256"]:
                    raise CorpusError(
                        f"sha256 mismatch for {pin['name']}: got {actual}, "
                        f"expected {pin['sha256']}"
                    )
            if args.verify_manifest_sig:
                verify_manifest_pin(manifest_path, pin)

            print(f"verified {release_tag}/{pin['name']} -> {out_path}")

    return 0


def parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Pull pinned chio-tee-corpus release artifacts and fail closed on "
            "missing releases, sha256 mismatches, or manifest signature failures."
        )
    )
    parser.add_argument("--pins", type=Path, default=DEFAULT_PINS, help=f"pin TOML path (default: {DEFAULT_PINS})")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"output directory (default: {DEFAULT_OUT})")
    parser.add_argument("--repo", default=None, help=f"GitHub owner/repo (default: GITHUB_REPOSITORY or {DEFAULT_REPO})")
    parser.add_argument(
        "--public-key",
        type=Path,
        default=DEFAULT_PUBLIC_KEY,
        help=f"Ed25519 public key for MANIFEST.toml.sig (default: {DEFAULT_PUBLIC_KEY})",
    )
    parser.add_argument(
        "--verify-sha256",
        action="store_true",
        help="compare every downloaded artifact digest against corpus_pins.toml",
    )
    parser.add_argument(
        "--verify-manifest-sig",
        action="store_true",
        help="verify MANIFEST.toml.sig under the integrations release public key",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate pins and key path without network downloads or signature checks",
    )
    parser.add_argument(
        "--allow-unpublished-placeholders",
        action="store_true",
        help=(
            "allow artifacts marked published = false to keep their all-zero sha256 "
            "placeholder and skip network downloads for those artifacts"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return pull(args)
    except CorpusError as exc:
        return fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
