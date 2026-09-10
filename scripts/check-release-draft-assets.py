#!/usr/bin/env python3
"""Record and compare exact draft asset identities; never publish or upload."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

TARGETS = (
    "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin", "aarch64-apple-darwin", "x86_64-pc-windows-msvc",
)


def api(endpoint: str):
    result = subprocess.run(["gh", "api", endpoint], check=True, capture_output=True,
                            text=True, timeout=60)
    return json.loads(result.stdout)


def pages(endpoint: str, read=api) -> list:
    rows = []
    for page in range(1, 101):
        batch = read(f"{endpoint}?per_page=100&page={page}")
        if not isinstance(batch, list):
            raise ValueError("invalid GitHub list response")
        rows.extend(batch)
        if len(batch) < 100:
            return rows
    raise ValueError("GitHub listing exceeds the bounded inventory")


def find_release(repository: str, tag: str, read=api):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    matches = [r for r in pages(f"repos/{repository}/releases", read) if r.get("tag_name") == tag]
    if len(matches) > 1:
        raise ValueError("ambiguous release tag")
    return matches[0] if matches else None


def require_stage(repository: str, tag: str, read=api) -> None:
    release = find_release(repository, tag, read)
    if release and (release.get("draft") is not True or release.get("prerelease") is not True):
        raise ValueError("existing candidate is not a draft prerelease; never reopen a published release")


def required_names(tag: str, source: str) -> set[str]:
    names = {"SHA256SUMS", "chio.rb", f"chio-{source}.intoto.jsonl"}
    names.update(f"{tag}.txt{suffix}" for suffix in ("", ".sig", ".pem"))
    for target in TARGETS:
        archive = f"chio-{tag[1:]}-{target}." + ("zip" if "windows" in target else "tar.gz")
        names.update(archive + suffix for suffix in ("", ".sha256", ".sig", ".pem"))
        names.update(f"chio-{target}.{suffix}" for suffix in ("cyclonedx.json", "validation.json"))
        if "apple" in target:
            names.update(f"chio-{target}.{suffix}" for suffix in (
                "native-openssl.json", "linkage.json", "openssl-LICENSE.txt",
                "native-openssl.catalog.cdx.json", "native-openssl.grype.json", "native-openssl-scan.json",
            ))
    return names


def snapshot(repository: str, tag: str, source: str, directory: Path, *, published=False, read=api) -> dict:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+-[0-9A-Za-z.-]+(?:\+[0-9A-Za-z.-]+)?", tag):
        raise ValueError("expected a candidate version tag")
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("invalid source commit")
    release = find_release(repository, tag, read)
    if not release or release.get("draft") is not (not published) or release.get("prerelease") is not True:
        raise ValueError("release does not have the required candidate publication state")
    ref = read(f"repos/{repository}/git/ref/tags/{quote(tag, safe='')}")["object"]
    for _ in range(8):
        if ref.get("type") != "tag":
            break
        ref = read(f"repos/{repository}/git/tags/{ref['sha']}")["object"]
    if ref.get("type") != "commit" or ref.get("sha") != source:
        raise ValueError("release tag does not resolve to the accepted source")
    if not isinstance(release.get("id"), int) or isinstance(release["id"], bool) or release["id"] <= 0:
        raise ValueError("invalid release id")
    assets = pages(f"repos/{repository}/releases/{release['id']}/assets", read)
    if len({a.get("id") for a in assets}) != len(assets):
        raise ValueError("duplicate release asset identity")
    names = [a.get("name") for a in assets]
    if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.+-]+", name) or name in {".", ".."} for name in names):
        raise ValueError("unsafe release asset name")
    if len(set(names)) != len(names) or not required_names(tag, source).issubset(names):
        raise ValueError("duplicate or missing required release assets")
    if directory.is_symlink() or not directory.is_dir() or {p.name for p in directory.iterdir()} != set(names):
        raise ValueError("downloaded directory must contain exactly the release assets")
    identities = []
    for asset in sorted(assets, key=lambda value: value["name"]):
        path = directory / asset["name"]
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError("release asset must be a nonempty regular file")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if asset.get("state") != "uploaded" or asset.get("size") != path.stat().st_size or asset.get("digest") != f"sha256:{digest}":
            raise ValueError("downloaded asset does not match its GitHub identity")
        if not isinstance(asset.get("id"), int) or isinstance(asset["id"], bool) or asset["id"] <= 0:
            raise ValueError("invalid release asset id")
        identities.append({"name": asset["name"], "id": asset["id"], "bytes": asset["size"], "sha256": digest})
    return {"schema": 1, "repository": repository, "release_id": release["id"], "tag": tag,
            "source_sha": source, "assets": identities}


def require_checksum_review(identity: dict, number: int, read=api) -> None:
    if number <= 0:
        raise ValueError("a checksum review PR number is required")
    repository = identity["repository"]
    pr = read(f"repos/{repository}/pulls/{number}")
    if (pr.get("merged") is not True or pr.get("state") != "closed"
            or pr.get("base", {}).get("ref") != "main"
            or pr.get("base", {}).get("repo", {}).get("full_name") != repository
            or not re.fullmatch(r"[0-9a-f]{40}", pr.get("merge_commit_sha", ""))):
        raise ValueError("checksum review PR must be merged into canonical main")
    names = {f"{identity['tag']}.txt{suffix}" for suffix in ("", ".sig", ".pem")}
    expected = {f"supply-chain/checksums/{name}" for name in names}
    changed = pages(f"repos/{repository}/pulls/{number}/files", read)
    if len(changed) != 3 or {f.get("filename") for f in changed} != expected or any(
            f.get("status") not in {"added", "modified"} for f in changed):
        raise ValueError("checksum review PR must contain exactly the signed index and its siblings")
    by_name = {asset["name"]: asset for asset in identity["assets"]}
    for path in sorted(expected):
        for ref in (pr["merge_commit_sha"], "main"):
            blob = read(f"repos/{repository}/contents/{path}?ref={ref}")
            if blob.get("encoding") != "base64" or blob.get("type") != "file" or blob.get("path") != path:
                raise ValueError("checksum review does not contain a regular file")
            body = base64.b64decode("".join(blob["content"].split()), validate=True)
            if hashlib.sha256(body).hexdigest() != by_name[Path(path).name]["sha256"]:
                raise ValueError("merged checksum review differs from the qualified draft assets")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("stage", "record", "check"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha")
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--published", action="store_true")
    parser.add_argument("--checksum-review-pr", type=int)
    args = parser.parse_args()
    if args.mode == "stage":
        if args.published:
            parser.error("stage cannot use --published")
        require_stage(args.repository, args.tag)
    else:
        if not args.source_sha or not args.directory or not args.manifest:
            parser.error("record/check require --source-sha, --directory and --manifest")
        if args.mode == "record" and args.published:
            parser.error("record requires an unpublished draft")
        actual = snapshot(args.repository, args.tag, args.source_sha, args.directory, published=args.published)
        if args.mode == "record":
            with args.manifest.open("x") as stream:
                json.dump(actual, stream, indent=2)
                stream.write("\n")
        else:
            if json.loads(args.manifest.read_text()) != actual:
                raise ValueError("release identity changed since qualification; repeat acceptance for new bytes")
            if not args.checksum_review_pr:
                parser.error("check requires --checksum-review-pr; operator review remains unresolved")
            require_checksum_review(actual, args.checksum_review_pr)
    print("PASS: release asset identity check (not signature, source-gate or host acceptance)")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"release asset check refused: {type(error).__name__}: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
