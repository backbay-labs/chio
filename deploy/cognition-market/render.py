#!/usr/bin/env python3
"""Render immutable cognition-market Kubernetes deployment templates."""

from __future__ import annotations

import argparse
import os
import re
import tempfile
from pathlib import Path


SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9./_-]{0,254}$")
HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def image_reference(repository: str, digest: str) -> str:
    if not IMAGE.fullmatch(repository) or ":" in repository or "@" in repository:
        raise ValueError("image repository must be an immutable tag-free repository name")
    if not SHA256.fullmatch(digest) or digest == "0" * 64:
        raise ValueError("image digest must be a nonzero lowercase SHA-256")
    return f"{repository}@sha256:{digest}"


def render(template: str, chio_image: str, proxy_image: str, public_host: str) -> str:
    if not HOST.fullmatch(public_host):
        raise ValueError("public host must be a canonical lowercase DNS name")
    replacements = {
        "@CHIO_IMAGE@": chio_image,
        "@PROXY_IMAGE@": proxy_image,
        "@PUBLIC_HOST@": public_host,
    }
    result = template
    for marker, value in replacements.items():
        if result.count(marker) == 0:
            raise ValueError(f"deployment template omits {marker}")
        result = result.replace(marker, value)
    if any(marker in result for marker in replacements):
        raise ValueError("deployment template contains an unresolved marker")
    return result


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio-image", required=True)
    parser.add_argument("--chio-digest", required=True)
    parser.add_argument("--proxy-image", required=True)
    parser.add_argument("--proxy-digest", required=True)
    parser.add_argument("--public-host", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    template = (root / "kubernetes.yaml.template").read_text(encoding="utf-8")
    content = render(
        template,
        image_reference(args.chio_image, args.chio_digest),
        image_reference(args.proxy_image, args.proxy_digest),
        args.public_host,
    )
    write_atomic(args.output, content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
