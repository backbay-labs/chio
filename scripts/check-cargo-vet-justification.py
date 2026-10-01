#!/usr/bin/env python3
"""Require an explicit exemption justification from a repository writer."""

import argparse
import json
import subprocess
import sys
from urllib.parse import quote


PREFIX = "cargo-vet-exemption-justification:"


def github(endpoint, paginated=False):
    command = ["gh", "api", endpoint]
    if paginated:
        command += ["--paginate", "--slurp"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def authorized_justification(repo, number, api=github):
    permissions = {}
    endpoints = [
        f"repos/{repo}/issues/{number}/comments",
        f"repos/{repo}/pulls/{number}/comments",
        f"repos/{repo}/pulls/{number}/reviews",
    ]
    for endpoint in endpoints:
        pages = api(endpoint, paginated=True)
        for page in pages:
            for comment in page:
                body = comment.get("body") or ""
                if not body.lower().startswith(PREFIX):
                    continue
                # author_association depends on the caller's visibility into
                # private organization membership. Verify actual repository
                # permission, including team/inherited access, instead.
                login = comment.get("user", {}).get("login")
                if not isinstance(login, str) or not login:
                    continue
                if login not in permissions:
                    record = api(f"repos/{repo}/collaborators/{quote(login, safe='')}/permission")
                    permissions[login] = record.get("permission")
                # GitHub maps maintain to write and triage to read here.
                if permissions[login] in {"admin", "write"}:
                    return comment.get("id")
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", type=int, required=True)
    args = parser.parse_args()
    try:
        identity = authorized_justification(args.repo, args.pr)
    except (subprocess.CalledProcessError, ValueError, TypeError, AttributeError) as error:
        print(f"Cannot verify exemption reviewer permission ({type(error).__name__})", file=sys.stderr)
        return 1
    if identity is None:
        print("No explicit cargo-vet justification from a repository writer", file=sys.stderr)
        return 1
    print(f"cargo-vet exemption justification verified: comment/review {identity}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
