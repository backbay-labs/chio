#!/usr/bin/env python3
"""Record or decide one exact MCP request using the private operator credential."""
import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["submit", "show", "approve", "deny"])
    parser.add_argument("--operator-file", type=Path, required=True)
    parser.add_argument("--proposal-file", type=Path)
    parser.add_argument("--approval-id")
    parser.add_argument("--output", type=Path, required=True, help="New private JSON response file")
    parser.add_argument("--base-url")
    args = parser.parse_args()
    operator = json.loads(args.operator_file.read_text())
    base = args.base_url or f"http://127.0.0.1:{int(operator['port'])}"
    parsed = urllib.parse.urlsplit(base)
    if (parsed.username or parsed.password or parsed.query or parsed.fragment
        or parsed.path not in ("", "/") or (parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")))):
        parser.error("operator endpoint requires HTTPS or loopback HTTP origin without credentials")
    route = "/admin/approvals"
    data = None
    if args.action == "submit":
        if not args.proposal_file or args.approval_id:
            parser.error("submit requires proposal-file and no approval-id")
        data = json.dumps(json.loads(args.proposal_file.read_text())).encode()
    else:
        if not args.approval_id or args.proposal_file:
            parser.error("show/approve/deny require approval-id and no proposal-file")
        route += "/" + urllib.parse.quote(args.approval_id, safe="")
        if args.action != "show":
            route += "/decision"
            data = json.dumps({"decision": "approved" if args.action == "approve" else "denied"}).encode()
    # Reserve a fresh private output before mutating the server; never overwrite
    # a prior operator artifact or print a bearer/signing credential.
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    request = urllib.request.Request(base.rstrip("/") + route, data=data, headers={
        "Authorization": "Bearer " + operator["adminToken"], "Content-Type": "application/json"})
    with os.fdopen(descriptor, "w") as output:
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.load(response)
                result["httpStatus"] = response.status
        except urllib.error.HTTPError as error:
            result = {"httpStatus": error.code, "ok": False}
        json.dump(result, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps({"output": str(args.output), "httpStatus": result["httpStatus"],
                      "status": result.get("status"), "approvalId": result.get("record", {}).get("id")}))
    return int(result["httpStatus"] >= 400)


if __name__ == "__main__":
    sys.exit(main())
