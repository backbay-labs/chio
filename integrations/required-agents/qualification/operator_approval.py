#!/usr/bin/env python3
"""Record or decide one exact MCP request using the private operator credential."""

import argparse
import json
import os
import sys
import urllib.parse
from pathlib import Path

from operator_http import (
    OperatorError,
    decode_object,
    identifier,
    origin,
    private_operator,
    request_json,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["submit", "show", "approve", "deny"])
    parser.add_argument("--operator-file", type=Path, required=True)
    parser.add_argument("--proposal-file", type=Path)
    parser.add_argument("--approval-id")
    parser.add_argument("--output", type=Path, required=True, help="New private JSON response file")
    parser.add_argument("--base-url", help="Explicit trusted HTTPS or loopback HTTP origin")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    try:
        operator = private_operator(args.operator_file)
        base = origin(args.base_url, operator)
        route = "/admin/approvals"
        data = None
        if args.action == "submit":
            if not args.proposal_file or args.approval_id:
                raise OperatorError("submit_requires_only_proposal_file")
            data = decode_object(args.proposal_file.read_bytes())
        else:
            if not args.approval_id or args.proposal_file:
                raise OperatorError("decision_or_show_requires_only_approval_id")
            approval_id = identifier(args.approval_id, operator)
            route += "/" + urllib.parse.quote(approval_id, safe="")
            if args.action != "show":
                route += "/decision"
                data = {"decision": "approved" if args.action == "approve" else "denied"}
        # Reserve a fresh private output before the mutation. Preserve all prior
        # artifacts, including ambiguous outcomes; never retry automatically.
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as output:
            try:
                result = request_json(base, route, operator, data, args.timeout)
                result["httpStatus"] = 200
            except OperatorError as error:
                result = {**error.record(), "retry": "never-automatic"}
                if args.action != "show":
                    result["outcome"] = "unknown"
            json.dump(result, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        # Only closed-vocabulary status and validated IDs may appear publicly.
        status = result.get("status")
        if status not in ("pending", "approved", "denied", "rejected", "expired"):
            status = None
        record = result.get("record")
        approval_id = record.get("id") if isinstance(record, dict) else None
        try:
            approval_id = identifier(approval_id, operator)
        except OperatorError:
            approval_id = None
        print(
            json.dumps(
                {
                    "output": str(args.output),
                    "httpStatus": result.get("httpStatus"),
                    "status": status,
                    "approvalId": approval_id,
                }
            )
        )
        return int(result.get("httpStatus") != 200 or result.get("ok") is False)
    except (OperatorError, OSError) as error:
        record = (
            error.record()
            if isinstance(error, OperatorError)
            else {"ok": False, "error": "private_input_or_output_unavailable"}
        )
        print(json.dumps(record), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
