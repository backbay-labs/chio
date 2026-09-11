#!/usr/bin/env python3
"""CLI entrypoint for the internet-of-agents web3 service-order scenario."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from internet_web3.scenario import REPO_ROOT, ScenarioConfig, ServiceOrderScenario


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--artifact-dir")
    parser.add_argument("--e2e-report")
    parser.add_argument("--promotion-report")
    parser.add_argument("--ops-audit")
    parser.add_argument("--x402-requirements")
    parser.add_argument("--base-sepolia-smoke")
    parser.add_argument("--base-sepolia-deployment")
    parser.add_argument("--require-base-sepolia-smoke", action="store_true")
    parser.add_argument("--operator-control-url")
    parser.add_argument("--provider-control-url")
    parser.add_argument("--subcontractor-control-url")
    parser.add_argument("--federation-control-url")
    parser.add_argument("--service-token")
    parser.add_argument("--chio-auth-token")
    parser.add_argument("--market-broker-url")
    parser.add_argument("--settlement-desk-url")
    parser.add_argument("--web3-evidence-mcp-url")
    parser.add_argument("--provider-review-mcp-url")
    parser.add_argument("--subcontractor-review-mcp-url")
    return parser.parse_args(argv)


def _optional_path(value: str | None) -> Path | None:
    return Path(value) if value else None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config = ScenarioConfig(
        repo_root=Path(args.repo_root).resolve(),
        artifact_dir=_optional_path(args.artifact_dir),
        e2e_report=_optional_path(args.e2e_report),
        promotion_report=_optional_path(args.promotion_report),
        ops_audit=_optional_path(args.ops_audit),
        x402_requirements=_optional_path(args.x402_requirements),
        base_sepolia_smoke=_optional_path(args.base_sepolia_smoke),
        base_sepolia_deployment=_optional_path(args.base_sepolia_deployment),
        require_base_sepolia_smoke=args.require_base_sepolia_smoke,
        operator_control_url=args.operator_control_url,
        provider_control_url=args.provider_control_url,
        subcontractor_control_url=args.subcontractor_control_url,
        federation_control_url=args.federation_control_url,
        service_token=args.service_token,
        chio_auth_token=args.chio_auth_token,
        market_broker_url=args.market_broker_url,
        settlement_desk_url=args.settlement_desk_url,
        web3_evidence_mcp_url=args.web3_evidence_mcp_url,
        provider_review_mcp_url=args.provider_review_mcp_url,
        subcontractor_review_mcp_url=args.subcontractor_review_mcp_url,
    )
    result = ServiceOrderScenario(config).run()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
