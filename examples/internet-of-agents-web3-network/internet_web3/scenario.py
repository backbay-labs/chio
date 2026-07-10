"""Production-shaped service-order scenario for agentic web3 settlement."""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import (
    ArtifactStore,
    Json,
    now_epoch,
    read_json,
    repo_rel,
    require_file,
    sha256_file,
    tx_hashes_by_id,
)
from .adversarial import write_adversarial_controls
from .approval import write_approval_checkpoint
from .budgeting import BudgetWorkflow
from .chio import ChioHttpError, TrustControlClient
from .capabilities import CapabilityIssuer, grant, scope
from .clients import (
    ChioMcpEvidenceTool,
    ChioMcpProviderReviewTool,
    EvidenceTool,
    HttpMarket,
    HttpSettlementDesk,
    JsonHttpClient,
    LocalMarket,
    LocalSettlementDesk,
    Market,
    ProviderReviewTool,
    SettlementDesk,
    StdioEvidenceTool,
)
from .chio_cli import (
    run_provider_federation_workflow,
    run_provider_passport_workflow,
    run_provider_reputation_workflow,
)
from .disputes import write_dispute_workflow
from .identity import (
    write_runtime_appraisals,
    write_runtime_degradation_workflow,
)
from .marketplace import (
    build_rfq_request,
    select_provider,
    write_payment_handshake,
    write_reputation_and_admission_artifacts,
)
from .observability import write_observability_artifacts
from .rails import write_rail_selection
from .reports import (
    write_behavioral_reports,
    write_receipt_reports,
    write_static_guardrail_denials,
    write_topology,
)
from .subcontracting import write_subcontract_workflow

EXAMPLE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EXAMPLE_ROOT.parents[1]

ACTOR_NAMES = [
    "treasury-agent",
    "procurement-agent",
    "provider-agent",
    "subcontractor-agent",
    "settlement-agent",
    "auditor-agent",
]

EVIDENCE_REFS = [
    "web3/validation-index.json",
    "contracts/web3-settlement-dispatch.json",
    "contracts/web3-settlement-receipt.json",
]


@dataclass(frozen=True)
class ScenarioConfig:
    repo_root: Path = REPO_ROOT
    artifact_dir: Path | None = None
    e2e_report: Path | None = None
    promotion_report: Path | None = None
    ops_audit: Path | None = None
    x402_requirements: Path | None = None
    base_sepolia_smoke: Path | None = None
    base_sepolia_deployment: Path | None = None
    require_base_sepolia_smoke: bool = False
    operator_control_url: str | None = None
    provider_control_url: str | None = None
    subcontractor_control_url: str | None = None
    federation_control_url: str | None = None
    service_token: str | None = None
    chio_auth_token: str | None = None
    market_broker_url: str | None = None
    settlement_desk_url: str | None = None
    web3_evidence_mcp_url: str | None = None
    provider_review_mcp_url: str | None = None
    subcontractor_review_mcp_url: str | None = None

    def output_dir(self) -> Path:
        if self.artifact_dir is not None:
            return self.artifact_dir
        return EXAMPLE_ROOT / "artifacts/live" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


@dataclass(frozen=True)
class EvidencePaths:
    e2e: Path
    promotion: Path
    ops: Path
    x402: Path
    base_sepolia_smoke: Path
    base_sepolia_deployment: Path

    @classmethod
    def from_config(cls, config: ScenarioConfig) -> "EvidencePaths":
        root = config.repo_root
        return cls(
            e2e=config.e2e_report or root / "target/web3-e2e-qualification/partner-qualification.json",
            promotion=config.promotion_report or root / "target/web3-promotion-qualification/promotion-qualification.json",
            ops=config.ops_audit or root / "target/web3-ops-qualification/incident-audit.json",
            x402=config.x402_requirements or root / "docs/standards/CHIO_X402_REQUIREMENTS_EXAMPLE.json",
            base_sepolia_smoke=config.base_sepolia_smoke
            or root / "target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json",
            base_sepolia_deployment=config.base_sepolia_deployment
            or root / "target/web3-live-rollout/base-sepolia/promotion/deployment.json",
        )


@dataclass(frozen=True)
class LoadedEvidence:
    paths: EvidencePaths
    e2e: Json
    promotion: Json
    ops: Json
    x402: Json
    base_smoke: Json | None
    deployment: Json | None

    @property
    def txs(self) -> dict[str, str]:
        return tx_hashes_by_id(self.base_smoke)

    @property
    def chain_id(self) -> str:
        if self.base_smoke:
            return self.base_smoke.get("chain_id", "eip155:84532")
        return "eip155:84532"

    @property
    def deployed_contracts(self) -> Json:
        if not self.deployment:
            return {}
        return self.deployment.get("deployed_contract_addresses", {})


class EvidenceLoader:
    """Loads release-gate artifacts and attaches them to the scenario bundle."""

    def __init__(self, config: ScenarioConfig, store: ArtifactStore) -> None:
        self.config = config
        self.paths = EvidencePaths.from_config(config)
        self.store = store

    def load(self) -> LoadedEvidence:
        required = {
            "e2e": self.paths.e2e,
            "promotion": self.paths.promotion,
            "ops": self.paths.ops,
            "x402": self.paths.x402,
        }
        for label, path in required.items():
            require_file(path, label)

        base_smoke_present = self.paths.base_sepolia_smoke.exists()
        if self.config.require_base_sepolia_smoke and not base_smoke_present:
            require_file(self.paths.base_sepolia_smoke, "Base Sepolia smoke report")
        if base_smoke_present:
            require_file(self.paths.base_sepolia_deployment, "Base Sepolia deployment record")

        e2e = self.store.copy_json(self.paths.e2e, "web3/e2e-partner-qualification.json")
        promotion = self.store.copy_json(self.paths.promotion, "web3/promotion-qualification.json")
        ops = self.store.copy_json(self.paths.ops, "web3/ops-incident-audit.json")
        x402 = self.store.copy_json(self.paths.x402, "web3/x402-requirements-example.json")

        base_smoke = None
        deployment = None
        if base_smoke_present:
            base_smoke = self.store.copy_json(self.paths.base_sepolia_smoke, "web3/base-sepolia-smoke.json")
            deployment = self.store.copy_json(
                self.paths.base_sepolia_deployment,
                "web3/base-sepolia-deployment.json",
            )

        return LoadedEvidence(
            paths=self.paths,
            e2e=e2e,
            promotion=promotion,
            ops=ops,
            x402=x402,
            base_smoke=base_smoke,
            deployment=deployment,
        )

    def build_validation_index(self, evidence: LoadedEvidence) -> Json:
        txs = evidence.txs
        smoke = evidence.base_smoke
        deployment = evidence.deployment
        paths = evidence.paths
        root = self.config.repo_root
        return {
            "schema": "chio.example.ioa-web3.validation-index.v1",
            "generated_at": now_epoch(),
            "required_local_validations": {
                "e2e": {
                    "path": repo_rel(paths.e2e, root),
                    "sha256": sha256_file(paths.e2e),
                    "status": evidence.e2e.get("status"),
                    "claims": evidence.e2e.get("claims", []),
                },
                "promotion": {
                    "path": repo_rel(paths.promotion, root),
                    "sha256": sha256_file(paths.promotion),
                    "checks": evidence.promotion.get("checks", []),
                },
                "ops": {
                    "path": repo_rel(paths.ops, root),
                    "sha256": sha256_file(paths.ops),
                    "assertions": evidence.ops.get("assertions", []),
                },
                "x402": {
                    "path": repo_rel(paths.x402, root),
                    "sha256": sha256_file(paths.x402),
                    "version": evidence.x402.get("version"),
                    "settlement_mode": evidence.x402.get("settlement_mode"),
                },
            },
            "base_sepolia_live_smoke": {
                "included": bool(smoke),
                "path": repo_rel(paths.base_sepolia_smoke, root) if smoke else None,
                "sha256": sha256_file(paths.base_sepolia_smoke) if smoke else None,
                "status": smoke.get("status") if smoke else "not_attached",
                "chain_id": smoke.get("chain_id") if smoke else None,
                "actor": smoke.get("actor") if smoke else None,
                "transaction_ids": list(txs.keys()),
                "tx_count": len(txs),
                "deployment_id": deployment.get("deployment_id") if deployment else None,
                "contracts": deployment.get("deployed_contract_addresses", {}) if deployment else {},
            },
        }


class ServiceOrderScenario:
    """Coordinates agents, services, and release evidence into one bundle."""

    def __init__(
        self,
        config: ScenarioConfig,
        *,
        issuer: CapabilityIssuer | None = None,
        evidence_tool: EvidenceTool | None = None,
        provider_review_tool: ProviderReviewTool | None = None,
    ) -> None:
        self.config = config
        self.store = ArtifactStore(config.output_dir())
        self.issuer = issuer or CapabilityIssuer()
        self.operator_trust = self._trust_client(config.operator_control_url)
        self.provider_trust = self._trust_client(config.provider_control_url)
        self.subcontractor_trust = self._trust_client(config.subcontractor_control_url)
        self.federation_trust = self._trust_client(config.federation_control_url)
        self.evidence_tool = evidence_tool or self._evidence_tool()
        self.provider_review_tool = provider_review_tool or self._provider_review_tool()
        self.subcontractor_review_tool = self._subcontractor_review_tool()

    def _trust_client(self, url: str | None) -> TrustControlClient | None:
        if not url or not self.config.service_token:
            return None
        return TrustControlClient(url, self.config.service_token)

    def _evidence_tool(self) -> EvidenceTool:
        if self.config.web3_evidence_mcp_url and self.config.chio_auth_token:
            return ChioMcpEvidenceTool(self.config.web3_evidence_mcp_url, self.config.chio_auth_token)
        return StdioEvidenceTool(
            repo_root=self.config.repo_root,
            script_path=EXAMPLE_ROOT / "tools/web3_evidence.py",
        )

    def _provider_review_tool(self) -> ProviderReviewTool | None:
        if self.config.provider_review_mcp_url and self.config.chio_auth_token:
            return ChioMcpProviderReviewTool(
                self.config.provider_review_mcp_url,
                self.config.chio_auth_token,
            )
        return None

    def _subcontractor_review_tool(self) -> ProviderReviewTool | None:
        if self.config.subcontractor_review_mcp_url and self.config.chio_auth_token:
            return ChioMcpProviderReviewTool(
                self.config.subcontractor_review_mcp_url,
                self.config.chio_auth_token,
            )
        return None

    @property
    def chio_mediated(self) -> bool:
        return all(
            [
                self.operator_trust,
                self.provider_trust,
                self.subcontractor_trust,
                self.federation_trust,
                self.config.market_broker_url,
                self.config.settlement_desk_url,
                self.config.web3_evidence_mcp_url,
                self.config.provider_review_mcp_url,
                self.config.subcontractor_review_mcp_url,
            ]
        )

    def _record_lineage_safe(
        self,
        trust: TrustControlClient | None,
        capability: Json,
        parent_capability_id: str | None,
        label: str,
    ) -> None:
        if not trust:
            return
        try:
            response = trust.record_lineage(capability, parent_capability_id)
        except ChioHttpError as exc:
            response = {"stored": False, "status": exc.status, "error": exc.body}
        self.store.write_json(f"chio/receipts/lineage-{label}.json", response)

    def run(self) -> Json:
        evidence_loader = EvidenceLoader(self.config, self.store)
        evidence = evidence_loader.load()
        order_request, treasury_policy, provider_catalog = self._copy_fixture_state()
        identities = self._build_identities()
        runtime_appraisals = write_runtime_appraisals(self.store, ACTOR_NAMES)
        capabilities = self._issue_capabilities(identities, runtime_appraisals)
        topology = write_topology(
            store=self.store,
            operator_control_url=self.config.operator_control_url,
            provider_control_url=self.config.provider_control_url,
            subcontractor_control_url=self.config.subcontractor_control_url,
            federation_control_url=self.config.federation_control_url,
            market_broker_url=self.config.market_broker_url,
            settlement_desk_url=self.config.settlement_desk_url,
            web3_evidence_mcp_url=self.config.web3_evidence_mcp_url,
            provider_review_mcp_url=self.config.provider_review_mcp_url,
            subcontractor_review_mcp_url=self.config.subcontractor_review_mcp_url,
        )

        service = self._select_service(provider_catalog, order_request)
        market = self._market(service, capabilities.get("sidecar-client"))
        budget_workflow = BudgetWorkflow(store=self.store, trust=self.operator_trust)
        rfq_request = build_rfq_request(order_request, capabilities["procurement-agent"])
        provider_bids = market.request_rfq(rfq_request)
        self.store.write_json("market/rfq-request.json", rfq_request)
        self.store.write_json("market/provider-bids.json", provider_bids)
        (
            history,
            scorecards,
            drift_report,
            provider_passport_verdicts,
            provider_federation_verdicts,
        ) = write_reputation_and_admission_artifacts(
            self.store,
            provider_bids,
            treasury_policy["max_single_order_minor_units"],
        )
        provider_selection = select_provider(
            store=self.store,
            rfq_request=rfq_request,
            bids=provider_bids,
            scorecards=scorecards,
            passport_verdicts=provider_passport_verdicts,
            federation_verdicts=provider_federation_verdicts,
            max_budget_units=treasury_policy["max_single_order_minor_units"],
        )
        if provider_selection["selected_provider_id"] != order_request["provider_id"]:
            order_request = {**order_request, "provider_id": provider_selection["selected_provider_id"]}
            self.store.write_json("scenario/order-request.json", order_request)
        passport_workflow, history = run_provider_passport_workflow(
            store=self.store,
            provider_identity=identities["provider-agent"],
            provider_capability=capabilities["provider-agent"],
            provider_bids=provider_bids,
            federation_control_url=self.config.federation_control_url,
            service_token=self.config.service_token or "",
        )
        (
            quote_request,
            quote_response,
            fulfillment,
            budget_authorization,
            approval,
            payment_handshake,
        ) = self._run_market_flow(
            market=market,
            order_request=order_request,
            treasury_policy=treasury_policy,
            identities=identities,
            capabilities=capabilities,
            budget_workflow=budget_workflow,
        )
        self.store.write_json("market/quote-request.json", quote_request)
        self.store.write_json("market/quote-response.json", quote_response)
        self.store.write_json("market/fulfillment-package.json", fulfillment)

        service_order = self._build_service_order(
            order_request=order_request,
            service=service,
            quote_response=quote_response,
            capabilities=capabilities,
            x402=evidence.x402,
            payment_handshake=payment_handshake,
        )
        self.store.write_json("contracts/service-order.json", service_order)

        validation_index = evidence_loader.build_validation_index(evidence)
        self.store.write_json("web3/validation-index.json", validation_index)
        cutover_readiness = self.evidence_tool.call("build_cutover_readiness")
        self.store.write_json("evidence/cutover-readiness.json", cutover_readiness)
        reputation_workflow = run_provider_reputation_workflow(
            store=self.store,
            provider_identity=identities["provider-agent"],
            passport=passport_workflow.passport,
        )
        federation_workflow = run_provider_federation_workflow(
            store=self.store,
            passport_workflow=passport_workflow,
            reputation_verdict=reputation_workflow.verdict,
            provider_capability=capabilities["provider-agent"],
            federation_control_url=self.config.federation_control_url,
            service_token=self.config.service_token or "",
        )
        runtime_degradation = write_runtime_degradation_workflow(
            store=self.store,
            provider_identity=identities["provider-agent"],
        )
        subcontract_workflow = write_subcontract_workflow(
            store=self.store,
            issuer=self.issuer,
            provider_identity=identities["provider-agent"],
            subcontractor_identity=identities["subcontractor-agent"],
            provider_capability=capabilities["provider-agent"],
            subcontractor_tool=self.subcontractor_review_tool,
            service_order=service_order,
            validation_index=validation_index,
        )
        capabilities["subcontractor-agent"] = subcontract_workflow.capability
        self._write_capabilities(capabilities)
        provider_review = self._run_provider_review(
            service_order=service_order,
            validation_index=validation_index,
            reputation=reputation_workflow.report,
        )
        rail_selection = write_rail_selection(
            store=self.store,
            evidence=evidence,
            order_request=order_request,
        )

        settlement_packet = self._settlement_desk(capabilities.get("sidecar-client")).assemble_packet(
            {
                "order": service_order,
                "quote": quote_response,
                "fulfillment": fulfillment,
                "validation_index": validation_index,
                "rail_selection": rail_selection,
            }
        )
        self.store.write_json("contracts/settlement-packet.json", settlement_packet)

        dispatch = self._build_dispatch(
            identities=identities,
            capabilities=capabilities,
            evidence=evidence,
            quote_response=quote_response,
            settlement_packet=settlement_packet,
            rail_selection=rail_selection,
        )
        self.store.write_json("contracts/web3-settlement-dispatch.json", dispatch)

        receipt = self._build_receipt(evidence, dispatch, quote_response)
        self.store.write_json("contracts/web3-settlement-receipt.json", receipt)

        reconciliation = self._build_reconciliation(
            order=service_order,
            quote_response=quote_response,
            fulfillment=fulfillment,
            dispatch=dispatch,
            receipt=receipt,
            treasury_policy=treasury_policy,
        )
        self.store.write_json("financial/settlement-reconciliation.json", reconciliation)
        dispute = write_dispute_workflow(
            store=self.store,
            service_order=service_order,
            quote_response=quote_response,
            provider_capability=capabilities["provider-agent"],
            settlement_capability=capabilities["settlement-agent"],
        )
        budget_reconciliation = budget_workflow.reconcile_settlement(
            capability_id=capabilities["settlement-agent"]["id"],
            grant_index=0,
            order_id=service_order["order_id"],
            exposed_cost_units=quote_response["price_minor_units"],
            realized_spend_units=quote_response["price_minor_units"],
        )
        budget_summary = budget_workflow.write_summary(budget_authorization, budget_reconciliation)
        overspend_denial = budget_workflow.overspend_negative_control(
            capability_id=capabilities["settlement-agent"]["id"],
            grant_index=0,
            order_id=service_order["order_id"],
            max_budget_units=treasury_policy["max_single_order_minor_units"],
        )
        guardrails = {
            **write_static_guardrail_denials(self.store),
            "overspend": overspend_denial,
        }
        adversarial = write_adversarial_controls(self.store)
        behavior = write_behavioral_reports(
            store=self.store,
            trust=self.operator_trust,
            quote_count=3,
            settlement_count=2,
        )
        receipts = write_receipt_reports(
            store=self.store,
            trust=self.operator_trust,
            expected_counts={
                "trust-control": len(capabilities) + 4,
                "market-api-sidecar": 5,
                "settlement-api-sidecar": 2,
                "web3-evidence-mcp": 1,
                "provider-review-mcp": 3 if provider_review else 0,
                "subcontractor-review-mcp": 1 if subcontract_workflow.review else 0,
                "budget": 2,
                "approval": 1,
                "rail-selection": 1,
            },
        )
        observability = write_observability_artifacts(
            store=self.store,
            order_id=service_order["order_id"],
            receipts=receipts,
            summary_refs={
                "market-api-sidecar": "market/provider-selection.json",
                "provider-review-mcp": "provider/review-result.json",
                "subcontractor-review-mcp": "subcontracting/review-attestation.json",
                "settlement-api-sidecar": "contracts/settlement-packet.json",
                "budget": "chio/budgets/budget-summary.json",
                "approval": "approvals/high-risk-release-audit.json",
                "rail-selection": "settlement/rail-selection.json",
            },
        )
        self._write_timeline(capabilities, quote_response, fulfillment, dispatch, provider_selection, subcontract_workflow, dispute)
        self._write_agent_outputs(
            order_request=order_request,
            service_order=service_order,
            treasury_policy=treasury_policy,
            capabilities=capabilities,
            quote_response=quote_response,
            fulfillment=fulfillment,
            dispatch=dispatch,
            receipt=receipt,
            evidence=evidence,
            provider_selection=provider_selection,
            subcontract_workflow=subcontract_workflow,
            rail_selection=rail_selection,
        )
        summary = self._build_summary(
            service_order=service_order,
            capabilities=capabilities,
            evidence=evidence,
            reconciliation=reconciliation,
            cutover_readiness=cutover_readiness,
            topology=topology,
            budget_summary=budget_summary,
            passport_verdict=passport_workflow.presentation_verdict,
            federation_verdict=federation_workflow.admission,
            reputation_verdict=reputation_workflow.verdict,
            behavior=behavior,
            guardrails=guardrails,
            receipts=receipts,
            provider_review=provider_review,
            provider_selection=provider_selection,
            subcontract_workflow=subcontract_workflow,
            dispute=dispute,
            approval=approval,
            payment_handshake=payment_handshake,
            rail_selection=rail_selection,
            runtime_degradation=runtime_degradation,
            observability=observability,
            history=history,
            drift_report=drift_report,
            adversarial=adversarial,
        )
        self.store.write_json("summary.json", summary)
        self.store.write_manifest()
        return {"artifact_dir": str(self.store.root), "summary": summary}

    def _copy_fixture_state(self) -> tuple[Json, Json, Json]:
        order_request = self.store.copy_json(
            EXAMPLE_ROOT / "workspaces/operator-lab/orders/settlement-proof-review.json",
            "scenario/order-request.json",
        )
        treasury_policy = self.store.copy_json(
            EXAMPLE_ROOT / "workspaces/operator-lab/treasury/policy.json",
            "scenario/treasury-policy.json",
        )
        provider_dir = EXAMPLE_ROOT / "workspaces/provider-lab/providers"
        providers = [
            read_json(provider_dir / "proofworks-agent-auditors.json"),
            read_json(provider_dir / "discount-zk-reviewers.json"),
            read_json(provider_dir / "overbudget-shadow-settlers.json"),
        ]
        provider_catalog = {
            "schema": "chio.example.ioa-web3.provider-catalog.v1",
            "providers": providers,
            "services": providers[0]["services"],
        }
        self.store.write_json("scenario/provider-catalog.json", provider_catalog)
        return order_request, treasury_policy, provider_catalog

    def _build_identities(self) -> dict[str, Any]:
        identities = {name: self.issuer.identity(name) for name in ACTOR_NAMES}
        self.store.write_json(
            "identities/public-identities.json",
            {name: identity.public_document() for name, identity in identities.items()},
        )
        return identities

    def _issue_capabilities(self, identities: dict[str, Any], runtime_appraisals: dict[str, Json]) -> dict[str, Json]:
        root_scope = scope(
            grant("agent-market", "request_rfq", ["invoke", "delegate"]),
            grant("agent-market", "request_quote", ["invoke", "delegate"]),
            grant("agent-market", "request_payment_requirements", ["invoke", "delegate"]),
            grant("agent-market", "submit_payment_proof", ["invoke", "delegate"]),
            grant("agent-market", "accept_fulfillment", ["invoke", "delegate"]),
            grant("http-sidecar-client", "request_rfq", ["invoke", "delegate"]),
            grant("http-sidecar-client", "request_quote", ["invoke", "delegate"]),
            grant("http-sidecar-client", "request_payment_requirements", ["invoke", "delegate"]),
            grant("http-sidecar-client", "submit_payment_proof", ["invoke", "delegate"]),
            grant("http-sidecar-client", "accept_fulfillment", ["invoke", "delegate"]),
            grant("http-sidecar-client", "assemble_packet", ["invoke", "delegate"]),
            grant("http-sidecar-client", "assemble_dispute_packet", ["invoke", "delegate"]),
            grant("chio_http_authority", "authorize_http_request", ["invoke", "delegate"]),
            grant("web3-evidence", "build_cutover_readiness", ["invoke", "delegate"]),
            grant("provider-review", "issue_review_attestation", ["invoke", "delegate"]),
            grant("subcontractor-review", "issue_specialist_review", ["invoke", "delegate"]),
            grant("chio-settle", "create_escrow", ["invoke", "delegate"], 300_000),
            grant("chio-settle", "release_escrow", ["invoke", "delegate"], 200_000),
            grant("chio-settle", "refund_escrow", ["invoke", "delegate"], 100_000),
            grant("chio-anchor", "publish_root", ["invoke", "delegate"]),
            grant("chio-link", "read_price", ["invoke", "delegate"]),
        )
        if self.operator_trust:
            root_cap = self.operator_trust.issue_capability(
                identities["treasury-agent"].public_key,
                root_scope,
                3600,
                runtime_attestation=runtime_appraisals["treasury-agent"]["attestation"],
            )
            self._record_lineage_safe(self.operator_trust, root_cap, None, "root-treasury")
        else:
            root_cap = self.issuer.issue_root(
                identities["treasury-agent"],
                root_scope,
                ttl_seconds=3600,
            )

        capabilities = {
            "root-treasury": root_cap,
            "procurement-agent": self.issuer.delegate(
                parent=root_cap,
                delegator=identities["treasury-agent"],
                delegatee=identities["procurement-agent"],
                capability_scope=scope(
                    grant("agent-market", "request_rfq", ["invoke"]),
                    grant("agent-market", "request_quote", ["invoke"]),
                    grant("agent-market", "request_payment_requirements", ["invoke"]),
                    grant("agent-market", "submit_payment_proof", ["invoke"]),
                    grant("agent-market", "accept_fulfillment", ["invoke"]),
                ),
                capability_id="cap-ioa-web3-procurement",
                ttl_seconds=1800,
                attenuations=[{"kind": "remove_settlement_authority"}],
            ),
            "provider-agent": self.issuer.delegate(
                parent=root_cap,
                delegator=identities["procurement-agent"],
                delegatee=identities["provider-agent"],
                capability_scope=scope(
                    grant("agent-market", "submit_fulfillment", ["invoke", "delegate"]),
                    grant("subcontractor-review", "issue_specialist_review", ["delegate"]),
                ),
                capability_id="cap-ioa-web3-provider",
                ttl_seconds=1200,
                attenuations=[{"kind": "provider_cannot_move_funds"}],
            ),
            "settlement-agent": self.issuer.delegate(
                parent=root_cap,
                delegator=identities["treasury-agent"],
                delegatee=identities["settlement-agent"],
                capability_scope=scope(
                    grant("chio-settle", "create_escrow", ["invoke"], 300_000),
                    grant("chio-settle", "release_escrow", ["invoke"], 200_000),
                    grant("chio-settle", "refund_escrow", ["invoke"], 100_000),
                    grant("chio-anchor", "publish_root", ["invoke"]),
                    grant("chio-link", "read_price", ["invoke"]),
                ),
                capability_id="cap-ioa-web3-settlement",
                ttl_seconds=1800,
                attenuations=[{"kind": "limit_to_base_sepolia_usdc"}],
            ),
            "auditor-agent": self.issuer.delegate(
                parent=root_cap,
                delegator=identities["treasury-agent"],
                delegatee=identities["auditor-agent"],
                capability_scope=scope(grant("web3-evidence", "verify_bundle", ["invoke"])),
                capability_id="cap-ioa-web3-auditor",
                ttl_seconds=1800,
                attenuations=[{"kind": "read_only"}],
            ),
        }
        if self.operator_trust:
            capabilities["sidecar-client"] = self.operator_trust.issue_capability(
                identities["procurement-agent"].public_key,
                scope(
                    grant("http-sidecar-client", "request_rfq", ["invoke"]),
                    grant("http-sidecar-client", "request_quote", ["invoke"]),
                    grant("http-sidecar-client", "request_payment_requirements", ["invoke"]),
                    grant("http-sidecar-client", "submit_payment_proof", ["invoke"]),
                    grant("http-sidecar-client", "accept_fulfillment", ["invoke"], 125_000),
                    grant("http-sidecar-client", "assemble_packet", ["invoke"], 125_000),
                    grant("http-sidecar-client", "assemble_dispute_packet", ["invoke"]),
                    grant("chio_http_authority", "authorize_http_request", ["invoke"]),
                ),
                1800,
                runtime_attestation=runtime_appraisals["procurement-agent"]["attestation"],
            )
            self._record_lineage_safe(
                self.operator_trust,
                capabilities["sidecar-client"],
                root_cap["id"],
                "sidecar-client",
            )
            for name, capability in capabilities.items():
                if name in {"root-treasury", "sidecar-client"}:
                    continue
                self._record_lineage_safe(self.operator_trust, capability, root_cap["id"], name)
            if self.provider_trust:
                self._record_lineage_safe(
                    self.provider_trust,
                    capabilities["provider-agent"],
                    root_cap["id"],
                    "provider-agent-provider-authority",
                )
            if self.federation_trust:
                self._record_lineage_safe(
                    self.federation_trust,
                    capabilities["auditor-agent"],
                    root_cap["id"],
                    "auditor-agent-federation-authority",
                )
        return capabilities

    def _write_capabilities(self, capabilities: dict[str, Json]) -> None:
        for name, capability in capabilities.items():
            self.store.write_json(f"capabilities/{name}.json", capability)
            self.store.write_json(f"chio/capabilities/{name}.json", capability)
            self.store.write_json(
                f"lineage/{name}-chain.json",
                {
                    "capability_id": capability["id"],
                    "subject": capability["subject"],
                    "issuer": capability["issuer"],
                    "delegation_depth": len(capability.get("delegation_chain", [])),
                    "delegation_chain": capability.get("delegation_chain", []),
                },
            )

    def _select_service(self, provider_catalog: Json, order_request: Json) -> Json:
        for service in provider_catalog["services"]:
            if service["service_id"] == order_request["requested_scope"]:
                return service
        raise RuntimeError(f"provider does not offer requested scope: {order_request['requested_scope']}")

    def _market(self, service: Json, sidecar_capability: Json | None) -> Market:
        if self.config.market_broker_url:
            return HttpMarket(JsonHttpClient(self.config.market_broker_url, capability=sidecar_capability))
        return LocalMarket(service)

    def _settlement_desk(self, sidecar_capability: Json | None) -> SettlementDesk:
        if self.config.settlement_desk_url:
            return HttpSettlementDesk(JsonHttpClient(self.config.settlement_desk_url, capability=sidecar_capability))
        return LocalSettlementDesk()

    def _run_market_flow(
        self,
        *,
        market: Market,
        order_request: Json,
        treasury_policy: Json,
        identities: dict[str, Any],
        capabilities: dict[str, Json],
        budget_workflow: BudgetWorkflow,
    ) -> tuple[Json, Json, Json, Json, Json, Json]:
        procurement_cap = capabilities["procurement-agent"]
        provider_cap = capabilities["provider-agent"]
        quote_request = {
            "quote_request_id": f"quote-request-{order_request['order_id']}",
            "order_id": order_request["order_id"],
            "buyer_id": order_request["buyer_id"],
            "provider_id": order_request["provider_id"],
            "requested_scope": order_request["requested_scope"],
            "max_budget_minor_units": order_request["max_budget_minor_units"],
            "currency": order_request["currency"],
            "capability_id": procurement_cap["id"],
        }
        quote_response = market.request_quote(
            {
                "order_id": order_request["order_id"],
                "provider_id": order_request["provider_id"],
                "requested_scope": order_request["requested_scope"],
                "max_budget_minor_units": order_request["max_budget_minor_units"],
                "currency": order_request["currency"],
            }
        )
        quote_response["capability_id"] = procurement_cap["id"]
        approval = {}
        _, approval_decision, _, approval_audit = write_approval_checkpoint(
            store=self.store,
            order_request=order_request,
            quote_response=quote_response,
            treasury_identity=identities["treasury-agent"],
            treasury_capability=capabilities["root-treasury"],
        )
        approval = approval_audit
        budget_authorization = budget_workflow.authorize_quote(
            capability_id=capabilities["settlement-agent"]["id"],
            grant_index=0,
            order_id=order_request["order_id"],
            exposure_units=quote_response["price_minor_units"],
            max_budget_units=treasury_policy["max_single_order_minor_units"],
        )
        if not budget_authorization.get("allowed"):
            raise RuntimeError("Chio budget authorization denied quote acceptance")
        payment_required, payment_proof, payment_satisfaction = write_payment_handshake(
            store=self.store,
            market=market,
            order_request=order_request,
            quote_response=quote_response,
            procurement_capability=procurement_cap,
            settlement_capability=capabilities["settlement-agent"],
            approval_decision=approval_decision,
        )
        fulfillment = market.accept_fulfillment(
            {
                "quote_id": quote_response["quote_id"],
                "order_id": quote_response["order_id"],
                "provider_id": quote_response["provider_id"],
                "accepted_by": identities["provider-agent"].public_key,
                "evidence_refs": EVIDENCE_REFS,
            }
        )
        fulfillment["capability_id"] = provider_cap["id"]
        payment_handshake = {
            "required": payment_required,
            "proof": payment_proof,
            "satisfaction": payment_satisfaction,
        }
        return quote_request, quote_response, fulfillment, budget_authorization, approval, payment_handshake

    def _build_service_order(
        self,
        *,
        order_request: Json,
        service: Json,
        quote_response: Json,
        capabilities: dict[str, Json],
        x402: Json,
        payment_handshake: Json,
    ) -> Json:
        return {
            "schema": "chio.example.ioa-web3.service-order.v1",
            "order_id": order_request["order_id"],
            "buyer": order_request["buyer_id"],
            "provider": order_request["provider_id"],
            "service": service["title"],
            "quote": {
                "units": quote_response["price_minor_units"],
                "currency": quote_response["currency"],
            },
            "payment_requirement": {
                "protocol_hint": "x402",
                "requirements_reference": "web3/x402-requirements-example.json",
                "settlement_mode": x402.get("settlement_mode", "deferred_chio_web3"),
                "local_payment_required": "payments/x402-payment-required.json",
                "payment_proof": payment_handshake["proof"]["proof_id"],
                "payment_status": payment_handshake["satisfaction"]["status"],
            },
            "capabilities": {
                "procurement": capabilities["procurement-agent"]["id"],
                "provider": capabilities["provider-agent"]["id"],
                "settlement": capabilities["settlement-agent"]["id"],
                "auditor": capabilities["auditor-agent"]["id"],
            },
            "market_refs": {
                "quote_request": "market/quote-request.json",
                "quote_response": "market/quote-response.json",
                "fulfillment": "market/fulfillment-package.json",
            },
        }

    def _run_provider_review(self, *, service_order: Json, validation_index: Json, reputation: Json) -> Json | None:
        if not self.provider_review_tool:
            self.store.write_json(
                "provider/review-attestation.json",
                {
                    "schema": "chio.example.ioa-web3.provider-review-attestation.v1",
                    "verdict": "skipped",
                    "reason": "provider review MCP edge unavailable",
                },
            )
            return None
        inspection = self.provider_review_tool.call(
            "inspect_service_order",
            {"service_order": service_order},
        )
        reputation_eval = self.provider_review_tool.call(
            "evaluate_provider_reputation",
            {"reputation": reputation},
        )
        attestation = self.provider_review_tool.call(
            "issue_review_attestation",
            {"service_order": service_order, "validation_index": validation_index},
        )
        review = {
            "schema": "chio.example.ioa-web3.provider-review-result.v1",
            "inspection": inspection,
            "reputation": reputation_eval,
            "attestation": attestation,
            "verdict": "pass"
            if inspection.get("verdict") == "pass"
            and reputation_eval.get("verdict") == "pass"
            and attestation.get("verdict") == "pass"
            else "fail",
        }
        self.store.write_json("provider/service-order-inspection.json", inspection)
        self.store.write_json("provider/reputation-evaluation.json", reputation_eval)
        self.store.write_json("provider/review-attestation.json", attestation)
        self.store.write_json("provider/review-result.json", review)
        return review

    def _build_dispatch(
        self,
        *,
        identities: dict[str, Any],
        capabilities: dict[str, Json],
        evidence: LoadedEvidence,
        quote_response: Json,
        settlement_packet: Json,
        rail_selection: Json,
    ) -> Json:
        contracts = evidence.deployed_contracts
        base_smoke = evidence.base_smoke
        settlement_cap = capabilities["settlement-agent"]
        quote_minor = quote_response["price_minor_units"]
        return {
            "schema": "chio.web3-settlement-dispatch.v1",
            "dispatch_id": "dispatch-ioa-web3-001",
            "issued_at": now_epoch(),
            "trust_profile_id": "chio.official-web3-stack",
            "contract_package_id": "chio.official-web3-contracts",
            "chain_id": evidence.chain_id,
            "capital_instruction": {
                "body": {
                    "schema": "chio.credit.capital-instruction.v1",
                    "instructionId": "cei-ioa-web3-001",
                    "issuedAt": now_epoch(),
                    "query": {
                        "agentSubject": identities["provider-agent"].public_key,
                        "receiptLimit": 50,
                        "facilityLimit": 1,
                        "bondLimit": 1,
                        "lossEventLimit": 5,
                    },
                    "subjectKey": identities["provider-agent"].public_key,
                    "sourceId": "capital-source:internet-of-agents-web3",
                    "sourceKind": "facility_commitment",
                    "governedReceiptId": "rcpt-ioa-web3-001",
                    "completionFlowRowId": "economic-completion-flow:rcpt-ioa-web3-001",
                    "action": "transfer_funds",
                    "ownerRole": "operator_treasury",
                    "counterpartyRole": "agent_counterparty",
                    "counterpartyId": identities["provider-agent"].public_key,
                    "amount": {"units": quote_minor, "currency": "USDC"},
                    "authorityChain": [
                        {
                            "role": "operator_treasury",
                            "principalId": identities["treasury-agent"].public_key,
                            "approvedAt": now_epoch(),
                            "expiresAt": capabilities["root-treasury"]["expires_at"],
                            "note": "root budget holder approved bounded web3 settlement",
                        },
                        {
                            "role": "settlement_agent",
                            "principalId": identities["settlement-agent"].public_key,
                            "approvedAt": now_epoch(),
                            "expiresAt": settlement_cap["expires_at"],
                            "note": "delegated only Base Sepolia USDC settlement authority",
                        },
                    ],
                    "executionWindow": {"notBefore": now_epoch(), "notAfter": settlement_cap["expires_at"]},
                    "rail": {
                        "kind": rail_selection["selected_rail"]["kind"],
                        "railId": rail_selection["selected_rail"]["rail_id"],
                        "custodyProviderId": "operator-test-wallet",
                        "sourceAccountRef": "wallet:base-sepolia-smoke"
                        if rail_selection["selected_rail"]["rail_id"] == "base-sepolia-usdc"
                        else "wallet:local-devnet",
                        "destinationAccountRef": identities["provider-agent"].public_key,
                        "jurisdiction": "US",
                    },
                    "intendedState": "pending_execution",
                    "reconciledState": "observed" if base_smoke else "qualified_not_live",
                    "supportBoundary": {
                        "capitalBookAuthoritative": True,
                        "externalExecutionAuthoritative": bool(base_smoke),
                        "automaticDispatchSupported": True,
                        "custodyNeutralInstructionSupported": False,
                    },
                    "evidenceRefs": [
                        {
                            "kind": "base_sepolia_smoke" if base_smoke else "web3_e2e_qualification",
                            "referenceId": "target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json"
                            if base_smoke else "target/web3-e2e-qualification/partner-qualification.json",
                            "observedAt": now_epoch(),
                            "locator": "web3/base-sepolia-smoke.json"
                            if base_smoke else "web3/e2e-partner-qualification.json",
                        }
                    ],
                    "description": "settle one internet-of-agents service order over Chio web3 escrow evidence",
                },
                "signerKey": identities["settlement-agent"].public_key,
                "signature": identities["settlement-agent"].sign({"dispatch": "dispatch-ioa-web3-001"}),
            },
            "settlement_path": "merkle_proof",
            "settlement_packet_id": settlement_packet["packet_id"],
            "rail_selection_id": rail_selection["selected_rail"]["rail_id"],
            "denied_rails": rail_selection["denied_rails"],
            "settlement_amount": {"units": quote_minor, "currency": "USDC"},
            "escrow_id": base_smoke.get("escrows", {}).get("primary", {}).get("escrow_id", "local-e2e-escrow")
            if base_smoke else "local-e2e-escrow",
            "escrow_contract": contracts.get("chio.escrow", "base-sepolia-smoke-not-attached"),
            "bond_vault_contract": contracts.get("chio.bond-vault", "base-sepolia-smoke-not-attached"),
            "beneficiary_address": identities["provider-agent"].public_key,
            "support_boundary": {
                "real_dispatch_supported": bool(base_smoke),
                "anchor_proof_required": True,
                "oracle_evidence_required_for_fx": True,
                "custody_boundary_explicit": True,
                "reversal_supported": True,
            },
            "note": "Example binds recursive agent delegation to the validated Base-first Chio web3 stack.",
        }

    def _build_receipt(self, evidence: LoadedEvidence, dispatch: Json, quote_response: Json) -> Json:
        txs = evidence.txs
        contracts = evidence.deployed_contracts
        final_tx = txs.get("settlement.final_release", "local-web3-e2e-qualified")
        refund_tx = txs.get("settlement.timeout_refund", "local-web3-e2e-qualified")
        root_tx = txs.get("anchor.final_root_publish", "local-web3-e2e-qualified")
        return {
            "schema": "chio.web3-settlement-execution-receipt.v1",
            "execution_receipt_id": "receipt-ioa-web3-001",
            "issued_at": now_epoch(),
            "dispatch": dispatch,
            "observed_execution": {
                "observedAt": now_epoch(),
                "externalReferenceId": final_tx,
                "amount": {"units": quote_response["price_minor_units"], "currency": "USDC"},
            },
            "lifecycle_state": "settled",
            "settlement_reference": "settlement-ioa-web3-001",
            "reconciled_anchor_proof": {
                "chain_anchor": {
                    "chain_id": evidence.chain_id,
                    "contract_address": contracts.get("chio.root-registry", "local-web3-e2e-qualified"),
                    "tx_hash": root_tx,
                },
                "escrow_release": {
                    "escrow_contract": contracts.get("chio.escrow", "base-sepolia-smoke-not-attached"),
                    "final_release_tx_hash": final_tx,
                    "timeout_refund_tx_hash": refund_tx,
                },
            },
            "oracle_evidence": evidence.base_smoke.get("prices", {}) if evidence.base_smoke else {
                "source": "target/web3-e2e-qualification/partner-qualification.json",
                "status": evidence.e2e.get("status"),
            },
        }

    def _build_reconciliation(
        self,
        *,
        order: Json,
        quote_response: Json,
        fulfillment: Json,
        dispatch: Json,
        receipt: Json,
        treasury_policy: Json,
    ) -> Json:
        return {
            "schema": "chio.example.ioa-web3.reconciliation.v1",
            "order_id": order["order_id"],
            "quote_id": quote_response["quote_id"],
            "fulfillment_id": fulfillment["fulfillment_id"],
            "dispatch_id": dispatch["dispatch_id"],
            "execution_receipt_id": receipt["execution_receipt_id"],
            "quoted_amount": order["quote"],
            "settled_amount": receipt["observed_execution"]["amount"],
            "status": "reconciled",
            "mainnet_blocked": treasury_policy["mainnet_blocked"],
        }

    def _write_timeline(
        self,
        capabilities: dict[str, Json],
        quote_response: Json,
        fulfillment: Json,
        dispatch: Json,
        provider_selection: Json,
        subcontract_workflow: Any,
        dispute: Json,
    ) -> None:
        self.store.write_json(
            "scenario/timeline.json",
            {
                "schema": "chio.example.ioa-web3.timeline.v1",
                "events": [
                    {
                        "actor": "treasury-agent",
                        "event": "issued root web3 budget",
                        "capability_id": capabilities["root-treasury"]["id"],
                    },
                    {
                        "actor": "procurement-agent",
                        "event": "selected provider through Chio RFQ routing",
                        "selected_provider_id": provider_selection["selected_provider_id"],
                    },
                    {
                        "actor": "procurement-agent",
                        "event": "satisfied x402 payment proof and accepted provider quote",
                        "quote_id": quote_response["quote_id"],
                    },
                    {
                        "actor": "provider-agent",
                        "event": "delivered validation review package",
                        "fulfillment_id": fulfillment["fulfillment_id"],
                    },
                    {
                        "actor": "subcontractor-agent",
                        "event": "completed specialist proof-leaf review",
                        "capability_id": subcontract_workflow.capability["id"],
                    },
                    {
                        "actor": "settlement-agent",
                        "event": "assembled web3 settlement dispatch",
                        "dispatch_id": dispatch["dispatch_id"],
                    },
                    {
                        "actor": "settlement-agent",
                        "event": "resolved secondary dispute branch",
                        "status": dispute["status"],
                    },
                    {
                        "actor": "auditor-agent",
                        "event": "verified bundle against web3 validation ladder",
                        "validation_index": "web3/validation-index.json",
                    },
                ],
            },
        )

    def _write_agent_outputs(
        self,
        *,
        order_request: Json,
        service_order: Json,
        treasury_policy: Json,
        capabilities: dict[str, Json],
        quote_response: Json,
        fulfillment: Json,
        dispatch: Json,
        receipt: Json,
        evidence: LoadedEvidence,
        provider_selection: Json,
        subcontract_workflow: Any,
        rail_selection: Json,
    ) -> None:
        txs = evidence.txs
        self.store.write_json(
            "agents/treasury-output.json",
            {
                "decision": "delegate_bounded_web3_budget",
                "capability_id": capabilities["root-treasury"]["id"],
                "max_budget": {
                    "units": treasury_policy["max_single_order_minor_units"],
                    "currency": treasury_policy["currency"],
                },
                "order_id": order_request["order_id"],
            },
        )
        self.store.write_json(
            "agents/procurement-output.json",
            {
                "decision": "select_provider_and_satisfy_x402",
                "capability_id": capabilities["procurement-agent"]["id"],
                "order_id": service_order["order_id"],
                "quote": service_order["quote"],
                "quote_id": quote_response["quote_id"],
                "selected_provider_id": provider_selection["selected_provider_id"],
                "payment_status": service_order["payment_requirement"]["payment_status"],
            },
        )
        self.store.write_json(
            "agents/provider-output.json",
            {
                "decision": "fulfill_order",
                "capability_id": capabilities["provider-agent"]["id"],
                "fulfillment_receipt": "rcpt-ioa-web3-001",
                "fulfillment_id": fulfillment["fulfillment_id"],
                "subcontractor_capability_id": subcontract_workflow.capability["id"],
            },
        )
        self.store.write_json(
            "agents/subcontractor-output.json",
            {
                "decision": "complete_specialist_review",
                "capability_id": subcontract_workflow.capability["id"],
                "lineage_depth": subcontract_workflow.lineage_depth,
                "review_attestation": "subcontracting/review-attestation.json",
            },
        )
        self.store.write_json(
            "agents/settlement-output.json",
            {
                "decision": "settle_with_chio_web3_evidence",
                "capability_id": capabilities["settlement-agent"]["id"],
                "dispatch_id": dispatch["dispatch_id"],
                "receipt_id": receipt["execution_receipt_id"],
                "selected_rail": rail_selection["selected_rail"]["rail_id"],
                "final_release_tx_hash": txs.get("settlement.final_release", "local-web3-e2e-qualified"),
                "timeout_refund_tx_hash": txs.get("settlement.timeout_refund", "local-web3-e2e-qualified"),
            },
        )
        self.store.write_json(
            "agents/auditor-output.json",
            {
                "decision": "accept_bundle",
                "capability_id": capabilities["auditor-agent"]["id"],
                "validation_index": "web3/validation-index.json",
                "base_sepolia_live_smoke_included": bool(evidence.base_smoke),
                "cutover_readiness": "evidence/cutover-readiness.json",
                "reconciliation": "financial/settlement-reconciliation.json",
            },
        )

    def _build_summary(
        self,
        *,
        service_order: Json,
        capabilities: dict[str, Json],
        evidence: LoadedEvidence,
        reconciliation: Json,
        cutover_readiness: Json,
        topology: Json,
        budget_summary: Json,
        passport_verdict: Json,
        federation_verdict: Json,
        reputation_verdict: Json,
        behavior: Json,
        guardrails: dict[str, Json],
        receipts: Json,
        provider_review: Json | None,
        provider_selection: Json,
        subcontract_workflow: Any,
        dispute: Json,
        approval: Json,
        payment_handshake: Json,
        rail_selection: Json,
        runtime_degradation: Json,
        observability: Json,
        history: Json,
        drift_report: Json,
        adversarial: dict[str, Json],
    ) -> Json:
        max_depth = max(len(capability.get("delegation_chain", [])) for capability in capabilities.values())
        guardrail_status = {
            name: "denied" if artifact.get("denied") else "failed"
            for name, artifact in guardrails.items()
        }
        adversarial_status = {
            name: "denied" if artifact.get("denied") else "failed"
            for name, artifact in adversarial.items()
            if name != "summary"
        }
        history_job_count = history.get("job_count", len(history.get("jobs", [])))
        return {
            "schema": "chio.example.ioa-web3.summary.v1",
            "example": "internet-of-agents-web3-network",
            "order_id": service_order["order_id"],
            "agent_count": len(ACTOR_NAMES),
            "capability_count": len(capabilities),
            "chio_mediated": self.chio_mediated,
            "mediation_status": "pass" if self.chio_mediated and not topology["directUnmediatedDefaultPath"] else "fail",
            "receipt_counts_by_boundary": receipts.get("boundaries", {}),
            "capability_lineage_depth": max_depth,
            "budget_exposure": budget_summary.get("authorizationStatus"),
            "budget_reconciliation": budget_summary.get("reconciliationStatus"),
            "passport_verdict": passport_verdict.get("verdict"),
            "federation_verdict": federation_verdict.get("verdict"),
            "reputation_verdict": reputation_verdict.get("verdict"),
            "behavioral_baseline_status": behavior.get("verdict"),
            "guardrail_denial_status": guardrail_status,
            "provider_review_verdict": provider_review.get("verdict") if provider_review else "missing",
            "rfq_selection_status": provider_selection.get("status"),
            "selected_provider_id": provider_selection.get("selected_provider_id"),
            "rejected_provider_count": len(provider_selection.get("rejected_providers", [])),
            "subcontract_lineage_depth": subcontract_workflow.lineage_depth,
            "subcontractor_review_verdict": subcontract_workflow.review.get("verdict"),
            "dispute_status": dispute.get("status"),
            "approval_status": approval.get("status"),
            "x402_payment_status": payment_handshake["satisfaction"].get("status"),
            "rail_selection_status": rail_selection.get("status"),
            "selected_rail": rail_selection.get("selected_rail", {}).get("rail_id"),
            "runtime_degradation_status": runtime_degradation.get("status"),
            "observability_status": observability.get("status"),
            "historical_reputation_status": "pass"
            if history_job_count >= 5 and drift_report.get("status") == "pass"
            else "fail",
            "adversarial_denial_status": adversarial_status,
            "settlement_status": "settled",
            "reconciliation_status": reconciliation["status"],
            "base_sepolia_live_smoke_included": bool(evidence.base_smoke),
            "base_sepolia_smoke_status": evidence.base_smoke.get("status") if evidence.base_smoke else "not_attached",
            "base_sepolia_attachment_status": "attached" if evidence.base_smoke else "not_attached_optional",
            "web3_local_e2e_status": evidence.e2e.get("status"),
            "promotion_checks": len(evidence.promotion.get("checks", [])),
            "ops_assertions": len(evidence.ops.get("assertions", [])),
            "mainnet_blocked": cutover_readiness.get("mainnet_blocked"),
            "service_topology": {
                "market_broker": "chio-api-protect" if self.config.market_broker_url else "local-direct",
                "settlement_desk": "chio-api-protect" if self.config.settlement_desk_url else "local-direct",
                "evidence_tool": "chio-mcp-serve-http" if self.config.web3_evidence_mcp_url else "stdio-direct",
                "provider_review": "chio-mcp-serve-http" if self.config.provider_review_mcp_url else "missing",
                "subcontractor_review": "chio-mcp-serve-http"
                if self.config.subcontractor_review_mcp_url else "missing",
            },
        }
