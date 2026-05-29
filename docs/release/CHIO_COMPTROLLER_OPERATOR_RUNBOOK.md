# Chio Comptroller Operator Runbook

## Purpose

This runbook defines the operator-facing control surfaces that make Chio more
than a technical control plane. It focuses on the economic governance plane:
budgets, authorization context, settlement reconciliation, metered billing,
underwriting, credit, capital, and liability workflows.

This runbook does not prove a market position. It documents the live operator
surfaces that would have to be run by an external operator before that broader
claim could be honest.

## Supported Operator Plane

The current operator-facing control plane is centered on `chio trust serve` and
its trust-control HTTP surface.

Representative governed endpoints already exposed by the service include:

- operator report aggregation
- settlement reconciliation report and update
- metered billing reconciliation report and update
- authorization-context report
- behavioral feed export
- exposure ledger and credit scorecard reports
- credit facility, bond, loss-lifecycle, and backtest surfaces
- capital book, instruction, and allocation-decision surfaces
- liability provider, quote, bind, claim, dispute, adjudication, payout, and
  settlement surfaces

The authoritative runtime wiring lives in:

- [cluster_and_reports.rs](../../crates/chio-control-plane/src/trust_control/cluster_and_reports.rs)
- [receipt_handlers.rs](../../crates/chio-control-plane/src/trust_control/receipt_handlers.rs)
- [risk_finance_handlers.rs](../../crates/chio-control-plane/src/trust_control/risk_finance_handlers.rs)
- [service_runtime.rs](../../crates/chio-control-plane/src/trust_control/service_runtime.rs)

## Core Operator Outputs

The operator plane currently exposes these first-class review artifacts:

- one aggregated operator report
- budget-utilization reporting
- compliance reporting
- settlement-reconciliation reporting
- metered-billing reconciliation reporting
- authorization-context reporting
- shared-evidence reporting
- underwriting decisions and simulations
- signed credit, capital, and liability artifacts

These are not merely log lines. They are typed outputs over governed receipt
and budget state.

## Required Runtime Inputs

Minimum persistent state for the economic plane:

- `--receipt-db`
- `--budget-db`
- `--authority-db`
- `--service-token`

Additional deployment inputs depend on the lanes exercised:

- underwriting or market policy/config files
- federation and provider registries
- verifier or enterprise-provider policies
- explicit operator signing material where signed exports are required

## Review Flow

1. Bring up `chio trust serve` with persistent receipt, budget, and authority
   state.
2. Confirm the operator report endpoints respond under service auth.
3. Confirm settlement and metered-billing reconciliation actions mutate only
   through governed update surfaces.
4. Confirm underwriting, credit, capital, and liability artifacts are issued
   through signed, typed trust-control surfaces rather than ad hoc local files.
5. Archive the operator qualification bundle before promotion outside the local
   operator boundary.

## Qualification Command

```bash
./scripts/qualify-comptroller-operator-surfaces.sh
```

Review the resulting bundle under:

`target/release-qualification/comptroller-operator-surfaces/`

## Boundaries

This operator runbook proves:

- Chio has externally describable operator control surfaces for the economic
  plane
- those surfaces are backed by governed state and typed reports

This runbook does not prove:

- independent third-party operators are already running those surfaces in
  production
- partners are already economically dependent on Chio as their control layer

