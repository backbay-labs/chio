# Infrastructure as Code Integration: Governing the Most Dangerous Tool Call

> **Status**: Proposed April 2026
> **Priority**: High -- when an agent runs `terraform apply`, it is making
> the highest-blast-radius tool call in the entire agent ecosystem. If Chio
> exists to govern tool access, this is the tool access that most needs
> governing. Covers Terraform, Pulumi, Crossplane, and CDK.

## 1. Why Infrastructure as Code

The initial instinct was to skip IaC: "niche and orthogonal to the core
agent story." That was wrong on both counts.

**Not niche.** Agent-driven infrastructure management is the next wave of
DevOps. Agents that respond to incidents by scaling infrastructure, agents
that provision customer environments on demand, agents that manage CI/CD
pipelines, agents that handle capacity planning. This is happening now.

**Not orthogonal.** `terraform apply` IS a tool call. It is literally an
agent invoking a tool that modifies real-world infrastructure. It creates
databases, opens network paths, provisions IAM roles, allocates compute.
This is the exact use case Chio was designed for -- capability-bounded,
attested, auditable tool access.

The difference is blast radius. When an agent calls a search API with the
wrong query, you get bad results. When an agent runs `terraform apply` with
the wrong config, you get a production outage, a security breach, or a
five-figure cloud bill.

### What Chio Adds to IaC

| IaC alone | IaC + Chio |
|-----------|-----------|
| IAM/RBAC controls who can apply | Capability tokens control what specific resources an agent can provision |
| Sentinel/OPA validates policy at plan time | Chio guards validate capability + identity + budget before any action |
| State file records what exists | Receipt proves WHO authorized it, WHEN, with WHAT capability |
| Plan/apply separation is manual workflow | Plan/apply separation is enforced by capability scope levels |
| Drift is detected after the fact | Drift without a receipt is a security signal |
| Modules are code organization | Modules are capability boundaries |

## 2. Architecture

### 2.1 Terraform Integration Model

Chio wraps Terraform's execution lifecycle. The key insight: Terraform
already has a two-phase model (plan / apply) that maps directly to Chio's
capability tiers.

```
Agent (requests infrastructure change)
  |
  v
Chio Evaluate: scope="infra:plan"  (low privilege, read-only)
  |
  | allowed
  v
terraform plan -> plan output
  |
  v
Chio Guard: plan-review (human or automated review of plan output)
  |
  | approved
  v
Chio Evaluate: scope="infra:apply" + approval guard  (high privilege)
  |
  | allowed
  v
terraform apply -> state change
  |
  v
Chio Receipt: signed attestation of what was provisioned, by whom, under what authority
  |
  v
State file + Receipt = complete provenance
```

### 2.2 Module-Level Capability Scoping

Terraform modules are the natural capability boundary. Each module maps
to a Chio scope:

```
Modules                          Chio Scopes
+------------------------+      +----------------------------------+
| modules/rds/           | ---> | infra:database:rds               |
| modules/elasticache/   | ---> | infra:cache:redis                |
| modules/vpc/           | ---> | infra:network:vpc                |
| modules/iam/           | ---> | infra:iam:roles                  |
| modules/s3/            | ---> | infra:storage:s3                 |
| modules/lambda/        | ---> | infra:compute:lambda             |
| modules/eks/           | ---> | infra:compute:kubernetes         |
+------------------------+      +----------------------------------+

Agent capability grant:
  scopes: ["infra:database:rds", "infra:cache:redis"]
  # This agent can provision databases and caches
  # It CANNOT provision VPCs, IAM roles, or compute
  # terraform plan will succeed but apply will be denied
  # for any resources outside granted scopes
```

### 2.3 Provider-Level Trust

Terraform providers are another trust boundary. An agent operating in a
specific cloud account should only use providers for that account:

```
Chio Policy:
  provider_trust:
    - provider: "aws"
      allowed_regions: ["us-east-1", "us-west-2"]
      allowed_accounts: ["123456789012"]
    - provider: "google"
      denied: true   # This agent cannot touch GCP
    - provider: "kubernetes"
      allowed_contexts: ["staging-cluster"]
      # Cannot target production cluster
```

## 3. Terraform Integration

### 3.1 Terraform Wrapper CLI

A thin wrapper around `terraform` that intercepts plan and apply:

```python
# chio-terraform: wraps terraform CLI with Chio governance
import subprocess
import json
from chio_sdk import ChioClient

class ChioTerraform:
    """Wraps terraform CLI with Chio capability enforcement."""

    def __init__(self, sidecar_url: str = "http://127.0.0.1:9090"):
        self.chio = ChioClient(base_url=sidecar_url)

    def plan(self, working_dir: str, var_file: str | None = None) -> dict:
        """Run terraform plan with Chio evaluation."""
        # Evaluate plan capability (low privilege)
        verdict = self.chio.evaluate_sync(
            tool="terraform:plan",
            scope="infra:plan",
            arguments={
                "working_dir": working_dir,
                "var_file": var_file,
            },
        )

        if verdict.denied:
            raise PermissionError(f"Chio denied terraform plan: {verdict.reason}")

        # Run terraform plan, output as JSON for analysis
        result = subprocess.run(
            ["terraform", "plan", "-out=tfplan", "-json"]
            + ([f"-var-file={var_file}"] if var_file else []),
            cwd=working_dir,
            capture_output=True,
            text=True,
        )

        # Parse plan for resource changes
        plan_show = subprocess.run(
            ["terraform", "show", "-json", "tfplan"],
            cwd=working_dir,
            capture_output=True,
            text=True,
        )
        plan_data = json.loads(plan_show.stdout)

        # Record plan receipt
        self.chio.record_sync(
            verdict=verdict,
            result_hash=self._hash_plan(plan_data),
        )

        return plan_data

    def apply(
        self,
        working_dir: str,
        plan_data: dict,
        auto_approve: bool = False,
    ) -> dict:
        """Run terraform apply with Chio evaluation + approval guard."""
        # Extract resource types from plan for scope checking
        resource_scopes = self._plan_to_scopes(plan_data)

        # Evaluate apply capability (high privilege, per-resource-type)
        verdict = self.chio.evaluate_sync(
            tool="terraform:apply",
            scope="infra:apply",
            arguments={
                "working_dir": working_dir,
                "resource_scopes": resource_scopes,
                "resource_count": len(plan_data.get("resource_changes", [])),
                "plan_hash": self._hash_plan(plan_data),
            },
            guards=["plan-review"],  # Requires plan review approval
        )

        if verdict.denied:
            raise PermissionError(f"Chio denied terraform apply: {verdict.reason}")

        # Check each resource type against granted scopes
        for scope in resource_scopes:
            resource_verdict = self.chio.evaluate_sync(
                tool=f"terraform:apply:{scope}",
                scope=f"infra:{scope}",
            )
            if resource_verdict.denied:
                raise PermissionError(
                    f"Chio denied resource type {scope}: {resource_verdict.reason}"
                )

        # Run terraform apply
        result = subprocess.run(
            ["terraform", "apply", "tfplan"]
            if not auto_approve
            else ["terraform", "apply", "-auto-approve"],
            cwd=working_dir,
            capture_output=True,
            text=True,
        )

        # Record apply receipt with full state change attestation
        receipt = self.chio.record_sync(
            verdict=verdict,
            result_hash=self._hash_state(working_dir),
        )

        return {
            "success": result.returncode == 0,
            "receipt_id": receipt.receipt_id,
            "resources_changed": len(plan_data.get("resource_changes", [])),
        }

    def _plan_to_scopes(self, plan_data: dict) -> list[str]:
        """Extract Chio scopes from terraform plan resource changes."""
        scopes = set()
        for change in plan_data.get("resource_changes", []):
            # aws_rds_instance -> database:rds
            # aws_elasticache_cluster -> cache:redis
            # aws_vpc -> network:vpc
            resource_type = change["type"]
            scope = self._resource_type_to_scope(resource_type)
            scopes.add(scope)
        return sorted(scopes)

    def _resource_type_to_scope(self, resource_type: str) -> str:
        """Map terraform resource type to Chio scope."""
        scope_map = {
            "aws_db_instance": "database:rds",
            "aws_rds_cluster": "database:rds",
            "aws_elasticache_cluster": "cache:redis",
            "aws_vpc": "network:vpc",
            "aws_subnet": "network:subnet",
            "aws_security_group": "network:security-group",
            "aws_iam_role": "iam:role",
            "aws_iam_policy": "iam:policy",
            "aws_s3_bucket": "storage:s3",
            "aws_lambda_function": "compute:lambda",
            "aws_eks_cluster": "compute:kubernetes",
            "google_compute_instance": "compute:vm",
            "google_sql_database_instance": "database:cloudsql",
            "azurerm_resource_group": "azure:resource-group",
        }
        return scope_map.get(resource_type, f"unknown:{resource_type}")
```

### 3.2 Plan Review Guard

The plan review guard inspects the terraform plan output and makes a
policy decision:

```python
# Chio guard: reviews terraform plan before approving apply
class TerraformPlanReviewGuard:
    """Guard that reviews terraform plan for policy violations."""

    async def evaluate(self, context) -> GuardVerdict:
        plan_hash = context.arguments.get("plan_hash")
        resource_scopes = context.arguments.get("resource_scopes", [])
        resource_count = context.arguments.get("resource_count", 0)

        violations = []

        # Check: no IAM changes without explicit approval
        if any(s.startswith("iam:") for s in resource_scopes):
            violations.append("IAM changes require elevated approval")

        # Check: no network changes in production
        if context.environment == "production":
            if any(s.startswith("network:") for s in resource_scopes):
                violations.append("Network changes in production require SRE approval")

        # Check: resource count threshold
        if resource_count > 20:
            violations.append(f"Large change set ({resource_count} resources) requires manual review")

        # Check: no destroy actions
        if context.arguments.get("has_destroys"):
            violations.append("Destroy actions require explicit approval")

        if violations:
            return GuardVerdict.deny(
                reason=f"Plan review failed: {'; '.join(violations)}",
                require_approval=True,
                approval_context={
                    "violations": violations,
                    "plan_hash": plan_hash,
                    "resource_count": resource_count,
                },
            )

        return GuardVerdict.allow()
```

### 3.3 Terraform Provider Plugin (Advanced)

For deeper integration, Chio can run as a Terraform provider that validates
capabilities before delegating to the real provider:

```hcl
# main.tf
terraform {
  required_providers {
    chio = {
      source = "backbay-labs/chio"
      version = "~> 0.1"
    }
  }
}

provider "chio" {
  sidecar_url = "http://127.0.0.1:9090"
}

# Chio-governed resource: wraps aws_db_instance
resource "chio_governed_resource" "database" {
  provider_resource = "aws_db_instance"
  scope             = "infra:database:rds"

  config = jsonencode({
    identifier     = "agent-provisioned-db"
    engine         = "postgres"
    instance_class = "db.t3.medium"
  })

  # Budget constraint: max cost per month
  budget {
    max_monthly_cost_usd = 200
  }
}
```

### 3.4 State File + Receipt Correlation

```
Terraform State                    Chio Receipt
+-----------------------------+    +-----------------------------+
| resource: aws_db_instance   |    | receipt_id: rcpt_abc123     |
| id: db-xyz789               |    | tool: terraform:apply       |
| arn: arn:aws:rds:...        |    | scope: infra:database:rds   |
| created: 2026-04-15         |    | identity: agent-42          |
|                             |    | capability: cap_def456      |
| Who created this?           |    | grant_authority: admin@co   |
| Under what authority?       |    | timestamp: 2026-04-15T14:30 |
| Is this legitimate?         |    | signature: 0x7f3a...        |
+-----------------------------+    +-----------------------------+
         |                                    |
         +-------- correlated by --------+
         |  state.resource_id = receipt.meta.tf_resource_id  |
         +--------------------------------------------------+
```

### 3.5 Drift Detection as Capability Violation

```python
class ChioDriftDetector:
    """Correlate terraform drift with Chio receipts."""

    async def check_drift(self, working_dir: str) -> DriftReport:
        # Run terraform plan to detect drift
        result = subprocess.run(
            ["terraform", "plan", "-detailed-exitcode", "-json"],
            cwd=working_dir,
            capture_output=True,
        )

        if result.returncode == 2:  # Drift detected
            plan = json.loads(result.stdout)
            drift_resources = self._extract_drift(plan)

            for resource in drift_resources:
                # Check if this change has a Chio receipt
                receipts = await self.chio.find_receipts(
                    meta={
                        "tf_resource_id": resource["id"],
                        "tf_resource_type": resource["type"],
                    },
                    after=resource.get("last_known_good"),
                )

                if not receipts:
                    # Drift with no receipt = unauthorized change
                    yield DriftViolation(
                        resource=resource,
                        severity="critical",
                        reason="Infrastructure change with no Chio receipt -- "
                               "either a human bypassed Chio or an agent "
                               "bypassed the sidecar",
                    )
                else:
                    # Drift with receipt = authorized change through Chio
                    yield DriftAuthorized(
                        resource=resource,
                        receipt=receipts[-1],
                    )
```

## 4. Pulumi Integration

Pulumi uses real programming languages. Chio decorators work naturally:

### 4.1 Python Decorator Model

```python
import pulumi
import pulumi_aws as aws
from chio_iac import chio_resource, chio_stack

@chio_stack(scope="infra:staging-environment")
def staging():
    """Entire Pulumi stack governed by a single Chio grant."""

    @chio_resource(scope="infra:database:rds")
    def create_database():
        return aws.rds.Instance(
            "agent-db",
            engine="postgres",
            instance_class="db.t3.medium",
            allocated_storage=20,
        )

    @chio_resource(scope="infra:cache:redis")
    def create_cache():
        return aws.elasticache.Cluster(
            "agent-cache",
            engine="redis",
            node_type="cache.t3.micro",
            num_cache_nodes=1,
        )

    @chio_resource(scope="infra:network:vpc")
    def create_vpc():
        # This will be DENIED if the agent only has database+cache scopes
        return aws.ec2.Vpc(
            "agent-vpc",
            cidr_block="10.0.0.0/16",
        )

    db = create_database()
    cache = create_cache()
    # vpc = create_vpc()  # Would fail: agent lacks infra:network:vpc

    return {"db_endpoint": db.endpoint, "cache_endpoint": cache.cache_nodes}

staging()
```

### 4.2 Implementation

```python
def chio_resource(scope: str, guards: list[str] | None = None):
    """Decorator that evaluates Chio capability before Pulumi resource creation."""

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            chio = ChioClient()

            verdict = chio.evaluate_sync(
                tool=f"pulumi:resource:{fn.__name__}",
                scope=scope,
                arguments={
                    "function": fn.__name__,
                    "stack": pulumi.get_stack(),
                    "project": pulumi.get_project(),
                },
                guards=guards,
            )

            if verdict.denied:
                raise PermissionError(
                    f"Chio denied infrastructure resource {fn.__name__}: {verdict.reason}"
                )

            resource = fn(*args, **kwargs)

            # Record receipt after resource is registered with Pulumi
            receipt = chio.record_sync(verdict=verdict)

            # Tag the resource with the receipt ID
            # (if the cloud provider supports tags)
            pulumi.log.info(f"Chio receipt: {receipt.receipt_id} for {fn.__name__}")

            return resource

        return wrapper
    return decorator


def chio_stack(scope: str):
    """Stack-level Chio grant -- scopes all resources within."""

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            chio = ChioClient()

            grant = chio.acquire_grant_sync(scope=scope)
            pulumi.log.info(f"Chio grant acquired: {grant.token[:16]}...")

            try:
                result = fn(*args, **kwargs)
            finally:
                chio.release_grant_sync(grant)
                pulumi.log.info("Chio grant released")

            return result

        return wrapper
    return decorator
```

### 4.3 TypeScript Model

```typescript
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import { arcResource, arcStack } from "@chio-protocol/pulumi";

// Stack-level grant
const stack = arcStack("infra:staging", async () => {

  // Each resource creation is capability-checked
  const db = await arcResource("infra:database:rds", () =>
    new aws.rds.Instance("agent-db", {
      engine: "postgres",
      instanceClass: "db.t3.medium",
      allocatedStorage: 20,
    })
  );

  const cache = await arcResource("infra:cache:redis", () =>
    new aws.elasticache.Cluster("agent-cache", {
      engine: "redis",
      nodeType: "cache.t3.micro",
      numCacheNodes: 1,
    })
  );

  return { dbEndpoint: db.endpoint, cacheEndpoint: cache.cacheNodes };
});
```

## 5. Crossplane Integration (Kubernetes-Native IaC)

Crossplane provisions infrastructure via Kubernetes CRDs. This connects
directly to the existing K8s integration:

### 5.1 Crossplane Composition as Capability Boundary

```yaml
# ChioJobGrant for a Crossplane Composition
apiVersion: chio.world/v1alpha1
kind: ChioJobGrant
metadata:
  name: crossplane-database-grant
  namespace: infrastructure
spec:
  # Match Crossplane Claims
  jobSelector:
    matchLabels:
      crossplane.io/claim-name: agent-database
      chio.world/governed: "true"

  capability:
    scopes:
      - "infra:database:rds"
      - "infra:database:cloudsql"
    guards:
      - "plan-review"
      - "cost-limit"
    budget:
      maxCostUSD: "500.00"

  # Crossplane-specific
  crossplane:
    # Only these Crossplane providers are allowed
    allowedProviders:
      - "provider-aws"
      - "provider-gcp"
    # Only these compositions can be used
    allowedCompositions:
      - "database-standard"
      - "database-ha"
    # Block direct Managed Resources (must use Compositions)
    requireComposition: true
```

### 5.2 Crossplane Admission Webhook Extension

Extend the existing Chio validating webhook to understand Crossplane Claims:

```go
func (v *ChioValidator) handleCrossplaneClaim(
    ctx context.Context,
    claim *unstructured.Unstructured,
) admission.Response {
    // Extract the Composition reference
    compositionRef := claim.GetAnnotations()["crossplane.io/composition-resource-name"]

    // Find matching ChioJobGrant
    grant, err := v.findCrossplaneGrant(ctx, claim)
    if err != nil || grant == nil {
        return admission.Denied("No Chio grant covers this Crossplane Claim")
    }

    // Check if the Composition is allowed
    if !slices.Contains(grant.Spec.Crossplane.AllowedCompositions, compositionRef) {
        return admission.Denied(fmt.Sprintf(
            "Composition %s not in allowed list: %v",
            compositionRef, grant.Spec.Crossplane.AllowedCompositions,
        ))
    }

    // Evaluate against Chio kernel
    verdict, err := v.arcKernel.Evaluate(ctx, EvaluateRequest{
        Tool:  fmt.Sprintf("crossplane:%s", compositionRef),
        Scope: grant.Spec.Capability.Scopes[0],
        Arguments: map[string]interface{}{
            "claim_name":    claim.GetName(),
            "claim_ns":      claim.GetNamespace(),
            "composition":   compositionRef,
            "provider":      extractProvider(compositionRef),
        },
    })

    if err != nil || verdict.Denied {
        return admission.Denied(fmt.Sprintf("Chio denied: %s", verdict.Reason))
    }

    // Mutate: inject receipt ID as annotation
    claim.SetAnnotations(mergeMaps(claim.GetAnnotations(), map[string]string{
        "chio.world/receipt-id": verdict.ReceiptID,
        "chio.world/grant":     grant.Name,
    }))

    return admission.Patched("Chio approved", claim)
}
```

## 6. CDK/CloudFormation Integration

AWS CDK produces CloudFormation templates. Chio can wrap the synthesis
and deployment:

```typescript
import { ChioCdkApp } from "@chio-protocol/cdk";

// Wrap the entire CDK app with Chio governance
const app = new ChioCdkApp({
  arcSidecarUrl: "http://127.0.0.1:9090",
  scope: "infra:cdk:my-app",
});

// Each stack is a capability boundary
const dbStack = new ChioStack(app, "DatabaseStack", {
  arcScope: "infra:database",
  arcGuards: ["cost-limit"],
});

// Synth will evaluate capabilities for all resources in the stack
// Deploy will require infra:apply + plan-review guard
app.synth();  // terraform plan equivalent -- requires infra:plan
// cdk deploy -- requires infra:apply + approval
```

## 7. Cost Governance Guard

Infrastructure provisioning has direct cost implications. A cost governance
guard estimates the monthly cost of a plan and evaluates against budget:

```python
class InfraCostGuard:
    """Guard that estimates infrastructure cost and checks budget."""

    async def evaluate(self, context) -> GuardVerdict:
        resource_scopes = context.arguments.get("resource_scopes", [])
        resource_count = context.arguments.get("resource_count", 0)

        # Estimate monthly cost using Infracost or similar
        estimated_cost = await self.estimate_cost(context.arguments)

        # Check against budget in the capability grant
        budget = context.budget
        if budget and estimated_cost > budget.get("max_monthly_cost_usd", float("inf")):
            return GuardVerdict.deny(
                reason=f"Estimated monthly cost ${estimated_cost:.2f} exceeds "
                       f"budget ${budget['max_monthly_cost_usd']:.2f}",
                metadata={
                    "estimated_cost": estimated_cost,
                    "budget_limit": budget["max_monthly_cost_usd"],
                    "resource_count": resource_count,
                },
            )

        # Warn if cost is >80% of budget
        if budget and estimated_cost > budget.get("max_monthly_cost_usd", float("inf")) * 0.8:
            return GuardVerdict.allow(
                warnings=[
                    f"Estimated cost ${estimated_cost:.2f} is "
                    f"{estimated_cost / budget['max_monthly_cost_usd'] * 100:.0f}% of budget"
                ],
            )

        return GuardVerdict.allow()
```

## 8. Resource Tagging

All agent-provisioned infrastructure should be tagged with Chio metadata
for traceability:

```python
# Standard Chio tags applied to all provisioned resources
CHIO_TAGS = {
    "chio:receipt-id": receipt.receipt_id,
    "chio:agent-id": identity.agent_id,
    "chio:capability-scope": scope,
    "chio:provisioned-by": "chio-protocol",
    "chio:grant-authority": grant.authority,
    "chio:timestamp": receipt.timestamp,
}

# In Terraform
resource "aws_db_instance" "agent_db" {
  # ... configuration ...
  tags = merge(var.common_tags, {
    "chio:receipt-id"       = var.chio_receipt_id
    "chio:agent-id"         = var.chio_agent_id
    "chio:capability-scope" = "infra:database:rds"
    "chio:provisioned-by"   = "chio-protocol"
  })
}

# In Pulumi (automatic via chio_resource decorator)
# Tags are injected by the decorator before resource creation
```

### Tag-Based Discovery

```bash
# Find all infrastructure provisioned by a specific agent
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=chio:agent-id,Values=agent-42

# Find all infrastructure provisioned under a specific capability
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=chio:capability-scope,Values=infra:database:rds

# Correlate cloud resources with Chio receipts
chio receipt list --meta tf_resource_type=aws_db_instance
```

## 9. CI/CD Pipeline Integration

Agent-driven infrastructure changes should flow through CI/CD with Chio
governance at each stage:

```yaml
# GitHub Actions: Chio-governed Terraform pipeline
name: Agent Infrastructure Change

on:
  workflow_dispatch:
    inputs:
      agent_id:
        description: "Agent requesting the change"
        required: true
      capability_token:
        description: "Chio capability token"
        required: true

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Chio Evaluate Plan
        uses: backbay-labs/chio-action@v1
        with:
          tool: terraform:plan
          scope: infra:plan
          token: ${{ inputs.capability_token }}
          sidecar-url: ${{ secrets.CHIO_SIDECAR_URL }}

      - name: Terraform Plan
        run: terraform plan -out=tfplan -json > plan.json

      - name: Chio Plan Review Guard
        uses: backbay-labs/chio-action@v1
        with:
          tool: terraform:plan-review
          scope: infra:plan
          guard: plan-review
          plan-file: plan.json

  apply:
    needs: plan
    runs-on: ubuntu-latest
    environment: production  # Requires GitHub environment approval
    steps:
      - name: Chio Evaluate Apply
        uses: backbay-labs/chio-action@v1
        with:
          tool: terraform:apply
          scope: infra:apply
          token: ${{ inputs.capability_token }}
          guards: plan-review,cost-limit
          sidecar-url: ${{ secrets.CHIO_SIDECAR_URL }}

      - name: Terraform Apply
        run: terraform apply tfplan

      - name: Record Chio Receipt
        uses: backbay-labs/chio-action@v1
        with:
          action: record
          state-file: terraform.tfstate
```

## 10. Package Structure

```
crates/
  chio-iac-core/
    Cargo.toml                # deps: chio-core
    src/
      lib.rs                  # IaC-specific evaluation types
      scope_map.rs            # Resource type -> Chio scope mapping
      plan_review.rs          # Plan analysis utilities
      drift.rs                # Drift-to-receipt correlation

sdks/python/chio-iac/
  pyproject.toml              # deps: chio-sdk-python
  src/chio_iac/
    __init__.py
    terraform/
      __init__.py
      wrapper.py              # ChioTerraform CLI wrapper
      scope_map.py            # Resource type -> scope mapping
      drift.py                # ChioDriftDetector
    pulumi/
      __init__.py
      decorators.py           # chio_resource, chio_stack
    guards/
      plan_review.py          # TerraformPlanReviewGuard
      cost_limit.py           # InfraCostGuard
  tests/
    test_terraform_wrapper.py
    test_pulumi_decorator.py
    test_plan_review.py
    test_drift_detection.py

sdks/typescript/chio-iac/
  package.json                # deps: @chio-protocol/node-http
  src/
    cdk/
      chio-cdk-app.ts          # ChioCdkApp
      chio-stack.ts             # ChioStack with scope
    pulumi/
      decorators.ts            # arcResource, arcStack
    index.ts

sdks/k8s/
  crds/
    arcjobgrant-crd.yaml      # Extended for Crossplane
  controller/
    crossplane_handler.go     # Crossplane Claim validation

deploy/
  github-actions/
    chio-action/
      action.yml              # GitHub Action for Chio evaluation
      index.js

  terraform/
    modules/
      chio-governed/            # Wrapper module for Chio governance
        main.tf
        variables.tf
        outputs.tf
```

## 11. The Agent DevOps Threat Model

Why this integration matters more than it initially appears:

```
Threat: Agent with broad infrastructure access
  |
  +-- Accidental: agent provisions wrong resource type
  |     Mitigation: module-level scope (infra:database:rds only)
  |
  +-- Accidental: agent provisions in wrong region
  |     Mitigation: provider-level trust (us-east-1 only)
  |
  +-- Accidental: agent over-provisions (massive instance)
  |     Mitigation: cost governance guard ($200/mo limit)
  |
  +-- Malicious/compromised: agent creates IAM backdoor
  |     Mitigation: infra:iam:* scope denied by default
  |     Mitigation: plan-review guard catches IAM changes
  |
  +-- Malicious/compromised: agent opens network path
  |     Mitigation: infra:network:* scope denied by default
  |     Mitigation: plan-review guard in production
  |
  +-- Bypass: agent modifies infrastructure outside Chio
        Detection: drift without receipt = security signal
        Response: alert, investigate, remediate
```

## 12. Open Questions

1. **Terraform Cloud / Spacelift / env0.** Managed Terraform platforms run
   plan/apply in their infrastructure. The Chio sidecar needs to be
   available there. Should Chio offer a remote evaluation API for managed
   IaC platforms, or require the sidecar in the execution environment?

2. **State locking.** Terraform uses state locking (DynamoDB, GCS) to
   prevent concurrent modifications. Should Chio's capability grant also
   function as a state lock, preventing concurrent agent modifications?

3. **Import.** `terraform import` brings existing resources under
   management. Should import require a different capability scope than
   provisioning new resources?

4. **Destroy.** `terraform destroy` is the highest-risk operation. Should
   it require a separate `infra:destroy` scope with mandatory human
   approval, even if `infra:apply` is auto-approved?

5. **Workspace isolation.** Terraform workspaces separate state. Should
   each workspace map to a separate Chio capability boundary?

6. **Ansible.** Ansible is configuration management, not IaC in the
   Terraform sense. But agents running Ansible playbooks against
   production servers is the same threat model. Should the IaC
   integration extend to configuration management tools?
