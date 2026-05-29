# Chio Governance for AWS Bedrock and MCP

AI agents are becoming operational software, not only chat surfaces. Once an
agent can call tools, read private data, or trigger a workflow, every tool call
needs a control point that is visible to security teams and practical for
application teams. Chio provides that control point for Bedrock-based agent
systems. The Chio Bedrock Governance listing combines AWS Marketplace
entitlement, least-privilege Bedrock access, and the Model Context Protocol
with signed Chio receipts so customers can prove which agent action was
allowed, denied, metered, or escalated. The listing is intentionally scoped:
AWS Bedrock in `us-east-1`, a single Chio control-plane integration, and an MCP
server entry that exposes governed tool calls rather than bypassing the policy
boundary.

The customer path starts in AWS Marketplace. A buyer subscribes to the Chio
SaaS contract, receives a tenant identifier, and launches the Quick Launch
CloudFormation template from the listing package. The template asks for the
Chio tenant ID, the Chio control-plane endpoint, an external ID, and the seller
principal ARN. It creates a customer-side role that allows the Chio control
plane to invoke Bedrock models and call `sts:GetCallerIdentity`, while the
customer keeps ownership of the AWS account, Bedrock quota, and runtime policy.
This keeps onboarding narrow enough for a security review: no broad admin
role, no multi-cloud sprawl, and no hidden application credentials in the
customer account.

After deployment, agent traffic flows through Chio before it reaches Bedrock or
an MCP tool server. The Chio kernel validates the capability, evaluates policy
and guards, emits a decision receipt, and only then allows the Bedrock Converse
request or MCP tool call to proceed. The architecture diagram in this draft
shows the main trust boundaries: the customer VPC and IAM role, the Chio
control plane, AWS Marketplace entitlement and metering APIs, Bedrock Runtime,
and the MCP registry entry. The critical property is that governance happens at
the boundary, not after the fact. A denied tool call has a customer-visible
error envelope with a stable `urn:chio:error:*` code, and an allowed call has a
signed receipt that can be exported to the customer's audit system.

Marketplace entitlement and metering are tied to receipts rather than raw
model calls. The base subscription covers the normal tenant allocation, and
receipt overage is represented as the `bedrock_receipt_overage` dimension. The
control-plane helper verifies `GetEntitlements` before it meters usage, and the
post-listing smoke test covers the expected customer shape: Quick Launch
template fields, an active entitlement, a first receipt under base quota, an
overage receipt that triggers `MeterUsage`, and a forced failure path that
returns a Chio error URN. That smoke test does not require AWS credentials, so
it can run in CI and in customer security review packets as a deterministic
contract for the listing behavior.

MCP matters because customers increasingly need a standard way to expose tools
to agents without creating one-off integration contracts for every application.
The Chio MCP server entry is submitted under the `dev.chio` namespace at
`https://registry.modelcontextprotocol.io/servers/dev.chio/chio-governed-tools`.
It declares Streamable HTTP transport, OAuth 2.1 with PKCE, protected resource
metadata, and a receipt-emission surface. Chio pins the conformance record to
draft suite hash `17f1f93cc070754cdd290ac13476dcfa13f39855`, with 31 passing
tests and 0 skipped tests at publication confirmation. The registry record is
not a badge by itself; it is a reproducible pointer that tells customers which
MCP contract Chio passed when the Bedrock listing was submitted.

The policy snippet in this package shows the default governance posture. It
allows Bedrock Converse requests only through the marketplace-backed tenant
capability, requires the Bedrock integration role to match the customer attach
policy, and denies unknown MCP tools by default. The Converse request snippet
shows how the governance overlay travels with the request: tenant ID,
capability ID, receipt intent, model identifier, and MCP tool context are
visible to the Chio boundary before Bedrock receives the final request. Teams
can change the policy, but the default package is conservative. Fail-closed
behavior is the product shape, not an optional hardening mode.

The healthcare design-partner pilot is the first customer outcome behind this
distribution package. The pilot audit record reports a 30-day
bounded-operation observation window with zero P0 incidents, zero P1 incidents,
one P2 receipt-export queue delay, 18 minute MTTR for that P2, and no PHI leak
in sampled CEF and OCSF audit exports. The public draft intentionally omits the
partner identity, but it keeps the operational signal: Chio held the bounded
profile under the design-partner deployment, retained redaction status and
policy hash in export records, and closed the audit-handoff freezes consumed by
mobile and HITRUST work. That is the customer proof point for why an AWS
Marketplace path is useful: security teams can buy, deploy, observe, and audit
the agent control plane in their existing AWS operating model.

Operationally, the listing is designed for teams that already have AWS incident
response, change management, and audit review processes. The support SLA in the
listing package gives customers a direct support route, while the Chio audit
records identify the provenance inputs that reviewers normally request:
reproducible build evidence, SBOM and cargo-vet evidence, the single-region
Bedrock scope, and the design-partner operational record. That matters because agent governance projects often fail when
the application demo looks strong but the operational evidence is scattered
across private notes. Chio keeps the evidence close to the deployable package.
The customer can inspect the CloudFormation template, the IAM policy, the
MCP registry entry, and the smoke test before a production cutover, then compare
those artifacts with the receipts and audit exports generated during operation.

The threat model is also intentionally limited. Chio does not claim to solve
every multi-cloud, public marketplace, or permissionless transparency problem
inside this Bedrock listing. The listing covers one AWS region, AWS Marketplace
entitlement, Bedrock Runtime calls, and the governed MCP server. Within that
scope, the important security boundary is crisp: the agent is untrusted, the
Chio kernel mediates capability use, guards and policy run before the request
crosses the tool boundary, and the receipt log records the signed decision. If
an entitlement lookup fails, if the marketplace subscription is inactive, if an
MCP tool is outside policy, or if the request cannot produce a receipt, the
expected result is denial. Customers can extend this pattern later, but the
first marketplace package is useful precisely because it avoids pretending that
every future integration is already production evidence.

For AWS field teams, the joint story is concrete. Bedrock provides the managed
model runtime and the customer procurement path through AWS Marketplace. MCP
provides a recognizable tool-server contract for agent applications. Chio adds
the missing governance layer between those surfaces: capability verification,
policy evaluation, guard execution, receipt signing, and metered commercial
events that line up with the Marketplace subscription. The result is a
repeatable reference motion for regulated agent deployments. A customer can
start with a minimal Quick Launch, test a governed Bedrock Converse call, verify
the MCP registry record, inspect the audit export shape, and then decide whether
the same receipt-backed boundary should cover more internal tools. That is the
right adoption path for agent systems that need to move from experimentation to
controlled operation.

The AI-lab evaluation adds a second distribution signal. The evaluation bundle
and conformance memo explain how external reviewers can consume Chio evidence
without trusting a private dashboard. The Bedrock
listing cross-links that memo because marketplace buyers often ask two
questions at once: whether the integration is easy to deploy, and whether the
governance evidence is portable enough for a third party to inspect. Chio's
answer is to keep receipts, conformance pins, and customer audit evidence in
versioned files and signed artifacts. The Marketplace page is the procurement
door, while the MCP registry and evaluation bundle are the technical proof
surfaces.

This draft is submitted for AWS Solutions Architect review and APN technical
content review before public posting. Publication may follow later, because
co-authored AWS content often has an editorial queue after the technical review
is complete. The closure condition for this milestone is therefore the submitted
draft plus SA review, not a live blog URL. The live listing URL, MCP registry
entry, conformance pass count, support SLA, Standard Contract for AWS
Marketplace posture, Quick Launch template, and post-listing smoke test are the
artifacts customers can inspect now. Future follow-up work can cite the third-party audit report after it
publishes, but this draft does not depend on that later vendor calendar.

The next customer step is deliberately simple. Subscribe, launch the template,
attach the generated role to the tenant record, run the smoke path, and export
the first receipt set to the existing security review workflow. If the customer
needs a stricter rule, they edit the Chio policy YAML and rerun the same smoke
path. If the customer needs a new MCP tool, they add it to the governed server
and keep the registry record current. That keeps growth incremental and
auditable. The distribution goal is not to hide complexity behind a product
claim; it is to give Bedrock customers a repeatable control plane for agent
tool access, with enough evidence to let procurement, platform, and security
teams review the same artifacts.
