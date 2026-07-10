import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const contractsDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(contractsDir, "..");

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function repoRelative(filePath) {
  return path.relative(repoRoot, filePath).replaceAll(path.sep, "/");
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function runNode(args) {
  const result = spawnSync("node", args, {
    cwd: repoRoot,
    encoding: "utf8"
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result;
}

function collectUnresolvedPlaceholders(value, findings = []) {
  if (typeof value === "string") {
    const match = /^<([^>]+)>$/.exec(value);
    if (match) {
      findings.push(match[1]);
    }
    return findings;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => collectUnresolvedPlaceholders(item, findings));
    return findings;
  }
  if (value && typeof value === "object") {
    Object.values(value).forEach((nested) => collectUnresolvedPlaceholders(nested, findings));
  }
  return findings;
}

function allowedDeferredPlaceholders(manifest) {
  const allowed = new Set();
  for (const contract of manifest.contracts ?? []) {
    const placeholderKey = contract.contract_id.replace("chio.", "").replaceAll("-", "_");
    allowed.add(placeholderKey);
    allowed.add(`${placeholderKey}_address`);
  }
  return allowed;
}

const DUMMY_VALUES = {
  registry_admin_address: "0x1111111111111111111111111111111111111111",
  price_admin_address: "0x2222222222222222222222222222222222222222",
  operator_address: "0x3333333333333333333333333333333333333333",
  delegate_address: "0x4444444444444444444444444444444444444444",
  operator_ed_key_label: "chio-operator-ed25519-key",
  delegate_expiry_seconds: 7200,
  create2_factory_address: "0x5555555555555555555555555555555555555555"
};

const TEMPLATE_SPECS = [
  {
    template: "contracts/deployments/base-mainnet.template.json",
    environment: "base-mainnet",
    placeholders: {}
  },
  {
    template: "contracts/deployments/base-sepolia.template.json",
    environment: "base-sepolia",
    placeholders: {
      base_sepolia_sequencer_uptime_feed: "0x6000000000000000000000000000000000000001",
      base_sepolia_eth_usd_feed: "0x6000000000000000000000000000000000000002",
      base_sepolia_btc_usd_feed: "0x6000000000000000000000000000000000000003",
      base_sepolia_usdc_usd_feed: "0x6000000000000000000000000000000000000004",
      base_sepolia_link_usd_feed: "0x6000000000000000000000000000000000000005"
    },
    singleRoleAddress: true
  },
  {
    template: "contracts/deployments/arbitrum-one.template.json",
    environment: "arbitrum-one",
    placeholders: {
      arbitrum_sequencer_uptime_feed: "0x7000000000000000000000000000000000000001"
    }
  }
];

async function main() {
  const outputDirIndex = process.argv.indexOf("--output-dir");
  const outputRoot =
    outputDirIndex >= 0 && process.argv[outputDirIndex + 1]
      ? path.resolve(repoRoot, process.argv[outputDirIndex + 1])
      : path.join(repoRoot, "target", "web3-promotion-qualification", "review-prep");
  ensureDir(outputRoot);

  const results = [];
  for (const spec of TEMPLATE_SPECS) {
    const baseName = path.basename(spec.template, ".template.json");
    const valuesPath = path.join(outputRoot, `${baseName}.review-inputs.json`);
    const manifestPath = path.join(outputRoot, `${baseName}.reviewed.json`);
    const approvalPath = path.join(outputRoot, `${baseName}.approval.template.json`);

    const roleValues = spec.singleRoleAddress
      ? {
          role_address: DUMMY_VALUES.registry_admin_address,
          operator_ed_key_label: DUMMY_VALUES.operator_ed_key_label,
          delegate_expiry_seconds: DUMMY_VALUES.delegate_expiry_seconds,
          create2_factory_address: DUMMY_VALUES.create2_factory_address
        }
      : DUMMY_VALUES;

    writeJson(valuesPath, {
      ...roleValues,
      placeholders: spec.placeholders
    });

    runNode([
      path.join("contracts", "scripts", "prepare-reviewed-manifest.mjs"),
      "--template",
      spec.template,
      "--values-file",
      repoRelative(valuesPath),
      "--environment",
      spec.environment,
      "--output",
      repoRelative(manifestPath),
      "--approval-output",
      repoRelative(approvalPath)
    ]);

    const manifest = readJson(manifestPath);
    const approval = readJson(approvalPath);

    assert.equal(manifest.deployment_mode, "reviewed-manifest");
    assert.equal(manifest.review_context.candidate_release_id, "chio.web3-contract-package.release.v0.1.0");
    assert.equal(manifest.review_context.deployment_policy_id, "chio.web3-deployment-promotion.v1");
    assert.equal(approval.status, "pending-review");
    assert.equal(approval.deployment_scope, "review-required");
    assert.ok(approval.non_testnet_guard);
    assert.deepEqual(approval.approvals, []);
    assert.equal(approval.reviewed_manifest_path, repoRelative(manifestPath));
    assert.equal(approval.reviewed_manifest_sha256, sha256File(manifestPath));
    assert.equal(approval.environment, spec.environment);
    assert.equal(approval.create2.factory_mode, "predeployed");
    assert.equal(approval.create2.factory_address, DUMMY_VALUES.create2_factory_address);
    if (spec.singleRoleAddress) {
      assert.equal(manifest.operator_configuration.registry_admin_address, DUMMY_VALUES.registry_admin_address);
      assert.equal(manifest.operator_configuration.price_admin_address, DUMMY_VALUES.registry_admin_address);
      assert.equal(manifest.operator_configuration.operator_address, DUMMY_VALUES.registry_admin_address);
      assert.equal(manifest.operator_configuration.delegate_address, DUMMY_VALUES.registry_admin_address);
    }
    const deferredPlaceholders = allowedDeferredPlaceholders(manifest);
    const unexpectedPlaceholders = collectUnresolvedPlaceholders(manifest).filter(
      (placeholder) => !deferredPlaceholders.has(placeholder)
    );
    assert.deepEqual(
      unexpectedPlaceholders,
      [],
      `${spec.template} left operator-supplied placeholders unresolved`
    );

    results.push({
      template: spec.template,
      environment: spec.environment,
      reviewed_manifest_path: repoRelative(manifestPath),
      approval_scaffold_path: repoRelative(approvalPath),
      review_inputs_path: repoRelative(valuesPath)
    });
  }

  writeJson(path.join(outputRoot, "qualification.json"), {
    report_id: "chio.web3-review-prep-qualification.v1",
    generated_at: new Date().toISOString(),
    deployment_status: "review-required",
    checks: [
      {
        id: "review_prep.templates_prepare_cleanly",
        outcome: "pass",
        note: "Every shipped public-chain template produced a reviewed manifest and pending-review approval scaffold with only deployment-internal contract-address placeholders remaining. Non-testnet scaffolds require external assurance."
      }
    ],
    outputs: results
  });
}

await main();
