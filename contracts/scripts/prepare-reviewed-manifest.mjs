import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const contractsDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(contractsDir, "..");

function parseArgs(argv) {
  const args = { set: [] };
  for (let index = 2; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      continue;
    }
    const key = token.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      args[key] = true;
      continue;
    }
    if (key === "set") {
      args.set.push(next);
    } else {
      args[key] = next;
    }
    index += 1;
  }
  return args;
}

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

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function repoRelative(filePath) {
  return path.relative(repoRoot, filePath).replaceAll(path.sep, "/");
}

function requireValue(label, value) {
  if (value === undefined || value === null || value === "") {
    throw new Error(`missing required ${label}`);
  }
  return value;
}

function resolveRoleAddress({ args, valuesFile, fieldName, argName, label }) {
  return requireValue(
    label,
    args[argName] ?? valuesFile[fieldName] ?? args["role-address"] ?? valuesFile.role_address
  );
}

function parseSetArgs(values) {
  const parsed = {};
  for (const entry of values) {
    const separator = entry.indexOf("=");
    if (separator <= 0 || separator === entry.length - 1) {
      throw new Error(`invalid --set value ${entry}; expected key=value`);
    }
    const key = entry.slice(0, separator);
    const value = entry.slice(separator + 1);
    parsed[key] = value;
  }
  return parsed;
}

function normalizeManifestId(templateId, override) {
  if (override) {
    return override;
  }
  if (templateId.includes(".template.")) {
    return templateId.replace(".template.", ".reviewed.");
  }
  if (templateId.endsWith(".template")) {
    return `${templateId.slice(0, -".template".length)}.reviewed`;
  }
  return `${templateId}.reviewed`;
}

function replaceExactPlaceholders(value, replacements) {
  if (typeof value === "string") {
    const match = /^<([^>]+)>$/.exec(value);
    if (!match) {
      return value;
    }
    const placeholder = match[1];
    return Object.hasOwn(replacements, placeholder) ? replacements[placeholder] : value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => replaceExactPlaceholders(item, replacements));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, replaceExactPlaceholders(nested, replacements)])
    );
  }
  return value;
}

function collectUnresolvedPlaceholders(value, currentPath = "$", findings = []) {
  if (typeof value === "string") {
    const match = /^<([^>]+)>$/.exec(value);
    if (match) {
      findings.push({ path: currentPath, placeholder: match[1] });
    }
    return findings;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectUnresolvedPlaceholders(item, `${currentPath}[${index}]`, findings));
    return findings;
  }
  if (value && typeof value === "object") {
    Object.entries(value).forEach(([key, nested]) =>
      collectUnresolvedPlaceholders(nested, `${currentPath}.${key}`, findings)
    );
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

function validateAddress(label, value) {
  if (typeof value !== "string" || !ethers.isAddress(value)) {
    throw new Error(`${label} must be a valid EVM address`);
  }
}

function validateBytes32(label, value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be a bytes32 hex string`);
  }
}

function validateManifestAddresses(manifest) {
  validateAddress(
    "operator_configuration.registry_admin_address",
    manifest.operator_configuration?.registry_admin_address
  );
  validateAddress(
    "operator_configuration.price_admin_address",
    manifest.operator_configuration?.price_admin_address
  );
  validateAddress("operator_configuration.operator_address", manifest.operator_configuration?.operator_address);
  validateAddress("operator_configuration.delegate_address", manifest.operator_configuration?.delegate_address);
  validateBytes32("operator_configuration.operator_key_hash", manifest.operator_configuration?.operator_key_hash);
  if (typeof manifest.settlement_token?.address === "string" && manifest.settlement_token.address.startsWith("0x")) {
    validateAddress("settlement_token.address", manifest.settlement_token.address);
  }
  if (
    typeof manifest.oracle_configuration?.sequencer_uptime_feed === "string" &&
    manifest.oracle_configuration.sequencer_uptime_feed.startsWith("0x")
  ) {
    validateAddress(
      "oracle_configuration.sequencer_uptime_feed",
      manifest.oracle_configuration.sequencer_uptime_feed
    );
  }
  for (const [index, feed] of (manifest.oracle_configuration?.feeds ?? []).entries()) {
    if (typeof feed.address === "string" && feed.address.startsWith("0x")) {
      validateAddress(`oracle_configuration.feeds[${index}].address`, feed.address);
    }
  }
  for (const [index, contract] of (manifest.contracts ?? []).entries()) {
    for (const [argIndex, arg] of (contract.constructor_args ?? []).entries()) {
      if (typeof arg === "string" && arg.startsWith("0x")) {
        validateAddress(`contracts[${index}].constructor_args[${argIndex}]`, arg);
      }
    }
  }
}

function buildApprovalScaffold({
  environment,
  manifest,
  manifestPath,
  manifestHash,
  candidateReleaseId,
  deploymentPolicyId,
  create2FactoryMode,
  create2FactoryAddress
}) {
  if (create2FactoryAddress !== null && create2FactoryAddress !== undefined) {
    validateAddress("create2_factory_address", create2FactoryAddress);
  }
  const defaultAllowedEnvironments = new Set(["local-devnet", "runtime-devnet", "base-sepolia"]);
  const requiresExternalAssurance = !defaultAllowedEnvironments.has(environment);

  return {
    approval_id: `chio.web3-deployment-approval.${environment}.v1`,
    candidate_release_id: candidateReleaseId,
    deployment_policy_id: deploymentPolicyId,
    reviewed_manifest_path: repoRelative(manifestPath),
    reviewed_manifest_sha256: manifestHash,
    environment,
    status: "pending-review",
    deployment_scope: "review-required",
    non_testnet_guard: {
      status: requiresExternalAssurance ? "external_assurance_required" : "local_or_testnet_only",
      requires_external_assurance: requiresExternalAssurance,
      note: requiresExternalAssurance
        ? "Non-testnet promotion requires an approved external assurance artifact."
        : "This scaffold is rehearsal or testnet evidence only and does not authorize mainnet custody."
    },
    approvals: [],
    create2: {
      factory_mode: create2FactoryMode,
      factory_address: create2FactoryAddress ?? null,
      salt_namespace: manifest.salt_namespace
    },
    failure_policy: {
      rollback_mode:
        create2FactoryMode === "runner-managed-local"
          ? "evm_snapshot_revert"
          : "manual-replacement-deployment",
      stop_on_error: true,
      require_manual_retry_after_failure: true
    }
  };
}

async function main() {
  const args = parseArgs(process.argv);
  const templatePath = args.template ? path.resolve(repoRoot, args.template) : null;
  const outputPath = args.output ? path.resolve(repoRoot, args.output) : null;
  const approvalOutputPath = args["approval-output"]
    ? path.resolve(repoRoot, args["approval-output"])
    : null;
  const environment = args.environment;

  if (!templatePath || !outputPath || !environment) {
    throw new Error(
      "usage: node contracts/scripts/prepare-reviewed-manifest.mjs --template <path> --output <path> --environment <name> [--approval-output <path>] [--values-file <path>] [--role-address <address>] [--registry-admin-address <address>] [--price-admin-address <address>] [--operator-address <address>] [--delegate-address <address>] --operator-key-hash <bytes32> [--operator-ed-key-label <label>] [--delegate-expiry-seconds <seconds>] [--candidate-release-id <id>] [--deployment-policy-id <id>] [--create2-factory-mode <mode>] [--create2-factory-address <address>] [--manifest-id <id>] [--set <key=value> ...]"
    );
  }

  const valuesFile = args["values-file"]
    ? readJson(path.resolve(repoRoot, args["values-file"]))
    : {};
  const contractRelease = readJson(path.join(contractsDir, "release", "CHIO_WEB3_CONTRACT_RELEASE.json"));
  const deploymentPolicy = readJson(
    path.join(repoRoot, "docs", "standards", "CHIO_WEB3_DEPLOYMENT_POLICY.json")
  );
  const template = readJson(templatePath);
  if (template.deployment_mode !== "deterministic-template") {
    throw new Error("prepare-reviewed-manifest requires a deterministic-template manifest");
  }

  const candidateReleaseId =
    args["candidate-release-id"] ?? valuesFile.candidate_release_id ?? contractRelease.release_id;
  const deploymentPolicyId =
    args["deployment-policy-id"] ?? valuesFile.deployment_policy_id ?? deploymentPolicy.policyId;
  const create2FactoryMode =
    args["create2-factory-mode"] ?? valuesFile.create2_factory_mode ?? "predeployed";
  const create2FactoryAddress =
    args["create2-factory-address"] ?? valuesFile.create2_factory_address ?? null;

  const registryAdminAddress = resolveRoleAddress({
    args,
    valuesFile,
    fieldName: "registry_admin_address",
    argName: "registry-admin-address",
    label: "registry-admin-address"
  });
  const priceAdminAddress = resolveRoleAddress({
    args,
    valuesFile,
    fieldName: "price_admin_address",
    argName: "price-admin-address",
    label: "price-admin-address"
  });
  const operatorAddress = resolveRoleAddress({
    args,
    valuesFile,
    fieldName: "operator_address",
    argName: "operator-address",
    label: "operator-address"
  });
  const delegateAddress = resolveRoleAddress({
    args,
    valuesFile,
    fieldName: "delegate_address",
    argName: "delegate-address",
    label: "delegate-address"
  });
  const operatorEdKeyLabel =
    args["operator-ed-key-label"] ??
    valuesFile.operator_ed_key_label ??
    "chio-operator-ed25519-key";
  const operatorKeyHash = requireValue(
    "operator-key-hash",
    args["operator-key-hash"] ?? valuesFile.operator_key_hash
  );
  validateBytes32("operator-key-hash", operatorKeyHash);
  const delegateExpirySeconds = Number(
    args["delegate-expiry-seconds"] ?? valuesFile.delegate_expiry_seconds ?? 3600
  );
  if (!Number.isFinite(delegateExpirySeconds) || delegateExpirySeconds <= 0) {
    throw new Error("delegate-expiry-seconds must be a positive integer");
  }

  const replacements = {
    ...(valuesFile.placeholders ?? {}),
    ...parseSetArgs(args.set ?? []),
    registry_admin_address: registryAdminAddress,
    price_admin_address: priceAdminAddress,
    operator_address: operatorAddress,
    delegate_address: delegateAddress
  };

  let manifest = structuredClone(template);
  manifest.manifest_id = normalizeManifestId(template.manifest_id, args["manifest-id"]);
  manifest.deployment_mode = "reviewed-manifest";
  manifest.review_context = {
    candidate_release_id: candidateReleaseId,
    deployment_policy_id: deploymentPolicyId
  };
  manifest.operator_configuration = {
    registry_admin_address: registryAdminAddress,
    price_admin_address: priceAdminAddress,
    operator_address: operatorAddress,
    operator_ed_key_label: operatorEdKeyLabel,
    operator_key_hash: operatorKeyHash,
    delegate_address: delegateAddress,
    delegate_expiry_seconds: delegateExpirySeconds
  };
  manifest = replaceExactPlaceholders(manifest, replacements);

  const deferredPlaceholders = allowedDeferredPlaceholders(manifest);
  const unresolved = collectUnresolvedPlaceholders(manifest).filter(
    (finding) => !deferredPlaceholders.has(finding.placeholder)
  );
  if (unresolved.length > 0) {
    const first = unresolved[0];
    throw new Error(`unresolved placeholder ${first.placeholder} at ${first.path}`);
  }

  validateManifestAddresses(manifest);

  writeJson(outputPath, manifest);
  const manifestHash = sha256File(outputPath);

  let approvalPath = null;
  if (approvalOutputPath) {
    const approval = buildApprovalScaffold({
      environment,
      manifest,
      manifestPath: outputPath,
      manifestHash,
      candidateReleaseId,
      deploymentPolicyId,
      create2FactoryMode,
      create2FactoryAddress
    });
    writeJson(approvalOutputPath, approval);
    approvalPath = approvalOutputPath;
  }

  const summary = {
    environment,
    prepared_manifest_path: repoRelative(outputPath),
    prepared_manifest_sha256: manifestHash,
    approval_scaffold_path: approvalPath ? repoRelative(approvalPath) : null
  };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

await main();
