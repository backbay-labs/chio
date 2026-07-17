import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";
import ganache from "ganache";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const contractsDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(contractsDir, "..");
const artifactsDir = path.join(contractsDir, "artifacts");

const LOCAL_PORT = Number(process.env.CHIO_PROMOTION_DEVNET_PORT ?? "8551");
const LOCAL_RPC_URL = `http://127.0.0.1:${LOCAL_PORT}`;
const LOCAL_CHAIN_ID = 31337;
const DEFAULT_ALLOWED_CHAIN_IDS = new Set([
  "31337",
  "1337",
  "84532",
  "11155111",
  "421614",
  "11155420",
  "80002"
]);
const USDC_UNITS = 10n ** 6n;
const DEFAULT_EXPIRY_SECONDS = 3600;
const ERC8021_MARKER = "80218021802180218021802180218021";
const REQUIRED_ARTIFACT_DIGEST_PATHS = [
  "docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json",
  "contracts/artifacts/ChioRootRegistry.json",
  "contracts/artifacts/ChioEscrow.json",
  "contracts/artifacts/ChioBondVault.json",
  "contracts/artifacts/ChioIdentityRegistry.json",
  "contracts/artifacts/ChioPriceResolver.json"
];
const ARTIFACT_DIGEST_EXCLUDED_PATHS = new Set([
  "target/web3-external-assurance/artifact-digest-gate.json",
  "target/web3-external-assurance/security-owner-assurance-unlock.json",
  "target/release-qualification/web3-runtime/artifact-manifest.json"
]);
const OFFICIAL_CONTRACT_ARTIFACTS = {
  "chio.root-registry": "contracts/artifacts/ChioRootRegistry.json",
  "chio.escrow": "contracts/artifacts/ChioEscrow.json",
  "chio.bond-vault": "contracts/artifacts/ChioBondVault.json",
  "chio.identity-registry": "contracts/artifacts/ChioIdentityRegistry.json",
  "chio.price-resolver": "contracts/artifacts/ChioPriceResolver.json"
};
const PRE_DEPLOYMENT_ASSURANCE_COMPONENTS = [
  "external_audit",
  "testnet_soak",
  "artifact_digest_gate",
  "minimum_bar_checklist"
];
const DEFAULT_ASSURANCE_COMPONENT_PATHS = {
  external_audit: "target/web3-external-assurance/external-audit-report.json",
  testnet_soak: "target/web3-external-assurance/testnet-soak-report.json",
  artifact_digest_gate: "target/web3-external-assurance/artifact-digest-gate.json",
  minimum_bar_checklist: "target/web3-external-assurance/minimum-bar-checklist.json",
  runtime_codehash_gate: "target/web3-external-assurance/deployed-runtime-codehash-gate.json"
};
const OPERATOR_BINDING_TYPES = {
  ChioOperatorBinding: [
    { name: "operatorAddress", type: "address" },
    { name: "edKeyHash", type: "bytes32" },
    { name: "settlementKey", type: "address" }
  ]
};

const ACCOUNT_CONFIG = [
  { name: "admin", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000001" },
  { name: "operator", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000002" },
  { name: "delegate", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000003" },
  { name: "beneficiary", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000004" },
  { name: "depositor", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000005" },
  { name: "principal", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000006" },
  { name: "outsider", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000007" }
];

function parseArgs(argv) {
  const args = {};
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
    args[key] = next;
    index += 1;
  }
  return args;
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function readJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function writeJson(jsonPath, value) {
  ensureDir(path.dirname(jsonPath));
  fs.writeFileSync(jsonPath, `${JSON.stringify(normalize(value), null, 2)}\n`);
}

function normalize(value) {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalize(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, normalize(nested)]));
  }
  return value;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256CanonicalObject(value) {
  return crypto.createHash("sha256").update(canonicalJson(normalize(value))).digest("hex");
}

function sha256Object(value) {
  return crypto.createHash("sha256").update(JSON.stringify(normalize(value))).digest("hex");
}

function repoRelative(filePath) {
  return path.relative(repoRoot, filePath).replaceAll(path.sep, "/");
}

function artifactPath(ref) {
  return path.isAbsolute(ref) ? ref : path.join(repoRoot, ref);
}

function parseEip155ChainId(chainId) {
  if (typeof chainId !== "string") {
    throw new Error("manifest chain_id must be an eip155 chain id");
  }
  const match = /^eip155:(\d+)$/.exec(chainId);
  if (!match) {
    throw new Error(`manifest chain_id ${chainId} must use eip155:<number>`);
  }
  return match[1];
}

function requireAssuranceCheck(label, value) {
  if (!value || value.status !== "pass") {
    throw new Error(`external assurance artifact missing passing ${label}`);
  }
}

function requireBytes32(label, value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be a bytes32 hex string`);
  }
}

function requireAddress(label, value) {
  if (typeof value !== "string" || !ethers.isAddress(value)) {
    throw new Error(`${label} must be an EVM address`);
  }
}

function requireManifestHashScope(label, value, manifestHash) {
  const scopedHash = value?.reviewed_manifest_sha256 ?? value?.manifest_sha256;
  if (scopedHash !== manifestHash) {
    throw new Error(`${label} must bind reviewed manifest sha256`);
  }
}

function normalizeRepoPath(value) {
  return typeof value === "string" ? value.replace(/^\.\//, "") : null;
}

function requiredArtifactDigestPaths(deploymentPolicy) {
  const paths = new Set(REQUIRED_ARTIFACT_DIGEST_PATHS);
  for (const key of [
    "requiredEvidence",
    "stagedBundleRequiredEvidence",
    "stagedBundleCutoverRequiredEvidence",
    "externalAssuranceRequiredEvidence"
  ]) {
    for (const rawPath of deploymentPolicy?.[key] ?? []) {
      const normalizedPath = normalizeRepoPath(rawPath);
      if (
        !normalizedPath ||
        ARTIFACT_DIGEST_EXCLUDED_PATHS.has(normalizedPath) ||
        normalizedPath.startsWith("target/web3-external-assurance/")
      ) {
        continue;
      }
      paths.add(normalizedPath);
    }
  }
  return [...paths].sort();
}

function requireDigest(label, value) {
  const normalized = typeof value === "string" ? value.replace(/^sha256:/i, "") : null;
  if (!normalized || !/^[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new Error(`${label} must be a SHA-256 digest`);
  }
  return normalized.toLowerCase();
}

function resolveRepoBoundPath(label, basePath, rawPath) {
  if (typeof rawPath !== "string" || rawPath.trim() === "") {
    throw new Error(`${label} must declare a path`);
  }
  const candidate = path.isAbsolute(rawPath)
    ? rawPath
    : rawPath.startsWith(".") || rawPath.startsWith("target/") || rawPath.startsWith("contracts/") || rawPath.startsWith("docs/")
      ? path.resolve(repoRoot, rawPath)
      : path.resolve(path.dirname(basePath), rawPath);
  const relative = path.relative(repoRoot, candidate);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`${label} must stay inside the repository`);
  }
  return candidate;
}

function assuranceComponentRef(unlock, name) {
  const components = unlock.components ?? unlock.component_digests ?? {};
  const directRef = components[name] ?? unlock[`${name}_component`] ?? unlock[`${name}_ref`];
  if (typeof directRef === "string") {
    return {
      path: DEFAULT_ASSURANCE_COMPONENT_PATHS[name],
      sha256: directRef
    };
  }
  if (directRef && typeof directRef === "object" && !Array.isArray(directRef)) {
    return {
      path: directRef.path ?? directRef.report_path ?? directRef.file ?? DEFAULT_ASSURANCE_COMPONENT_PATHS[name],
      sha256: directRef.sha256 ?? directRef.digest ?? directRef.report_sha256
    };
  }
  return null;
}

function loadDetachedAssuranceComponent(unlock, unlockPath, name) {
  const ref = assuranceComponentRef(unlock, name);
  if (!ref) {
    throw new Error(`external assurance artifact must bind detached ${name} component`);
  }
  const componentPath = resolveRepoBoundPath(`external assurance ${name}`, unlockPath, ref.path);
  const expectedDigest = requireDigest(`external assurance ${name} component digest`, ref.sha256);
  const actualDigest = sha256File(componentPath);
  if (actualDigest !== expectedDigest) {
    throw new Error(`external assurance ${name} component digest does not match ${repoRelative(componentPath)}`);
  }
  return {
    value: readJson(componentPath),
    path: componentPath,
    sha256: actualDigest
  };
}

function expectedSecurityOwnerAddress(approval) {
  const declaredValues = [
    approval.security_owner_address,
    approval.securityOwnerAddress,
    approval.security_owner?.address,
    approval.securityOwner?.address
  ].filter((value) => value !== undefined && value !== null && value !== "");
  for (const value of declaredValues) {
    if (typeof value !== "string" || !ethers.isAddress(value)) {
      throw new Error("non-testnet approval security-owner address is invalid");
    }
  }
  const declaredAddress = declaredValues.length > 0 ? ethers.getAddress(declaredValues[0]) : null;
  for (const value of declaredValues.slice(1)) {
    if (ethers.getAddress(value) !== declaredAddress) {
      throw new Error("non-testnet approval has conflicting security-owner addresses");
    }
  }

  const approvedAddresses = [];
  for (const entry of approval.approvals ?? []) {
    const role = String(entry.role ?? "").toLowerCase().replaceAll("_", "-");
    if (role === "security-owner" && entry.status === "approved" && entry.approved_at) {
      for (const value of [entry.address, entry.evm_address, entry.signer_address]) {
        if (typeof value === "string" && ethers.isAddress(value)) {
          approvedAddresses.push(ethers.getAddress(value));
        }
      }
    }
  }
  const uniqueApprovedAddresses = [...new Set(approvedAddresses)];
  if (uniqueApprovedAddresses.length > 1) {
    throw new Error("non-testnet approval has conflicting approved security-owner addresses");
  }
  const approvedAddress = uniqueApprovedAddresses[0] ?? null;
  if (declaredAddress && approvedAddress && declaredAddress !== approvedAddress) {
    throw new Error("non-testnet approval security-owner address does not match approved role entry");
  }
  if (approvedAddress) {
    return approvedAddress;
  }
  throw new Error("non-testnet approval must declare an approved security-owner EVM address");
}

function signaturelessSecurityOwnerApproval(unlock) {
  const approval = structuredClone(unlock.security_owner_approval ?? {});
  delete approval.signature;
  delete approval.signature_hex;
  delete approval.approval_signature;
  delete approval.attestation_signature;
  return approval;
}

function assuranceUnlockSignaturePayload(unlock) {
  const copy = structuredClone(unlock);
  copy.security_owner_approval = signaturelessSecurityOwnerApproval(unlock);
  delete copy.security_owner_signature;
  delete copy.signature;
  delete copy.signature_hex;
  return `chio.web3.assurance-unlock.v1:${sha256CanonicalObject(copy)}`;
}

function validateSecurityOwnerSignature(unlock, approval) {
  const securityOwner = unlock.security_owner_approval ?? {};
  if (securityOwner.status !== "approved" || !securityOwner.actor || !securityOwner.approved_at) {
    throw new Error("external assurance artifact requires security_owner_approval with status approved, actor, and approved_at");
  }
  const signature =
    securityOwner.signature ??
    securityOwner.signature_hex ??
    securityOwner.approval_signature ??
    securityOwner.attestation_signature ??
    unlock.security_owner_signature;
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    throw new Error("external assurance artifact requires a security-owner ECDSA signature");
  }
  const expectedAddress = expectedSecurityOwnerAddress(approval);
  const recoveredAddress = ethers.verifyMessage(assuranceUnlockSignaturePayload(unlock), signature);
  if (ethers.getAddress(recoveredAddress) !== expectedAddress) {
    throw new Error("external assurance artifact security-owner signature does not match approval");
  }
}

function fieldValue(value, names) {
  if (!value || typeof value !== "object") {
    return null;
  }
  for (const name of names) {
    if (value[name] !== undefined && value[name] !== null && value[name] !== "") {
      return value[name];
    }
  }
  return null;
}

function requireFreshExternalEvidence(label, value) {
  const reportDigest = fieldValue(value, ["report_sha256", "report_digest", "sha256", "digest"]);
  requireDigest(`${label} report digest`, reportDigest);
  const candidateRevision = fieldValue(value, ["candidate_revision", "candidate_sha", "workflow_sha", "git_sha"]);
  if (typeof candidateRevision !== "string" || candidateRevision.trim() === "") {
    throw new Error(`${label} must bind a candidate revision`);
  }
  const issuedAt = fieldValue(value, ["issued_at", "generated_at", "observed_at", "completed_at", "approved_at"]);
  if (typeof issuedAt !== "string" || issuedAt.trim() === "") {
    throw new Error(`${label} must carry report freshness timestamp`);
  }
  const signer = fieldValue(value, ["signed_by", "approver", "approved_by", "actor"]);
  const signature = fieldValue(value, ["signature", "signature_hex", "approval_signature", "attestation_signature"]);
  if (!signer || !signature) {
    throw new Error(`${label} must carry signer plus signature`);
  }
}

function validateExternalAssuranceComponent(label, value, { manifest, manifestHash, contractRelease, deploymentPolicy }) {
  requireAssuranceCheck(label, value);
  requireManifestHashScope(`external assurance ${label}`, value, manifestHash);
  if (value.chain_id !== manifest.chain_id) {
    throw new Error(`external assurance ${label} chain_id does not match the manifest`);
  }
  if (value.candidate_release_id !== contractRelease.release_id) {
    throw new Error(`external assurance ${label} candidate_release_id does not match the contract release`);
  }
  if (value.deployment_policy_id !== deploymentPolicy.policyId) {
    throw new Error(`external assurance ${label} deployment_policy_id does not match the deployment policy`);
  }
  requireFreshExternalEvidence(`external assurance ${label}`, value);
}

function validateArtifactDigestGate(gate, contractPackage, manifestHash, deploymentPolicy) {
  requireManifestHashScope("external assurance artifact_digest_gate", gate, manifestHash);
  const packageId = gate.contract_package_id ?? gate.package_id ?? gate.packageId;
  if (packageId !== contractPackage.package_id) {
    throw new Error("external assurance artifact_digest_gate contract package id does not match package");
  }
  if (!gate.digests || typeof gate.digests !== "object" || Array.isArray(gate.digests)) {
    throw new Error("external assurance artifact_digest_gate requires structured digests");
  }
  for (const digestPath of requiredArtifactDigestPaths(deploymentPolicy)) {
    const expected = sha256File(path.join(repoRoot, digestPath)).toLowerCase();
    const actual = requireDigest(`external assurance artifact_digest_gate ${digestPath}`, gate.digests[digestPath]);
    if (actual !== expected) {
      throw new Error(`external assurance artifact_digest_gate digest for ${digestPath} does not match repository artifact`);
    }
  }
}

async function validateRuntimeCodehashGate(gate, contractPackage, manifest, manifestHash, provider, plannedContractAddresses) {
  requireManifestHashScope("external assurance runtime_codehash_gate", gate, manifestHash);
  if (gate.chain_id !== manifest.chain_id) {
    throw new Error("external assurance runtime_codehash_gate chain_id does not match the manifest");
  }
  requireBytes32("external assurance runtime_codehash_gate observed_block_hash", gate.observed_block_hash);
  if (!Number.isSafeInteger(gate.observed_block_number) || gate.observed_block_number < 0) {
    throw new Error("external assurance runtime_codehash_gate observed_block_number must be a non-negative safe integer");
  }
  const records = gate.deployed_runtime_codehashes ?? gate.runtime_codehashes;
  if (!records || typeof records !== "object" || Array.isArray(records)) {
    throw new Error("external assurance runtime_codehash_gate requires deployed_runtime_codehashes");
  }
  const addressSources = [
    gate.deployed_contract_addresses,
    gate.contract_addresses,
    gate.contracts
  ].filter((value) => value && typeof value === "object" && !Array.isArray(value));

  for (const contract of contractPackage.contracts ?? []) {
    const contractId = contract.contract_id;
    const kind = contract.kind;
    const expectedCodehash = contract.deployed_runtime_codehash;
    const artifactRef = OFFICIAL_CONTRACT_ARTIFACTS[contractId];
    if (!contractId || !kind || !expectedCodehash) {
      throw new Error("contract package runtime entry is incomplete");
    }
    if (!artifactRef) {
      throw new Error(`external assurance runtime_codehash_gate has no official artifact mapping for ${contractId}`);
    }
    const record = records[contractId] ?? records[kind];
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw new Error(`external assurance runtime_codehash_gate missing record for ${contractId}`);
    }
    requireBytes32(`${contractId} actual_runtime_codehash`, record.actual_runtime_codehash);
    requireBytes32(
      `${contractId} immutable_normalized_runtime_codehash`,
      record.immutable_normalized_runtime_codehash
    );
    requireBytes32(`${contractId} package_runtime_codehash`, record.package_runtime_codehash);
    requireBytes32(`${contractId} observed_block_hash`, record.observed_block_hash);
    if (!Number.isSafeInteger(record.observed_block_number) || record.observed_block_number < 0) {
      throw new Error(`${contractId} observed_block_number must be a non-negative safe integer`);
    }
    if (record.observed_block_hash.toLowerCase() !== gate.observed_block_hash.toLowerCase()) {
      throw new Error(`${contractId} observed_block_hash does not match runtime_codehash_gate`);
    }
    if (record.observed_block_number !== gate.observed_block_number) {
      throw new Error(`${contractId} observed_block_number does not match runtime_codehash_gate`);
    }
    if (record.observation_source !== "eth_getCode") {
      throw new Error(`${contractId} observation_source must be eth_getCode`);
    }
    if (record.immutable_normalized_runtime_codehash.toLowerCase() !== expectedCodehash.toLowerCase()) {
      throw new Error(`${contractId} immutable_normalized_runtime_codehash does not match package`);
    }
    if (record.package_runtime_codehash.toLowerCase() !== expectedCodehash.toLowerCase()) {
      throw new Error(`${contractId} package_runtime_codehash does not match package`);
    }

    let address = null;
    for (const source of addressSources) {
      address = source[contractId] ?? source[kind] ?? null;
      if (address) {
        break;
      }
    }
    requireAddress(`${contractId} deployed address`, address);
    const plannedAddress = plannedContractAddresses?.[contractId] ?? plannedContractAddresses?.[kind] ?? null;
    requireAddress(`${contractId} planned address`, plannedAddress);
    if (address.toLowerCase() !== plannedAddress.toLowerCase()) {
      throw new Error(`${contractId} deployed address does not match reviewed CREATE2 plan`);
    }

    const observedBlock = await provider.getBlock(record.observed_block_number);
    if (!observedBlock?.hash) {
      throw new Error(`${contractId} observed block ${record.observed_block_number} is unavailable`);
    }
    if (observedBlock.hash.toLowerCase() !== record.observed_block_hash.toLowerCase()) {
      throw new Error(`${contractId} observed_block_hash does not match live chain`);
    }
    const deployedCode = await provider.getCode(address, record.observed_block_number);
    if (!deployedCode || deployedCode === "0x") {
      throw new Error(`${contractId} has no deployed bytecode at ${address} for observed block`);
    }
    const liveActualRuntimeCodehash = ethers.keccak256(deployedCode);
    if (liveActualRuntimeCodehash.toLowerCase() !== record.actual_runtime_codehash.toLowerCase()) {
      throw new Error(`${contractId} actual_runtime_codehash does not match live eth_getCode result`);
    }
    const artifact = readArtifact(artifactRef);
    const liveNormalizedRuntimeCodehash = ethers.keccak256(
      normalizeDeployedCodeForImmutableReferences(contractId, artifact, deployedCode)
    );
    if (liveNormalizedRuntimeCodehash.toLowerCase() !== expectedCodehash.toLowerCase()) {
      throw new Error(`${contractId} live immutable-normalized runtime codehash does not match package`);
    }
  }
}

function validateRunnerRuntimeCodehashes(deployedRuntimeCodehashes, contractPackage) {
  if (!deployedRuntimeCodehashes || typeof deployedRuntimeCodehashes !== "object") {
    throw new Error("deployment runtime codehash records are missing");
  }
  for (const contract of contractPackage.contracts ?? []) {
    const record = deployedRuntimeCodehashes[contract.contract_id] ?? deployedRuntimeCodehashes[contract.kind];
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw new Error(`deployment runtime codehash record is missing for ${contract.contract_id}`);
    }
    requireBytes32(`${contract.contract_id} actual_runtime_codehash`, record.actual_runtime_codehash);
    requireBytes32(
      `${contract.contract_id} immutable_normalized_runtime_codehash`,
      record.immutable_normalized_runtime_codehash
    );
    requireBytes32(`${contract.contract_id} package_runtime_codehash`, record.package_runtime_codehash);
    requireBytes32(`${contract.contract_id} observed_block_hash`, record.observed_block_hash);
    if (!Number.isSafeInteger(record.observed_block_number) || record.observed_block_number < 0) {
      throw new Error(`${contract.contract_id} observed_block_number must be a non-negative safe integer`);
    }
    if (record.observation_source !== "eth_getCode") {
      throw new Error(`${contract.contract_id} post-deployment runtime observation must use eth_getCode`);
    }
    if (record.immutable_normalized_runtime_codehash.toLowerCase() !== contract.deployed_runtime_codehash.toLowerCase()) {
      throw new Error(`${contract.contract_id} post-deployment runtime codehash does not match package`);
    }
    if (record.package_runtime_codehash.toLowerCase() !== contract.deployed_runtime_codehash.toLowerCase()) {
      throw new Error(`${contract.contract_id} post-deployment package runtime codehash does not match package`);
    }
  }
}

function validateAssuranceUnlockHeader({
  unlock,
  manifest,
  manifestHash,
  approval,
  contractRelease,
  deploymentPolicy
}) {
  if (!unlock || typeof unlock !== "object") {
    throw new Error("external assurance artifact must be a JSON object");
  }
  requireManifestHashScope("external assurance artifact", unlock, manifestHash);
  if (unlock.status !== "approved") {
    throw new Error("external assurance artifact status must be approved");
  }
  if (unlock.gate !== "EXTERNAL_ASSURANCE") {
    throw new Error("external assurance artifact gate must be EXTERNAL_ASSURANCE");
  }
  if (unlock.chain_id !== manifest.chain_id) {
    throw new Error("external assurance artifact chain_id does not match the manifest");
  }
  if (unlock.candidate_release_id !== contractRelease.release_id) {
    throw new Error("external assurance artifact candidate_release_id does not match the contract release");
  }
  if (unlock.deployment_policy_id !== deploymentPolicy.policyId) {
    throw new Error("external assurance artifact deployment_policy_id does not match the deployment policy");
  }
  if (unlock.approval_id !== approval.approval_id) {
    throw new Error("external assurance artifact approval_id does not match the promotion approval");
  }
  validateSecurityOwnerSignature(unlock, approval);
  if (!Array.isArray(unlock.unresolved_critical_high_findings) || unlock.unresolved_critical_high_findings.length !== 0) {
    throw new Error("external assurance artifact must declare zero unresolved critical/high findings");
  }
}

async function validateAssuranceUnlock({
  unlock,
  unlockPath,
  manifest,
  manifestHash,
  approval,
  contractRelease,
  deploymentPolicy,
  contractPackage
}) {
  validateAssuranceUnlockHeader({
    unlock,
    manifest,
    manifestHash,
    approval,
    contractRelease,
    deploymentPolicy
  });

  const components = Object.fromEntries(
    PRE_DEPLOYMENT_ASSURANCE_COMPONENTS.map((name) => [name, loadDetachedAssuranceComponent(unlock, unlockPath, name)])
  );
  for (const name of ["external_audit", "testnet_soak", "minimum_bar_checklist"]) {
    validateExternalAssuranceComponent(name, components[name].value, {
      manifest,
      manifestHash,
      contractRelease,
      deploymentPolicy
    });
  }

  requireAssuranceCheck("artifact_digest_gate", components.artifact_digest_gate.value);
  validateArtifactDigestGate(components.artifact_digest_gate.value, contractPackage, manifestHash, deploymentPolicy);

  return {
    unlock,
    unlockPath,
    components,
    check: {
      id: "deployment.external_assurance_predeployment",
      outcome: "pass",
      note: `External assurance artifact ${repoRelative(unlockPath)} authorizes pre-deployment non-testnet rollout for ${manifest.chain_id}.`
    }
  };
}

async function enforceNonTestnetPreDeploymentAssurance({
  args,
  manifest,
  manifestHash,
  approval,
  contractRelease,
  deploymentPolicy,
  contractPackage
}) {
  const chainId = parseEip155ChainId(manifest.chain_id);
  if (DEFAULT_ALLOWED_CHAIN_IDS.has(chainId)) {
    return null;
  }

  const unlockPathArg = args["assurance-unlock"];
  if (!unlockPathArg) {
    throw new Error(
      `${manifest.chain_id} is not a default-allowed local or testnet chain. ` +
        "Non-testnet promotion requires signed external audit, testnet soak, artifact digest, " +
        "and minimum-bar gates before deployment, then live runtime codehash verification after deployment. " +
        "Provide --assurance-unlock <reviewed-json> only after security-owner approval."
    );
  }

  const unlockPath = path.resolve(repoRoot, unlockPathArg);
  const unlock = readJson(unlockPath);
  return await validateAssuranceUnlock({
    unlock,
    unlockPath,
    manifest,
    manifestHash,
    approval,
    contractRelease,
    deploymentPolicy,
    contractPackage
  });
}

async function enforceNonTestnetPostDeploymentAssurance({
  assurance,
  manifest,
  manifestHash,
  contractPackage,
  provider,
  plannedContractAddresses,
  deployedRuntimeCodehashes
}) {
  if (!assurance) {
    return null;
  }
  validateRunnerRuntimeCodehashes(deployedRuntimeCodehashes, contractPackage);
  const runtimeRef = assuranceComponentRef(assurance.unlock, "runtime_codehash_gate");
  if (!runtimeRef) {
    throw new Error("external assurance artifact must bind detached runtime_codehash_gate before post-configuration");
  }
  const runtimeGate = loadDetachedAssuranceComponent(assurance.unlock, assurance.unlockPath, "runtime_codehash_gate");
  requireAssuranceCheck("runtime_codehash_gate", runtimeGate.value);
  await validateRuntimeCodehashGate(
    runtimeGate.value,
    contractPackage,
    manifest,
    manifestHash,
    provider,
    plannedContractAddresses
  );
  return {
    id: "deployment.external_assurance_postdeployment",
    outcome: "pass",
    note: `Detached runtime codehash gate ${repoRelative(runtimeGate.path)} matched live deployed code before post-configuration.`
  };
}

function readArtifact(ref) {
  return readJson(artifactPath(ref));
}

function toHexBalance(amount) {
  return ethers.toBeHex(amount);
}

function toSalt(namespace, localSalt) {
  return ethers.keccak256(ethers.toUtf8Bytes(`${namespace}:${localSalt}`));
}

function labelHash(label) {
  return ethers.keccak256(ethers.toUtf8Bytes(label));
}

function reviewedOperatorKeyHash(operatorConfig) {
  const keyHash = operatorConfig.operator_key_hash;
  requireBytes32("manifest operator_configuration.operator_key_hash", keyHash);
  if (keyHash.toLowerCase() === `0x${"00".repeat(32)}`) {
    throw new Error("manifest operator_configuration.operator_key_hash must not be zero");
  }
  return keyHash;
}

async function operatorBindingSignature(chainId, identityRegistryAddress, adminPrivateKey, operatorAddress, edKeyHash, settlementKey) {
  return new ethers.Wallet(adminPrivateKey).signTypedData(
    {
      name: "ChioIdentityRegistry",
      version: "1",
      chainId,
      verifyingContract: identityRegistryAddress
    },
    OPERATOR_BINDING_TYPES,
    { operatorAddress, edKeyHash, settlementKey }
  );
}

function normalizeDeployedCodeForImmutableReferences(label, artifact, deployedCode) {
  const deployedHex = deployedCode.toLowerCase().replace(/^0x/, "");
  const templateHex = (artifact.deployedBytecode ?? "").toLowerCase().replace(/^0x/, "");
  if (!templateHex) {
    throw new Error(`${label} artifact has no deployedBytecode`);
  }
  if (deployedHex.length !== templateHex.length) {
    throw new Error(`${label} deployed runtime bytecode length does not match compiled artifact`);
  }
  let normalized = deployedHex;
  for (const references of Object.values(artifact.immutableReferences ?? {})) {
    for (const reference of references) {
      const start = reference.start * 2;
      const end = start + reference.length * 2;
      normalized = `${normalized.slice(0, start)}${templateHex.slice(start, end)}${normalized.slice(end)}`;
    }
  }
  return `0x${normalized}`;
}

function contractPackageRuntimeCodehash(contractPackage, contractId) {
  const packageEntry = (contractPackage.contracts ?? []).find((entry) => entry.contract_id === contractId);
  if (!packageEntry?.deployed_runtime_codehash) {
    throw new Error(`contract package is missing deployed_runtime_codehash for ${contractId}`);
  }
  return packageEntry.deployed_runtime_codehash;
}

async function verifyDeployedRuntimeCodehash({ provider, plan, contractPackage }) {
  let observedBlock = await provider.getBlock("latest");
  let deployedCode = await provider.getCode(plan.planned_address, observedBlock.number);
  let observationSource = "eth_getCode";
  if (!deployedCode || deployedCode === "0x") {
    const network = await provider.getNetwork();
    if (network.chainId === 31337n || network.chainId === 1337n) {
      deployedCode = await provider.getCode(plan.planned_address);
      observedBlock = await provider.getBlock("latest");
      observationSource = "eth_getCode:latest-local-fallback";
    }
  }
  if (!deployedCode || deployedCode === "0x") {
    throw new Error(`${plan.contract_id} deployed bytecode is empty at ${plan.planned_address}`);
  }
  const actualRuntimeCodehash = ethers.keccak256(deployedCode);
  const normalizedRuntimeCodehash = ethers.keccak256(
    normalizeDeployedCodeForImmutableReferences(plan.contract_id, plan.artifact_json, deployedCode)
  );
  if (normalizedRuntimeCodehash.toLowerCase() !== plan.artifact_deployed_runtime_codehash.toLowerCase()) {
    throw new Error(
      `${plan.contract_id} immutable-normalized runtime codehash ${normalizedRuntimeCodehash} ` +
        `does not match artifact ${plan.artifact_deployed_runtime_codehash}`
    );
  }
  const packageRuntimeCodehash = contractPackageRuntimeCodehash(contractPackage, plan.contract_id);
  if (normalizedRuntimeCodehash.toLowerCase() !== packageRuntimeCodehash.toLowerCase()) {
    throw new Error(
      `${plan.contract_id} immutable-normalized runtime codehash ${normalizedRuntimeCodehash} ` +
        `does not match contract package ${packageRuntimeCodehash}`
    );
  }
  return {
    actual_runtime_codehash: actualRuntimeCodehash,
    immutable_normalized_runtime_codehash: normalizedRuntimeCodehash,
    package_runtime_codehash: packageRuntimeCodehash,
    observed_block_number: Number(observedBlock.number),
    observed_block_hash: observedBlock.hash,
    observation_source: observationSource
  };
}

function splitPair(pair) {
  const [base, quote] = pair.split("/");
  if (!base || !quote) {
    throw new Error(`invalid oracle pair ${pair}`);
  }
  return [base.trim(), quote.trim()];
}

function normalizeHex(label, value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]*$/.test(value)) {
    throw new Error(`${label} must be 0x-prefixed hex`);
  }
  if (value.length % 2 !== 0) {
    throw new Error(`${label} must contain complete bytes`);
  }
  return value.toLowerCase();
}

function encodeBaseBuilderDataSuffix(rawCodes) {
  const codes = rawCodes
    .split(",")
    .map((code) => code.trim())
    .filter((code) => code.length > 0);
  if (codes.length === 0) {
    throw new Error("base builder code list cannot be empty");
  }
  for (const code of codes) {
    if (!/^[A-Za-z0-9_:-]+$/.test(code)) {
      throw new Error(`base builder code ${code} contains unsupported characters`);
    }
  }
  const schemaText = codes.join(",");
  const schemaBytes = ethers.toUtf8Bytes(schemaText);
  if (schemaBytes.length > 255) {
    throw new Error("base builder code suffix schema data must fit in one length byte");
  }
  const schemaData = ethers.hexlify(Uint8Array.from([...schemaBytes, schemaBytes.length])).slice(2);
  return `0x${schemaData}00${ERC8021_MARKER}`;
}

function resolveDataSuffix(args) {
  if (args["data-suffix"] || process.env.CHIO_BASE_DATA_SUFFIX) {
    return normalizeHex("base data suffix", args["data-suffix"] ?? process.env.CHIO_BASE_DATA_SUFFIX);
  }
  const builderCode = args["base-builder-code"] ?? process.env.CHIO_BASE_BUILDER_CODE;
  return builderCode ? encodeBaseBuilderDataSuffix(builderCode) : null;
}

function appendDataSuffix(data, dataSuffix) {
  if (!dataSuffix) {
    return data;
  }
  const normalizedData = normalizeHex("transaction data", data ?? "0x");
  return `${normalizedData}${dataSuffix.slice(2)}`;
}

async function sendContractCall(contract, method, params, dataSuffix) {
  const txRequest = await contract[method].populateTransaction(...params);
  txRequest.data = appendDataSuffix(txRequest.data, dataSuffix);
  return await contract.runner.sendTransaction(txRequest);
}

async function waitForCode(provider, address) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const code = await provider.getCode(address);
    if (code && code !== "0x") {
      return code;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`no deployed code found at ${address}`);
}

async function deployContract(name, signer, ...args) {
  const artifact = readArtifact(`contracts/artifacts/${name}.json`);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
  const contract = await factory.deploy(...args);
  const receipt = await contract.deploymentTransaction().wait();
  if (receipt?.status !== 1) {
    throw new Error(`${name} deployment transaction failed`);
  }
  await contract.waitForDeployment();
  return contract;
}

async function startLocalDevnet() {
  const server = ganache.server({
    logging: { quiet: true },
    chain: { chainId: LOCAL_CHAIN_ID, hardfork: "shanghai" },
    wallet: {
      accounts: ACCOUNT_CONFIG.map((account) => ({
        secretKey: account.privateKey,
        balance: toHexBalance(ethers.parseEther("1000"))
      }))
    }
  });

  await new Promise((resolve, reject) => {
    server.listen(LOCAL_PORT, (error) => (error ? reject(error) : resolve()));
  });

  const provider = new ethers.JsonRpcProvider(LOCAL_RPC_URL);
  const wallets = Object.fromEntries(
    ACCOUNT_CONFIG.map((account) => {
      const rawWallet = new ethers.Wallet(account.privateKey, provider);
      const signer = new ethers.NonceManager(rawWallet);
      signer.address = rawWallet.address;
      signer.privateKey = account.privateKey;
      return [account.name, signer];
    })
  );

  return { server, provider, wallets };
}

function createSigner(privateKey, provider) {
  const rawWallet = new ethers.Wallet(privateKey, provider);
  const signer = new ethers.NonceManager(rawWallet);
  signer.address = rawWallet.address;
  signer.privateKey = privateKey;
  return signer;
}

function requireRoleSigner(roleName, expectedAddress, args, provider, fallbackSigner) {
  if (fallbackSigner && fallbackSigner.address.toLowerCase() === expectedAddress.toLowerCase()) {
    return fallbackSigner;
  }

  const roleKeyArg = `${roleName}-key`;
  const privateKey = args[roleKeyArg];
  if (!privateKey) {
    throw new Error(
      `non-local promotion requires --${roleKeyArg} when ${roleName.replaceAll("-", " ")} address ${expectedAddress} differs from the deployer signer`
    );
  }

  const signer = createSigner(privateKey, provider);
  if (signer.address.toLowerCase() !== expectedAddress.toLowerCase()) {
    throw new Error(
      `--${roleKeyArg} signer ${signer.address} does not match reviewed manifest ${roleName.replaceAll("-", " ")} address ${expectedAddress}`
    );
  }
  return signer;
}

async function setupLocalDependencies(wallets) {
  const sequencerFeed = await deployContract("mocks/MockAggregatorV3", wallets.admin, 0, "Local Sequencer Uptime", 0);
  const ethUsdFeed = await deployContract(
    "mocks/MockAggregatorV3",
    wallets.admin,
    8,
    "ETH / USD",
    3000n * 10n ** 8n
  );
  const mockUsdc = await deployContract("mocks/MockERC20", wallets.admin, "Mock USD Coin", "mUSDC", 6);
  await (await mockUsdc.mint(wallets.depositor.address, 5_000_000n * USDC_UNITS)).wait();
  await (await mockUsdc.mint(wallets.principal.address, 5_000_000n * USDC_UNITS)).wait();
  return {
    local_mock_usdc_address: await mockUsdc.getAddress(),
    local_sequencer_uptime_feed: await sequencerFeed.getAddress(),
    local_eth_usd_feed: await ethUsdFeed.getAddress()
  };
}

function resolveValue(token, state) {
  if (typeof token !== "string") {
    return token;
  }
  if (!(token.startsWith("<") && token.endsWith(">"))) {
    return token;
  }

  const key = token.slice(1, -1);
  if (key in state.placeholders) {
    return state.placeholders[key];
  }
  if (key in state.contractAddresses) {
    return state.contractAddresses[key];
  }
  throw new Error(`unresolved placeholder ${token}`);
}

function deploymentReportSkeleton({ manifest, manifestHash, approval, approvalHash, environment }) {
  return {
    report_id: `chio.web3-deployment-promotion.${environment}.v1`,
    generated_at: new Date().toISOString(),
    environment,
    status: "pending",
    manifest_id: manifest.manifest_id,
    manifest_sha256: manifestHash,
    approval_id: approval.approval_id,
    approval_sha256: approvalHash,
    candidate_release_id: approval.candidate_release_id,
    deployment_policy_id: approval.deployment_policy_id,
    checks: []
  };
}

function rollbackPlanSkeleton({ manifest, approval, environment }) {
  return {
    plan_id: `chio.web3-rollback-plan.${environment}.v1`,
    generated_at: new Date().toISOString(),
    environment,
    manifest_id: manifest.manifest_id,
    approval_id: approval.approval_id,
    rollback_mode: approval.failure_policy?.rollback_mode ?? "manual-replacement-deployment",
    stop_on_error: approval.failure_policy?.stop_on_error ?? true,
    require_manual_retry_after_failure: approval.failure_policy?.require_manual_retry_after_failure ?? true,
    rollback_executed: false,
    failure_stage: null,
    notes: []
  };
}

function validateApproval({ manifest, manifestHash, approval, contractRelease, deploymentPolicy, manifestPath, isLocal }) {
  if (approval.status !== "approved") {
    throw new Error("deployment approval is not approved");
  }
  if (approval.reviewed_manifest_sha256 !== manifestHash) {
    throw new Error("deployment approval manifest hash does not match the reviewed manifest");
  }
  const expectedManifestPath = repoRelative(manifestPath);
  if (approval.reviewed_manifest_path !== expectedManifestPath) {
    throw new Error(`deployment approval reviewed_manifest_path mismatch: expected ${expectedManifestPath}`);
  }
  if (approval.candidate_release_id !== contractRelease.release_id) {
    throw new Error("deployment approval candidate release does not match the shipped contract release");
  }
  if (approval.deployment_policy_id !== deploymentPolicy.policyId) {
    throw new Error("deployment approval policy does not match the shipped deployment policy");
  }
  if (approval.create2?.salt_namespace !== manifest.salt_namespace) {
    throw new Error("deployment approval salt namespace does not match the reviewed manifest");
  }

  const factoryMode = approval.create2?.factory_mode;
  if (isLocal) {
    if (factoryMode !== "runner-managed-local") {
      throw new Error("local promotion qualification requires factory_mode runner-managed-local");
    }
    return;
  }

  if (factoryMode !== "predeployed" || !approval.create2?.factory_address) {
    throw new Error("non-local promotion requires a predeployed create2 factory address in the approval artifact");
  }
}

async function main() {
  const args = parseArgs(process.argv);
  const manifestPath = args.manifest ? path.resolve(repoRoot, args.manifest) : null;
  const approvalPath = args.approval ? path.resolve(repoRoot, args.approval) : null;
  const outputDir = args["output-dir"] ? path.resolve(repoRoot, args["output-dir"]) : null;
  const localDevnet = Boolean(args["local-devnet"]);
  const rollbackOnFailure = Boolean(args["rollback-on-failure"]);
  const dataSuffix = resolveDataSuffix(args);

  if (!manifestPath || !approvalPath || !outputDir) {
    throw new Error("usage: node contracts/scripts/promote-deployment.mjs --manifest <path> --approval <path> --output-dir <path> [--local-devnet] [--rollback-on-failure] [--rpc-url <url>] [--deployer-key <hex>] [--registry-admin-key <hex>] [--operator-key <hex>] [--price-admin-key <hex>] [--assurance-unlock <reviewed-json>] [--base-builder-code <code>] [--data-suffix <hex>]");
  }

  ensureDir(outputDir);
  const manifest = readJson(manifestPath);
  const approval = readJson(approvalPath);
  const contractRelease = readJson(path.join(contractsDir, "release", "CHIO_WEB3_CONTRACT_RELEASE.json"));
  const deploymentPolicy = readJson(path.join(repoRoot, "docs", "standards", "CHIO_WEB3_DEPLOYMENT_POLICY.json"));
  const contractPackage = readJson(path.join(repoRoot, "docs", "standards", "CHIO_WEB3_CONTRACT_PACKAGE.json"));
  const manifestHash = sha256File(manifestPath);
  const approvalHash = sha256File(approvalPath);
  const environment = localDevnet ? "local-devnet" : approval.environment ?? "operator-rollout";

  const reportPath = path.join(outputDir, "promotion-report.json");
  const rollbackPath = path.join(outputDir, "rollback-plan.json");
  const deploymentPath = path.join(outputDir, "deployment.json");

  let report = deploymentReportSkeleton({ manifest, manifestHash, approval, approvalHash, environment });
  let rollbackPlan = rollbackPlanSkeleton({ manifest, approval, environment });
  if (dataSuffix) {
    report.attribution = {
      data_suffix_sha256: ethers.sha256(dataSuffix),
      erc8021_marker: `0x${ERC8021_MARKER}`
    };
  }

  let server;
  let provider;
  let wallets;
  let snapshotId = null;

  try {
    validateApproval({ manifest, manifestHash, approval, contractRelease, deploymentPolicy, manifestPath, isLocal: localDevnet });
    report.checks.push({
      id: "approval.validation",
      outcome: "pass",
      note: "Reviewed manifest hash, release id, deployment policy, and create2 salt namespace matched the approved promotion artifact."
    });
    const state = {
      placeholders: {},
      contractAddresses: {},
      deploymentPlan: []
    };

    if (localDevnet) {
      ({ server, provider, wallets } = await startLocalDevnet());
      state.placeholders = await setupLocalDependencies(wallets);
    } else {
      const rpcUrl = args["rpc-url"];
      const deployerKey = args["deployer-key"];
      if (!rpcUrl || !deployerKey) {
        throw new Error("non-local promotion requires --rpc-url and --deployer-key");
      }
      provider = new ethers.JsonRpcProvider(rpcUrl);
      const deployerSigner = createSigner(deployerKey, provider);
      wallets = {
        deployer: deployerSigner,
        admin: requireRoleSigner(
          "registry-admin",
          manifest.operator_configuration?.registry_admin_address,
          args,
          provider,
          deployerSigner
        ),
        operator: requireRoleSigner(
          "operator",
          manifest.operator_configuration?.operator_address,
          args,
          provider,
          deployerSigner
        ),
        priceAdmin: requireRoleSigner(
          "price-admin",
          manifest.operator_configuration?.price_admin_address,
          args,
          provider,
          deployerSigner
        )
      };
    }

    if (localDevnet) {
      wallets.deployer = wallets.admin;
      wallets.priceAdmin = wallets.admin;
    }

    const network = await provider.getNetwork();
    if (manifest.chain_id !== `eip155:${network.chainId}`) {
      throw new Error(`manifest chain id ${manifest.chain_id} does not match target chain eip155:${network.chainId}`);
    }

    const factoryArtifact = readArtifact("contracts/artifacts/mocks/ChioCreate2Factory.json");
    let create2FactoryAddress = approval.create2?.factory_address ?? null;
    let create2Factory;

    if (!create2FactoryAddress) {
      const factory = new ethers.ContractFactory(
        factoryArtifact.abi,
        factoryArtifact.bytecode,
        wallets.deployer
      );
      const deployed = await factory.deploy();
      await deployed.waitForDeployment();
      create2FactoryAddress = await deployed.getAddress();
      report.checks.push({
        id: "create2.factory_bootstrap",
        outcome: "pass",
        note: "Runner bootstrapped the bounded local CREATE2 factory for promotion rehearsal."
      });
    } else {
      report.checks.push({
        id: "create2.factory_predeployed",
        outcome: "pass",
        note: `Runner used the preapproved CREATE2 factory ${create2FactoryAddress}.`
      });
    }

    create2Factory = new ethers.Contract(create2FactoryAddress, factoryArtifact.abi, wallets.deployer);

    if (localDevnet && rollbackOnFailure) {
      snapshotId = await provider.send("evm_snapshot", []);
      rollbackPlan.snapshot_id = snapshotId;
      rollbackPlan.notes.push("Snapshot captured after local dependencies and CREATE2 factory bootstrap.");
    }

    for (const contract of manifest.contracts ?? []) {
      const artifact = readArtifact(contract.artifact);
      const constructorArgs = (contract.constructor_args ?? []).map((arg) => resolveValue(arg, state));
      const deployFactory = new ethers.ContractFactory(
        artifact.abi,
        artifact.bytecode,
        wallets.deployer
      );
      const deployTx = await deployFactory.getDeployTransaction(...constructorArgs);
      const initCode = deployTx.data;
      const salt = toSalt(manifest.salt_namespace, contract.create2_salt);
      const plannedAddress = ethers.getCreate2Address(create2FactoryAddress, salt, ethers.keccak256(initCode));
      const artifactDeployedRuntimeCodehash = artifact.deployedRuntimeCodehash;
      if (!artifactDeployedRuntimeCodehash) {
        throw new Error(`${contract.contract_id} artifact has no deployedRuntimeCodehash`);
      }
      state.deploymentPlan.push({
        contract_id: contract.contract_id,
        artifact: contract.artifact,
        artifact_json: artifact,
        source: contract.source,
        constructor_args: constructorArgs,
        init_code_hash: ethers.keccak256(initCode),
        create2_salt: contract.create2_salt,
        create2_salt_hash: salt,
        planned_address: plannedAddress,
        init_code: initCode,
        artifact_deployed_runtime_codehash: artifactDeployedRuntimeCodehash,
        package_deployed_runtime_codehash: contractPackageRuntimeCodehash(contractPackage, contract.contract_id)
      });

      const placeholderKey = contract.contract_id.replace("chio.", "").replaceAll("-", "_");
      state.contractAddresses[`${placeholderKey}_address`] = plannedAddress;
      state.contractAddresses[`${placeholderKey}`] = plannedAddress;
    }

    report.planned_contract_addresses = Object.fromEntries(
      state.deploymentPlan.map((plan) => [plan.contract_id, plan.planned_address])
    );

    const assurance = await enforceNonTestnetPreDeploymentAssurance({
      args,
      manifest,
      manifestHash,
      approval,
      contractRelease,
      deploymentPolicy,
      contractPackage
    });
    if (assurance) {
      report.checks.push(assurance.check);
    }

    const deploymentTransactions = {};
    const deployedRuntimeCodehashes = {};
    for (const plan of state.deploymentPlan) {
      const existingCode = await provider.getCode(plan.planned_address);
      if (existingCode && existingCode !== "0x") {
        // CREATE2 binds the planned_address to (factory, salt, keccak(initcode)).
        // We just computed initcode from the reviewed artifact + reviewed
        // constructor args, so any code that lives at planned_address must be
        // the deterministic constructor output of our exact initcode (modulo
        // SHA-3 collision, which is cryptographically infeasible). Stale or
        // out-of-band code therefore cannot land at the planned address with
        // bytecode that disagrees with the reviewed artifact.
        //
        // When the artifact happens to expose deployedBytecode (toolchains
        // sometimes do, sometimes do not), we keep a defense-in-depth check
        // that compares its hash to the on-chain runtime hash. The check is a
        // best-effort cross-validation, not the primary safety guarantee, and
        // a missing deployedBytecode does NOT block idempotent promotion.
        const runtimeCodehash = await verifyDeployedRuntimeCodehash({ provider, plan, contractPackage });
        deployedRuntimeCodehashes[plan.contract_id] = runtimeCodehash;
        deploymentTransactions[plan.contract_id] = {
          tx_hash: null,
          gas_used: 0n,
          status: "already_deployed",
          init_code_hash: plan.init_code_hash,
          runtime_codehash_check: "matched_artifact_and_contract_package",
          ...runtimeCodehash
        };
        continue;
      }
      const tx = await sendContractCall(
        create2Factory,
        "deploy",
        [plan.create2_salt_hash, plan.init_code],
        dataSuffix
      );
      const receipt = await tx.wait();
      if (receipt?.status !== 1) {
        throw new Error(`${plan.contract_id} CREATE2 deployment transaction failed`);
      }
      await waitForCode(provider, plan.planned_address);
      const runtimeCodehash = await verifyDeployedRuntimeCodehash({ provider, plan, contractPackage });
      deployedRuntimeCodehashes[plan.contract_id] = runtimeCodehash;
      deploymentTransactions[plan.contract_id] = {
        tx_hash: tx.hash,
        gas_used: receipt.gasUsed,
        status: "deployed",
        init_code_hash: plan.init_code_hash,
        runtime_codehash_check: "matched_artifact_and_contract_package",
        ...runtimeCodehash
      };
    }

    report.checks.push({
      id: "deployment.create2_rollout",
      outcome: "pass",
      note: "Reviewed manifest deployed the full bounded contract family through CREATE2 and every actual address matched the planned address. Each deployed runtime bytecode hash was checked against the compiled artifact and official contract package."
    });

    const postDeploymentAssuranceCheck = await enforceNonTestnetPostDeploymentAssurance({
      assurance,
      manifest,
      manifestHash,
      contractPackage,
      provider,
      plannedContractAddresses: report.planned_contract_addresses,
      deployedRuntimeCodehashes
    });
    if (postDeploymentAssuranceCheck) {
      report.checks.push(postDeploymentAssuranceCheck);
    }

    const deployedContracts = Object.fromEntries(
      state.deploymentPlan.map((plan) => [plan.contract_id, plan.planned_address])
    );

    const identityRegistryArtifact = readArtifact("contracts/artifacts/ChioIdentityRegistry.json");
    const rootRegistryArtifact = readArtifact("contracts/artifacts/ChioRootRegistry.json");
    const priceResolverArtifact = readArtifact("contracts/artifacts/ChioPriceResolver.json");
    const escrowArtifact = readArtifact("contracts/artifacts/ChioEscrow.json");
    const bondVaultArtifact = readArtifact("contracts/artifacts/ChioBondVault.json");

    const identityRegistry = new ethers.Contract(
      deployedContracts["chio.identity-registry"],
      identityRegistryArtifact.abi,
      wallets.admin
    );
    const rootRegistry = new ethers.Contract(
      deployedContracts["chio.root-registry"],
      rootRegistryArtifact.abi,
      wallets.operator
    );
    const priceResolver = new ethers.Contract(
      deployedContracts["chio.price-resolver"],
      priceResolverArtifact.abi,
      wallets.priceAdmin
    );
    const escrow = new ethers.Contract(
      deployedContracts["chio.escrow"],
      escrowArtifact.abi,
      wallets.admin
    );
    const bondVault = new ethers.Contract(
      deployedContracts["chio.bond-vault"],
      bondVaultArtifact.abi,
      wallets.admin
    );
    const rootIdentityRegistry = ethers.getAddress(await rootRegistry.identityRegistry());
    if (ethers.getAddress(await escrow.identityRegistry()) !== rootIdentityRegistry) {
      throw new Error("escrow identity registry must match root registry identity registry");
    }
    if (ethers.getAddress(await bondVault.identityRegistry()) !== rootIdentityRegistry) {
      throw new Error("bond vault identity registry must match root registry identity registry");
    }
    const rawSettlementTokenAddress = resolveValue(manifest.settlement_token?.address, state);
    if (!rawSettlementTokenAddress) {
      throw new Error("manifest settlement_token.address is required");
    }
    const settlementTokenAddress = ethers.getAddress(rawSettlementTokenAddress);

    const operatorConfig = manifest.operator_configuration ?? {};
    const expectedEdKeyHash = reviewedOperatorKeyHash(operatorConfig);
    const expectedSettlementKey = ethers.getAddress(operatorConfig.operator_address);
    const existingOperator = await identityRegistry.getOperator(operatorConfig.operator_address);
    let operatorTx = null;
    if (existingOperator.active) {
      // Active record on chain: verify the bound key material matches the
      // reviewed manifest before treating registration as idempotent. If the
      // edKeyHash or settlement key disagree, refuse rather than implicitly
      // accept stale or unrelated identity bindings (which would later break
      // root publication and other key-bound flows).
      const onChainEdKeyHash = existingOperator.edKeyHash.toLowerCase();
      const onChainSettlement = ethers.getAddress(existingOperator.settlementKey);
      if (
        onChainEdKeyHash !== expectedEdKeyHash.toLowerCase() ||
        onChainSettlement !== expectedSettlementKey
      ) {
        throw new Error(
          `operator ${operatorConfig.operator_address} is already registered with mismatched key material ` +
            `(on-chain edKeyHash=${existingOperator.edKeyHash}, settlementKey=${onChainSettlement}; ` +
            `manifest expects edKeyHash=${expectedEdKeyHash}, settlementKey=${expectedSettlementKey}). ` +
            `Refusing to skip registerOperator.`
        );
      }
    } else {
      const bindingProof = await operatorBindingSignature(
        network.chainId,
        await identityRegistry.getAddress(),
        wallets.admin.privateKey,
        operatorConfig.operator_address,
        expectedEdKeyHash,
        operatorConfig.operator_address
      );
      operatorTx = await sendContractCall(
        identityRegistry,
        "registerOperator",
        [
          operatorConfig.operator_address,
          expectedEdKeyHash,
          operatorConfig.operator_address,
          bindingProof
        ],
        null
      );
      await operatorTx.wait();
    }

    const latestBlock = await provider.getBlock("latest");
    const delegateExpiry = BigInt(Number(latestBlock.timestamp) + (operatorConfig.delegate_expiry_seconds ?? DEFAULT_EXPIRY_SECONDS));
    const delegateAlreadyRegistered = await rootRegistry.isAuthorizedPublisher(
      operatorConfig.operator_address,
      operatorConfig.delegate_address
    );
    let delegateTx = null;
    if (!delegateAlreadyRegistered) {
      delegateTx = await sendContractCall(
        rootRegistry,
        "registerDelegate",
        [operatorConfig.delegate_address, delegateExpiry],
        null
      );
      await delegateTx.wait();
    }

    const feedTransactions = [];
    for (const feed of manifest.oracle_configuration?.feeds ?? []) {
      const [base, quote] = splitPair(feed.pair);
      const tx = await sendContractCall(
        priceResolver,
        "registerFeed",
        [
          labelHash(base),
          labelHash(quote),
          resolveValue(feed.address, state),
          BigInt(feed.heartbeat_seconds ?? 3600)
        ],
        null
      );
      await tx.wait();
      feedTransactions.push({
        pair: feed.pair,
        tx_hash: tx.hash,
        feed_address: resolveValue(feed.address, state)
      });
    }

    const escrowTokenAlreadyAllowed = await escrow.tokenAllowed(settlementTokenAddress);
    let escrowTokenTx = null;
    if (!escrowTokenAlreadyAllowed) {
      escrowTokenTx = await sendContractCall(
        escrow,
        "setTokenAllowed",
        [settlementTokenAddress, true],
        null
      );
      await escrowTokenTx.wait();
    }
    const bondTokenAlreadyAllowed = await bondVault.tokenAllowed(settlementTokenAddress);
    let bondTokenTx = null;
    if (!bondTokenAlreadyAllowed) {
      bondTokenTx = await sendContractCall(
        bondVault,
        "setTokenAllowed",
        [settlementTokenAddress, true],
        null
      );
      await bondTokenTx.wait();
    }

    report.checks.push({
      id: "deployment.post_config",
      outcome: "pass",
      note: "Operator binding, delegate registration, token allowlisting, and oracle feed configuration were applied from the reviewed manifest and chain config."
    });

    const deploymentRecord = {
      deployment_id: `chio.web3-reviewed-rollout.${environment}.v1`,
      generated_at: new Date().toISOString(),
      environment,
      manifest_id: manifest.manifest_id,
      manifest_sha256: manifestHash,
      approval_id: approval.approval_id,
      approval_sha256: approvalHash,
      create2_factory_address: create2FactoryAddress,
      chain_id: `eip155:${network.chainId}`,
      rpc_url: localDevnet ? LOCAL_RPC_URL : args["rpc-url"],
      settlement_token: {
        symbol: manifest.settlement_token?.symbol,
        address: resolveValue(manifest.settlement_token?.address, state)
      },
      planned_contract_addresses: report.planned_contract_addresses,
      deployed_contract_addresses: Object.fromEntries(
        state.deploymentPlan.map((plan) => [plan.contract_id, plan.planned_address])
      ),
      deployed_runtime_codehashes: deployedRuntimeCodehashes,
      deployment_transactions: deploymentTransactions,
      configuration_transactions: {
        operator_registration: operatorTx
          ? { tx_hash: operatorTx.hash, status: "submitted" }
          : { tx_hash: null, status: "already_registered" },
        delegate_registration: delegateTx
          ? { tx_hash: delegateTx.hash, status: "submitted" }
          : { tx_hash: null, status: "already_registered" },
        feed_registrations: feedTransactions,
        token_allowlist: {
          settlement_token: settlementTokenAddress,
          escrow: escrowTokenTx
            ? { tx_hash: escrowTokenTx.hash, status: "submitted" }
            : { tx_hash: null, status: "already_allowed" },
          bond_vault: bondTokenTx
            ? { tx_hash: bondTokenTx.hash, status: "submitted" }
            : { tx_hash: null, status: "already_allowed" }
        }
      },
      attribution: dataSuffix
        ? {
            data_suffix_sha256: ethers.sha256(dataSuffix),
            erc8021_marker: `0x${ERC8021_MARKER}`
          }
        : null,
      local_dependencies: localDevnet ? state.placeholders : {}
    };

    rollbackPlan.notes.push(
      localDevnet
        ? "Local rehearsal can revert to the captured snapshot on failure; successful promotion remains reproducible by rerunning against a fresh devnet with the same reviewed manifest and approval."
        : "Live rollback is replacement-oriented: stop broader promotion, retain the reviewed manifest and approval artifact, and cut a superseding reviewed manifest if replacement is required."
    );

    report.status = "promoted";
    report.chain_id = `eip155:${network.chainId}`;
    report.create2_factory_address = create2FactoryAddress;
    report.deployment_path = repoRelative(deploymentPath);
    report.rollback_plan_path = repoRelative(rollbackPath);
    report.deployed_contract_addresses = deploymentRecord.deployed_contract_addresses;
    report.deployed_runtime_codehashes = deployedRuntimeCodehashes;

    writeJson(deploymentPath, deploymentRecord);
    writeJson(rollbackPath, rollbackPlan);
    writeJson(reportPath, report);
  } catch (error) {
    rollbackPlan.failure_stage = report.checks.at(-1)?.id ?? "deployment.error";
    rollbackPlan.notes.push(error?.message ?? String(error));
    report.status = "failed";
    report.error = error?.message ?? String(error);
    report.checks.push({
      id: "deployment.failure",
      outcome: "fail",
      note: report.error
    });

    if (localDevnet && rollbackOnFailure && provider && snapshotId !== null) {
      const reverted = await provider.send("evm_revert", [snapshotId]);
      rollbackPlan.rollback_executed = Boolean(reverted);
      rollbackPlan.notes.push(
        reverted
          ? "Local snapshot rollback executed after failed promotion."
          : "Local snapshot rollback was attempted but the provider did not confirm it."
      );
    }

    writeJson(rollbackPath, rollbackPlan);
    writeJson(reportPath, report);
    throw error;
  } finally {
    const destroyResult = provider?.destroy?.();
    if (destroyResult && typeof destroyResult.then === "function") {
      await destroyResult;
    }
    if (server) {
      server.close();
    }
  }
}

await main();
