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

function validateAssuranceUnlock({ unlock, unlockPath, manifest, approval, contractRelease, deploymentPolicy }) {
  if (!unlock || typeof unlock !== "object") {
    throw new Error("external assurance artifact must be a JSON object");
  }
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
  const securityOwner = unlock.security_owner_approval ?? {};
  if (securityOwner.status !== "approved" || !securityOwner.actor || !securityOwner.approved_at) {
    throw new Error("external assurance artifact requires security_owner_approval with status approved, actor, and approved_at");
  }
  requireAssuranceCheck("external_audit", unlock.external_audit);
  requireAssuranceCheck("testnet_soak", unlock.testnet_soak);
  requireAssuranceCheck("artifact_digest_gate", unlock.artifact_digest_gate);
  requireAssuranceCheck("runtime_codehash_gate", unlock.runtime_codehash_gate);
  requireAssuranceCheck("minimum_bar_checklist", unlock.minimum_bar_checklist);
  if (!Array.isArray(unlock.unresolved_critical_high_findings) || unlock.unresolved_critical_high_findings.length !== 0) {
    throw new Error("external assurance artifact must declare zero unresolved critical/high findings");
  }
  return {
    id: "deployment.external_assurance",
    outcome: "pass",
    note: `External assurance artifact ${repoRelative(unlockPath)} authorizes non-testnet promotion for ${manifest.chain_id}.`
  };
}

function enforceNonTestnetAssurance({ args, manifest, approval, contractRelease, deploymentPolicy }) {
  const chainId = parseEip155ChainId(manifest.chain_id);
  if (DEFAULT_ALLOWED_CHAIN_IDS.has(chainId)) {
    return null;
  }

  const unlockPathArg = args["assurance-unlock"];
  if (!unlockPathArg) {
    throw new Error(
      `${manifest.chain_id} is not a default-allowed local or testnet chain. ` +
        "Non-testnet promotion requires external audit, testnet soak, artifact digest, runtime codehash, " +
        "and minimum-bar gates. Provide --assurance-unlock <reviewed-json> only after security-owner approval."
    );
  }

  const unlockPath = path.resolve(repoRoot, unlockPathArg);
  const unlock = readJson(unlockPath);
  return validateAssuranceUnlock({ unlock, unlockPath, manifest, approval, contractRelease, deploymentPolicy });
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
    const assuranceCheck = enforceNonTestnetAssurance({ args, manifest, approval, contractRelease, deploymentPolicy });
    if (assuranceCheck) {
      report.checks.push(assuranceCheck);
    }

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
      const expectedDeployedBytecode = (artifact.deployedBytecode ?? "").toLowerCase();
      state.deploymentPlan.push({
        contract_id: contract.contract_id,
        artifact: contract.artifact,
        source: contract.source,
        constructor_args: constructorArgs,
        init_code_hash: ethers.keccak256(initCode),
        create2_salt: contract.create2_salt,
        create2_salt_hash: salt,
        planned_address: plannedAddress,
        init_code: initCode,
        expected_deployed_bytecode: expectedDeployedBytecode,
        expected_deployed_bytecode_hash: expectedDeployedBytecode
          ? ethers.keccak256(expectedDeployedBytecode.startsWith("0x") ? expectedDeployedBytecode : `0x${expectedDeployedBytecode}`)
          : null
      });

      const placeholderKey = contract.contract_id.replace("chio.", "").replaceAll("-", "_");
      state.contractAddresses[`${placeholderKey}_address`] = plannedAddress;
      state.contractAddresses[`${placeholderKey}`] = plannedAddress;
    }

    report.planned_contract_addresses = Object.fromEntries(
      state.deploymentPlan.map((plan) => [plan.contract_id, plan.planned_address])
    );

    const deploymentTransactions = {};
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
        const onChainHash = ethers.keccak256(existingCode);
        if (
          plan.expected_deployed_bytecode_hash &&
          onChainHash.toLowerCase() !== plan.expected_deployed_bytecode_hash.toLowerCase()
        ) {
          throw new Error(
            `address ${plan.planned_address} for ${plan.contract_id} has unexpected on-chain bytecode ` +
              `(expected runtime hash ${plan.expected_deployed_bytecode_hash}, on-chain hash ${onChainHash}). ` +
              `Refusing to mark as already_deployed.`
          );
        }
        deploymentTransactions[plan.contract_id] = {
          tx_hash: null,
          gas_used: 0n,
          status: "already_deployed",
          on_chain_bytecode_hash: onChainHash,
          init_code_hash: plan.init_code_hash,
          deployed_bytecode_hash_check: plan.expected_deployed_bytecode_hash
            ? "matched_artifact"
            : "skipped_artifact_lacks_deployedBytecode"
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
      await waitForCode(provider, plan.planned_address);
      deploymentTransactions[plan.contract_id] = {
        tx_hash: tx.hash,
        gas_used: receipt.gasUsed
      };
    }

    report.checks.push({
      id: "deployment.create2_rollout",
      outcome: "pass",
      note: "Reviewed manifest deployed the full bounded contract family through CREATE2 and every actual address matched the planned address. Any address with pre-existing code was verified against the artifact's runtime bytecode hash before being marked already_deployed."
    });

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
    const rawSettlementTokenAddress = resolveValue(manifest.settlement_token?.address, state);
    if (!rawSettlementTokenAddress) {
      throw new Error("manifest settlement_token.address is required");
    }
    const settlementTokenAddress = ethers.getAddress(rawSettlementTokenAddress);

    const operatorConfig = manifest.operator_configuration ?? {};
    const operatorLabel = operatorConfig.operator_ed_key_label ?? "chio-operator-ed25519-key";
    const expectedEdKeyHash = labelHash(operatorLabel);
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
      operatorTx = await sendContractCall(
        identityRegistry,
        "registerOperator",
        [
          operatorConfig.operator_address,
          expectedEdKeyHash,
          operatorConfig.operator_address,
          ethers.toUtf8Bytes("deployment-runner:operator")
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
    report.create2_factory_address = create2FactoryAddress;
    report.deployment_path = repoRelative(deploymentPath);
    report.rollback_plan_path = repoRelative(rollbackPath);
    report.deployed_contract_addresses = deploymentRecord.deployed_contract_addresses;

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
