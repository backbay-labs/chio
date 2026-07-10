import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";
import ganache from "ganache";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(rootDir, "..");
const artifactsDir = path.join(rootDir, "artifacts");
const deploymentsDir = path.join(rootDir, "deployments");
const reportsDir = path.join(rootDir, "reports");
const contractPackagePath = path.join(repoRoot, "docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json");
const deploymentPolicyPath = path.join(repoRoot, "docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json");

const PORT = 8545;
const RPC_URL = `http://127.0.0.1:${PORT}`;
const CHAIN_ID = 31337;
const USDC_UNITS = 10n ** 6n;
const ESCROW_PROOF_LEAF_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes(
    "ChioEscrowProof(uint256 chainId,address escrow,bytes32 escrowId,address token,address beneficiary,bytes32 operatorKeyHash,bytes32 receiptHash,uint256 amount,bool partial)",
  ),
);
const LEGACY_ESCROW_PROOF_LEAF_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes(
    "ChioEscrowProof(uint256 chainId,address escrow,bytes32 escrowId,bytes32 receiptHash,uint256 amount,bool partial)",
  ),
);
const ESCROW_RELEASE_TYPES = {
  ChioEscrowRelease: [
    { name: "escrowId", type: "bytes32" },
    { name: "receiptHash", type: "bytes32" },
    { name: "amount", type: "uint256" },
    { name: "operatorEpoch", type: "uint64" },
  ],
};
const ENTITY_BINDING_TYPES = {
  ChioEntityBinding: [
    { name: "chioEntityId", type: "bytes32" },
    { name: "settlementAddress", type: "address" },
    { name: "operator", type: "address" },
  ],
};
const OPERATOR_BINDING_TYPES = {
  ChioOperatorBinding: [
    { name: "operatorAddress", type: "address" },
    { name: "edKeyHash", type: "bytes32" },
    { name: "settlementKey", type: "address" },
  ],
};
const BOND_PROOF_LEAF_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes(
    "ChioBondProof(uint256 chainId,address vault,bytes32 vaultId,bytes32 operatorKeyHash,bytes32 evidenceHash,uint8 action,uint256 slashAmount,bytes32 distributionHash)",
  ),
);
const ZERO_BYTES32 = ethers.ZeroHash;
const BOND_ACTION_RELEASE = 0;
const BOND_ACTION_IMPAIR = 1;
const PAUSED_SELECTOR = ethers.id("Paused()").slice(0, 10);
const INVALID_SIGNATURE_SELECTOR = ethers.id("InvalidSignature()").slice(0, 10);
const INVALID_RELEASE_AMOUNT_SELECTOR = ethers.id("InvalidReleaseAmount()").slice(0, 10);
const INVALID_BATCH_RANGE_SELECTOR = ethers.id("InvalidBatchRange()").slice(0, 10);
const INVALID_MERKLE_ROOT_SELECTOR = ethers.id("InvalidMerkleRoot()").slice(0, 10);
const INVALID_TIMESTAMP_SELECTOR = ethers.id("InvalidTimestamp()").slice(0, 10);
const INVALID_ROUND_SELECTOR = ethers.id("InvalidRound()").slice(0, 10);
const INVALID_SLASH_DISTRIBUTION_SELECTOR = ethers.id("InvalidSlashDistribution()").slice(0, 10);
const INVALID_EVIDENCE_SELECTOR = ethers.id("InvalidEvidence()").slice(0, 10);
const BOND_NO_LONGER_LIVE_SELECTOR = ethers.id("BondNoLongerLive()").slice(0, 10);
const OPERATOR_KEY_HASH_MISMATCH_SELECTOR = ethers.id("OperatorKeyHashMismatch()").slice(0, 10);
const RECEIPT_ALREADY_USED_SELECTOR = ethers.id("ReceiptAlreadyUsed()").slice(0, 10);
const EVIDENCE_ALREADY_USED_SELECTOR = ethers.id("EvidenceAlreadyUsed()").slice(0, 10);
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const ACCOUNT_CONFIG = [
  { name: "admin", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000001" },
  { name: "operator", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000002" },
  { name: "delegate", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000003" },
  { name: "beneficiary", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000004" },
  { name: "depositor", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000005" },
  { name: "principal", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000006" },
  { name: "outsider", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000007" },
  { name: "rotatingOperator", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000008" },
];

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function artifactPath(name) {
  return path.join(artifactsDir, `${name}.json`);
}

function abiEntry(artifact, type, name) {
  return artifact.abi.find((entry) => entry.type === type && entry.name === name);
}

function assertErrorInAbi(artifact, contractName, errorName) {
  assert.ok(
    abiEntry(artifact, "error", errorName),
    `${contractName} artifact is stale: missing ${errorName} error`,
  );
}

function hashArtifactBytecode(contractName, fieldName, bytecode) {
  assert.equal(typeof bytecode, "string", `${contractName} artifact ${fieldName} must be a string`);
  if (bytecode.length === 0) {
    return "";
  }
  assert.match(bytecode, /^[0-9a-fA-F]+$/, `${contractName} artifact ${fieldName} must be hex`);
  return ethers.keccak256(`0x${bytecode}`);
}

function validateArtifactShape(name, artifact) {
  if (
    Object.hasOwn(artifact, "bytecode") ||
    Object.hasOwn(artifact, "deployedBytecode") ||
    Object.hasOwn(artifact, "creationBytecodeHash") ||
    Object.hasOwn(artifact, "deployedRuntimeCodehash")
  ) {
    assert.equal(
      artifact.creationBytecodeHash,
      hashArtifactBytecode(name, "bytecode", artifact.bytecode),
      `${name} artifact creationBytecodeHash is stale`,
    );
    assert.equal(
      artifact.deployedRuntimeCodehash,
      hashArtifactBytecode(name, "deployedBytecode", artifact.deployedBytecode),
      `${name} artifact deployedRuntimeCodehash is stale`,
    );
  }

  if (name === "ChioBondVault") {
    const lockBond = abiEntry(artifact, "function", "lockBond");
    const componentNames = lockBond?.inputs?.[0]?.components?.map((component) => component.name) ?? [];
    assert.ok(
      componentNames.includes("operatorKeyHash"),
      "ChioBondVault artifact is stale: lockBond BondTerms missing operatorKeyHash",
    );
    assertErrorInAbi(artifact, name, "OperatorKeyHashMismatch");
  }

  if (name === "ChioEscrow") {
    const createEscrow = abiEntry(artifact, "function", "createEscrow");
    const componentNames = createEscrow?.inputs?.[0]?.components?.map((component) => component.name) ?? [];
    assert.ok(
      componentNames.includes("operatorKeyHash"),
      "ChioEscrow artifact is stale: createEscrow EscrowTerms missing operatorKeyHash",
    );
    const releaseWithSignature = abiEntry(artifact, "function", "releaseWithSignature");
    const signatureInputs = releaseWithSignature?.inputs?.map((input) => input.name) ?? [];
    assert.equal(
      signatureInputs[3],
      "operatorEpoch",
      "ChioEscrow artifact is stale: releaseWithSignature missing operatorEpoch",
    );
    assertErrorInAbi(artifact, name, "OperatorKeyHashMismatch");
  }

  if (name === "ChioIdentityRegistry") {
    assertErrorInAbi(artifact, name, "InvalidOperatorKeyHash");
    const getOperator = abiEntry(artifact, "function", "getOperator");
    const outputNames = getOperator?.outputs?.[0]?.components?.map((component) => component.name) ?? [];
    assert.ok(
      outputNames.includes("operatorEpoch"),
      "ChioIdentityRegistry artifact is stale: OperatorRecord missing operatorEpoch",
    );
  }

  if (name === "ChioPriceResolver") {
    assertErrorInAbi(artifact, name, "InvalidRound");
  }

  if (name === "ChioRootRegistry") {
    const legacyDetailed = abiEntry(artifact, "function", "verifyInclusionDetailed");
    assert.equal(
      legacyDetailed?.stateMutability,
      "pure",
      "ChioRootRegistry artifact is stale: legacy detailed verifier must be pure/reverting",
    );
    assert.ok(
      abiEntry(artifact, "function", "verifyInclusionDetailedForKeyHash"),
      "ChioRootRegistry artifact is stale: missing keyed detailed verifier",
    );
    assert.ok(
      abiEntry(artifact, "function", "isAuthorizedPublisherForKeyHash"),
      "ChioRootRegistry artifact is stale: missing keyed publisher authorization preflight",
    );
    const getRoot = abiEntry(artifact, "function", "getRoot");
    const rootFields = getRoot?.outputs?.[0]?.components?.map((component) => component.name) ?? [];
    assert.ok(
      rootFields.includes("operatorEpoch"),
      "ChioRootRegistry artifact is stale: RootEntry missing operatorEpoch",
    );
    const rootPublished = abiEntry(artifact, "event", "RootPublished");
    const eventFields = rootPublished?.inputs?.map((input) => input.name) ?? [];
    assert.ok(
      eventFields.includes("operatorEpoch"),
      "ChioRootRegistry artifact is stale: RootPublished missing operatorEpoch",
    );
  }
}

function readArtifact(name) {
  const artifact = JSON.parse(fs.readFileSync(artifactPath(name), "utf8"));
  validateArtifactShape(name, artifact);
  return artifact;
}

function readContractPackageRuntimeCodehashes() {
  const contractPackage = JSON.parse(fs.readFileSync(contractPackagePath, "utf8"));
  return new Map(
    contractPackage.contracts.map((contract) => [
      contract.kind,
      contract.deployed_runtime_codehash,
    ]),
  );
}

function assertGasBudgets(gasEstimates) {
  const deploymentPolicy = JSON.parse(fs.readFileSync(deploymentPolicyPath, "utf8"));
  const gasBudgets = deploymentPolicy.gasBudgets ?? {};
  const gasChecks = {
    register_operator: "registerOperator",
    register_delegate: "registerDelegate",
    publish_root_operator: "publishRoot",
    publish_root_delegate: "publishRoot",
    register_feed: "registerFeed",
    price_read: "getPrice",
    create_escrow: "createEscrow",
    merkle_partial_release: "merklePartialRelease",
    dual_sign_release: "dualSignRelease",
    lock_bond: "lockBond",
    bond_release: "releaseBond",
  };

  for (const [estimateKey, budgetKey] of Object.entries(gasChecks)) {
    const rawEstimate = gasEstimates[estimateKey];
    const estimate = typeof rawEstimate === "string" ? Number(rawEstimate) : rawEstimate;
    const budget = gasBudgets[budgetKey];
    assert.ok(
      Number.isSafeInteger(estimate) && estimate > 0,
      `local-devnet gas estimate ${estimateKey} is missing or invalid`,
    );
    assert.ok(
      Number.isSafeInteger(budget) && budget > 0,
      `deployment policy gas budget ${budgetKey} is missing or invalid`,
    );
    assert.ok(
      estimate <= budget,
      `local-devnet gas estimate ${estimateKey} exceeds ${budgetKey} budget: ${estimate} > ${budget}`,
    );
  }
}

function normalizeDeployedCodeForImmutableReferences(label, artifact, deployedCode) {
  const deployedHex = deployedCode.toLowerCase().replace(/^0x/, "");
  const templateHex = artifact.deployedBytecode.toLowerCase();
  assert.equal(
    deployedHex.length,
    templateHex.length,
    `${label} deployed runtime bytecode length does not match compiled artifact`,
  );
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

async function assertDeployedRuntimeCodehash(provider, label, contract, artifact, expectedPackageHash) {
  const address = await contract.getAddress();
  let observedBlock = await provider.getBlock("latest");
  let deployedCode = await provider.getCode(address, observedBlock.number);
  let observationSource = "eth_getCode";
  if (!deployedCode || deployedCode === "0x") {
    const network = await provider.getNetwork();
    if (network.chainId === 31337n || network.chainId === 1337n) {
      deployedCode = await provider.getCode(address);
      observedBlock = await provider.getBlock("latest");
      observationSource = "eth_getCode:latest-local-fallback";
    }
  }
  assert.notEqual(deployedCode, "0x", `${label} deployed bytecode is empty`);
  const actualRuntimeCodehash = ethers.keccak256(deployedCode);
  const normalizedRuntimeCodehash = ethers.keccak256(
    normalizeDeployedCodeForImmutableReferences(label, artifact, deployedCode),
  );
  assert.equal(
    normalizedRuntimeCodehash,
    artifact.deployedRuntimeCodehash,
    `${label} immutable-normalized deployed runtime codehash does not match compiled artifact`,
  );
  assert.equal(
    typeof expectedPackageHash,
    "string",
    `${label} contract package runtime codehash is missing`,
  );
  assert.equal(
    normalizedRuntimeCodehash,
    expectedPackageHash,
    `${label} immutable-normalized deployed runtime codehash does not match contract package`,
  );
  return {
    actual_runtime_codehash: actualRuntimeCodehash,
    immutable_normalized_runtime_codehash: normalizedRuntimeCodehash,
    package_runtime_codehash: expectedPackageHash,
    observed_block_number: Number(observedBlock.number),
    observed_block_hash: observedBlock.hash,
    observation_source: observationSource,
  };
}

async function deploy(name, signer, ...args) {
  const artifact = readArtifact(name);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
  const contract = await factory.deploy(...args);
  const receipt = await contract.deploymentTransaction().wait();
  assert.equal(receipt?.status, 1, `${name} deployment transaction failed`);
  await contract.waitForDeployment();
  return contract;
}

async function expectDeployRevert(label, provider, name, signer, ...args) {
  const artifact = readArtifact(name);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
  const tx = await factory.getDeployTransaction(...args);
  await expectRevert(label, async () => {
    await provider.call({ ...tx, from: signer.address });
  });
}

function toHexBalance(amount) {
  return ethers.toBeHex(amount);
}

async function expectRevert(label, action) {
  let reverted = false;
  let message = "";
  try {
    await action();
  } catch (error) {
    reverted = true;
    message = error?.shortMessage ?? error?.info?.error?.message ?? error?.message ?? String(error);
  }
  assert(reverted, `${label} should revert`);
  return message;
}

function extractRevertData(error) {
  if (!error || typeof error !== "object") {
    return "";
  }
  if (typeof error.data === "string" && /^0x[0-9a-fA-F]{8}/.test(error.data)) {
    return error.data;
  }
  if (
    error.data &&
    typeof error.data === "object" &&
    typeof error.data.result === "string" &&
    /^0x[0-9a-fA-F]{8}/.test(error.data.result)
  ) {
    return error.data.result;
  }
  const nestedError = error.error ?? error.info?.error;
  if (nestedError && nestedError !== error) {
    return extractRevertData(nestedError);
  }
  return "";
}

async function expectRevertSelector(label, action, selector) {
  let data = "";
  try {
    await action();
  } catch (error) {
    data = extractRevertData(error);
  }
  assert.equal(data.slice(0, 10), selector, `${label} should revert with ${selector}`);
}

function toBytes32Label(label) {
  return ethers.keccak256(ethers.toUtf8Bytes(label));
}

function rfc6962Node(left, right) {
  return ethers.sha256(ethers.concat(["0x01", left, right]));
}

function escrowProofLeaf(
  chainId,
  escrowAddress,
  escrowId,
  token,
  beneficiary,
  operatorKeyHash,
  receiptHash,
  amount,
  isPartial,
) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "bytes32",
        "uint256",
        "address",
        "bytes32",
        "address",
        "address",
        "bytes32",
        "bytes32",
        "uint256",
        "bool",
      ],
      [
        ESCROW_PROOF_LEAF_TYPEHASH,
        BigInt(chainId),
        escrowAddress,
        escrowId,
        token,
        beneficiary,
        operatorKeyHash,
        receiptHash,
        amount,
        isPartial,
      ],
    ),
  );
}

function legacyEscrowProofLeaf(chainId, escrowAddress, escrowId, receiptHash, amount, isPartial) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "address", "bytes32", "bytes32", "uint256", "bool"],
      [
        LEGACY_ESCROW_PROOF_LEAF_TYPEHASH,
        BigInt(chainId),
        escrowAddress,
        escrowId,
        receiptHash,
        amount,
        isPartial,
      ],
    ),
  );
}

function escrowReleaseDomain(chainId, escrowAddress) {
  return {
    name: "ChioEscrow",
    version: "1",
    chainId,
    verifyingContract: escrowAddress,
  };
}

function entityBindingDomain(chainId, identityRegistryAddress) {
  return {
    name: "ChioIdentityRegistry",
    version: "1",
    chainId,
    verifyingContract: identityRegistryAddress,
  };
}

async function operatorBindingSignature(chainId, identityRegistryAddress, adminPrivateKey, operatorAddress, edKeyHash, settlementKey) {
  return new ethers.Wallet(adminPrivateKey).signTypedData(
    entityBindingDomain(chainId, identityRegistryAddress),
    OPERATOR_BINDING_TYPES,
    { operatorAddress, edKeyHash, settlementKey },
  );
}

function bondProofLeaf(chainId, bondVaultAddress, vaultId, operatorKeyHash, evidenceHash, action, slashAmount, distributionHash) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "address", "bytes32", "bytes32", "bytes32", "uint8", "uint256", "bytes32"],
      [
        BOND_PROOF_LEAF_TYPEHASH,
        BigInt(chainId),
        bondVaultAddress,
        vaultId,
        operatorKeyHash,
        evidenceHash,
        action,
        slashAmount,
        distributionHash,
      ],
    ),
  );
}

function bondDistributionHash(beneficiaries, shares) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(["address[]", "uint256[]"], [beneficiaries, shares]),
  );
}

function deterministicAddress(seed) {
  return ethers.getAddress(`0x${seed.toString(16).padStart(40, "0")}`);
}

function normalizeBigints(value) {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeBigints(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, normalizeBigints(nested)]),
    );
  }
  return value;
}

function logStep(message) {
  console.log(`[qualify] ${message}`);
}

async function waitForReceipt(provider, txResponse) {
  for (let attempt = 0; attempt < 200; ++attempt) {
    const receipt = await provider.getTransactionReceipt(txResponse.hash);
    if (receipt) {
      return receipt;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`timed out waiting for receipt ${txResponse.hash}`);
}

async function latestTimestamp(provider) {
  const block = await provider.send("eth_getBlockByNumber", ["latest", false]);
  return Number(BigInt(block.timestamp));
}

async function mineAt(provider, timestamp) {
  const latest = await latestTimestamp(provider);
  assert(timestamp >= latest, `cannot mine backwards from ${latest} to ${timestamp}`);
  await provider.send("evm_increaseTime", [timestamp - latest]);
  await provider.send("evm_mine", []);
  assert.ok((await latestTimestamp(provider)) >= timestamp);
}

async function findContractEvent(receipt, contract, eventName) {
  const contractAddress = (await contract.getAddress()).toLowerCase();
  for (const log of receipt.logs ?? []) {
    if (log.address.toLowerCase() !== contractAddress) {
      continue;
    }
    try {
      const parsed = contract.interface.parseLog(log);
      if (parsed?.name === eventName) {
        return parsed;
      }
    } catch {}
  }
  throw new Error(`missing ${eventName} event on receipt ${receipt.hash}`);
}

async function main() {
  ensureDir(deploymentsDir);
  ensureDir(reportsDir);

  const server = ganache.server({
    logging: { quiet: true },
    chain: { chainId: CHAIN_ID, hardfork: "shanghai" },
    wallet: {
      accounts: ACCOUNT_CONFIG.map((account) => ({
        secretKey: account.privateKey,
        balance: toHexBalance(ethers.parseEther("1000")),
      })),
    },
  });

  await new Promise((resolve, reject) => {
    server.listen(PORT, (error) => (error ? reject(error) : resolve()));
  });

  let provider;

  const checks = [];
  const gasEstimates = {};

  try {
    provider = new ethers.JsonRpcProvider(RPC_URL);
    const wallets = Object.fromEntries(
      ACCOUNT_CONFIG.map((account) => {
        const rawWallet = new ethers.Wallet(account.privateKey, provider);
        const signer = new ethers.NonceManager(rawWallet);
        signer.address = rawWallet.address;
        signer.privateKey = account.privateKey;
        return [account.name, signer];
      }),
    );
    const adminRpcSigner = await provider.getSigner(wallets.admin.address);
    const outsiderRpcSigner = await provider.getSigner(wallets.outsider.address);

    const network = await provider.getNetwork();
    const chainId = Number(network.chainId);
    const nowBlock = await provider.getBlock("latest");
    const now = Number(nowBlock.timestamp);

    const operatorEdKeyHash = toBytes32Label("chio-operator-ed25519-key");
    const reentrantOperatorKeyHash = toBytes32Label("chio-reentrant-operator-key");
    const beneficiaryEntityId = toBytes32Label("chio-beneficiary-entity");
    const priceBase = toBytes32Label("ETH");
    const priceQuote = toBytes32Label("USD");

    logStep("deploying mocks and core contracts");
    const sequencerFeed = await deploy(
      "mocks/MockAggregatorV3",
      wallets.admin,
      0,
      "Base Sequencer Uptime",
      0,
    );
    const ethUsdFeed = await deploy(
      "mocks/MockAggregatorV3",
      wallets.admin,
      8,
      "ETH / USD",
      3000n * 10n ** 8n,
    );
    const mockUsdc = await deploy("mocks/MockERC20", wallets.admin, "Mock USD Coin", "mUSDC", 6);
    const noReturnToken = await deploy(
      "mocks/NoReturnERC20",
      wallets.admin,
      "No Return Token",
      "NORET",
      6,
    );
    const feeToken = await deploy(
      "mocks/FeeOnTransferERC20",
      wallets.admin,
      "Fee Token",
      "FEE",
      6,
      100,
    );
    const contractAdmin = await deploy("mocks/Mock1271Admin", wallets.admin, wallets.admin.address);
    const identityRegistry = await deploy(
      "ChioIdentityRegistry",
      wallets.admin,
      wallets.admin.address,
    );
    await expectDeployRevert("root registry zero identity", provider, "ChioRootRegistry", wallets.admin, ethers.ZeroAddress);
    await expectDeployRevert("root registry EOA identity", provider, "ChioRootRegistry", wallets.admin, wallets.admin.address);
    const rootRegistry = await deploy(
      "ChioRootRegistry",
      wallets.admin,
      await identityRegistry.getAddress(),
    );
    const divergentIdentityRegistry = await deploy(
      "ChioIdentityRegistry",
      wallets.admin,
      wallets.admin.address,
    );
    await expectDeployRevert(
      "escrow zero root registry",
      provider,
      "ChioEscrow",
      wallets.admin,
      ethers.ZeroAddress,
      await identityRegistry.getAddress(),
      wallets.admin.address,
    );
    await expectDeployRevert(
      "escrow zero identity registry",
      provider,
      "ChioEscrow",
      wallets.admin,
      await rootRegistry.getAddress(),
      ethers.ZeroAddress,
      wallets.admin.address,
    );
    await expectDeployRevert(
      "escrow EOA root registry",
      provider,
      "ChioEscrow",
      wallets.admin,
      wallets.admin.address,
      await identityRegistry.getAddress(),
      wallets.admin.address,
    );
    await expectDeployRevert(
      "escrow EOA identity registry",
      provider,
      "ChioEscrow",
      wallets.admin,
      await rootRegistry.getAddress(),
      wallets.admin.address,
      wallets.admin.address,
    );
    await expectDeployRevert(
      "escrow divergent identity registry",
      provider,
      "ChioEscrow",
      wallets.admin,
      await rootRegistry.getAddress(),
      await divergentIdentityRegistry.getAddress(),
      wallets.admin.address,
    );
    const escrow = await deploy(
      "ChioEscrow",
      wallets.admin,
      await rootRegistry.getAddress(),
      await identityRegistry.getAddress(),
      wallets.admin.address,
    );
    assert.equal(await escrow.identityRegistry(), await rootRegistry.identityRegistry());
    await expectDeployRevert(
      "bond zero root registry",
      provider,
      "ChioBondVault",
      wallets.admin,
      ethers.ZeroAddress,
      await identityRegistry.getAddress(),
      wallets.admin.address,
    );
    await expectDeployRevert(
      "bond zero identity registry",
      provider,
      "ChioBondVault",
      wallets.admin,
      await rootRegistry.getAddress(),
      ethers.ZeroAddress,
      wallets.admin.address,
    );
    await expectDeployRevert(
      "bond EOA root registry",
      provider,
      "ChioBondVault",
      wallets.admin,
      wallets.admin.address,
      await identityRegistry.getAddress(),
      wallets.admin.address,
    );
    await expectDeployRevert(
      "bond EOA identity registry",
      provider,
      "ChioBondVault",
      wallets.admin,
      await rootRegistry.getAddress(),
      wallets.admin.address,
      wallets.admin.address,
    );
    await expectDeployRevert(
      "bond divergent identity registry",
      provider,
      "ChioBondVault",
      wallets.admin,
      await rootRegistry.getAddress(),
      await divergentIdentityRegistry.getAddress(),
      wallets.admin.address,
    );
    const bondVault = await deploy(
      "ChioBondVault",
      wallets.admin,
      await rootRegistry.getAddress(),
      await identityRegistry.getAddress(),
      wallets.admin.address,
    );
    assert.equal(await bondVault.identityRegistry(), await rootRegistry.identityRegistry());
    const reentrantBondToken = await deploy(
      "mocks/ReentrantBondToken",
      wallets.admin,
      "Reentrant Bond Token",
      "rBOND",
      6,
    );
    const priceResolver = await deploy(
      "ChioPriceResolver",
      wallets.admin,
      wallets.admin.address,
      await sequencerFeed.getAddress(),
    );
    const packageRuntimeCodehashes = readContractPackageRuntimeCodehashes();
    const deployedRuntimeCodehashes = {
      identity_registry: await assertDeployedRuntimeCodehash(
        provider,
        "ChioIdentityRegistry",
        identityRegistry,
        readArtifact("ChioIdentityRegistry"),
        packageRuntimeCodehashes.get("identity_registry"),
      ),
      root_registry: await assertDeployedRuntimeCodehash(
        provider,
        "ChioRootRegistry",
        rootRegistry,
        readArtifact("ChioRootRegistry"),
        packageRuntimeCodehashes.get("root_registry"),
      ),
      escrow: await assertDeployedRuntimeCodehash(
        provider,
        "ChioEscrow",
        escrow,
        readArtifact("ChioEscrow"),
        packageRuntimeCodehashes.get("escrow"),
      ),
      bond_vault: await assertDeployedRuntimeCodehash(
        provider,
        "ChioBondVault",
        bondVault,
        readArtifact("ChioBondVault"),
        packageRuntimeCodehashes.get("bond_vault"),
      ),
      price_resolver: await assertDeployedRuntimeCodehash(
        provider,
        "ChioPriceResolver",
        priceResolver,
        readArtifact("ChioPriceResolver"),
        packageRuntimeCodehashes.get("price_resolver"),
      ),
    };
    checks.push({
      id: "deployment.runtime_codehashes",
      outcome: "pass",
      note: "Deployed local-devnet bytecode hashes match compiled artifacts and the reviewed contract package.",
    });
    checks.push({
      id: "deployment.constructor_wiring",
      outcome: "pass",
      note: "Root registry, escrow, and bond vault reject zero or non-contract registry addresses at construction.",
    });

    logStep("registering identity bindings");
    const operatorBindingProof = await operatorBindingSignature(
      chainId,
      await identityRegistry.getAddress(),
      wallets.admin.privateKey,
      wallets.operator.address,
      operatorEdKeyHash,
      wallets.operator.address,
    );
    gasEstimates.register_operator = (
      await identityRegistry.registerOperator.estimateGas(
        wallets.operator.address,
        operatorEdKeyHash,
        wallets.operator.address,
        operatorBindingProof,
      )
    ).toString();
    await (
      await identityRegistry.registerOperator(
        wallets.operator.address,
        operatorEdKeyHash,
        wallets.operator.address,
        operatorBindingProof,
      )
    ).wait();
    const operatorRecord = await identityRegistry.getOperator(wallets.operator.address);
    const operatorEpoch = operatorRecord.operatorEpoch;
    assert.notEqual(operatorEpoch, 0n);
    await expectRevert("identity zero operator key hash", async () => {
      await identityRegistry.registerOperator.staticCall(
        deterministicAddress(0x70),
        ZERO_BYTES32,
        wallets.operator.address,
        ethers.toUtf8Bytes("binding:zero-operator-key"),
      );
    });
    await expectRevertSelector(
      "identity operator binding proof",
      async () => {
        await identityRegistry.registerOperator.staticCall(
          deterministicAddress(0x72),
          toBytes32Label("chio-invalid-operator-binding"),
          wallets.operator.address,
          ethers.toUtf8Bytes("binding:invalid-operator"),
        );
      },
      INVALID_SIGNATURE_SELECTOR,
    );
    checks.push({
      id: "identity.operator_registration",
      outcome: "pass",
      note: "Identity registry bound the operator settlement key to the Chio Ed25519 key hash.",
    });

    const contractAdminRegistry = await deploy(
      "ChioIdentityRegistry",
      wallets.admin,
      await contractAdmin.getAddress(),
    );
    const contractAdminOperatorKeyHash = toBytes32Label("chio-contract-admin-operator-key");
    const contractAdminOperatorBindingProof = await operatorBindingSignature(
      chainId,
      await contractAdminRegistry.getAddress(),
      wallets.admin.privateKey,
      wallets.operator.address,
      contractAdminOperatorKeyHash,
      wallets.operator.address,
    );
    const registerContractAdminOperatorCall = contractAdminRegistry.interface.encodeFunctionData(
      "registerOperator",
      [
        wallets.operator.address,
        contractAdminOperatorKeyHash,
        wallets.operator.address,
        contractAdminOperatorBindingProof,
      ],
    );
    await (
      await contractAdmin.execute(
        await contractAdminRegistry.getAddress(),
        registerContractAdminOperatorCall,
      )
    ).wait();
    const contractAdminEntityId = toBytes32Label("chio-contract-admin-entity");
    const contractAdminEntitySignature = await new ethers.Wallet(wallets.admin.privateKey).signTypedData(
      entityBindingDomain(chainId, await contractAdminRegistry.getAddress()),
      ENTITY_BINDING_TYPES,
      {
        chioEntityId: contractAdminEntityId,
        settlementAddress: wallets.beneficiary.address,
        operator: wallets.operator.address,
      },
    );
    await (
      await contractAdminRegistry
        .connect(wallets.operator)
        .registerEntity(
          contractAdminEntityId,
          wallets.beneficiary.address,
          contractAdminEntitySignature,
        )
    ).wait();
    assert.equal(await contractAdminRegistry.getEntityAddress(contractAdminEntityId), wallets.beneficiary.address);
    checks.push({
      id: "identity.contract_admin_entity_registration",
      outcome: "pass",
      note: "Entity binding authorization accepts a standards-compatible contract admin signature.",
    });

    const lifecycleOperator = deterministicAddress(0x71);
    const lifecycleOperatorKeyHash = toBytes32Label("chio-lifecycle-operator-key");
    const replacementOperatorKeyHash = toBytes32Label("chio-lifecycle-replacement-key");
    const lifecycleOperatorBindingProof = await operatorBindingSignature(
      chainId,
      await identityRegistry.getAddress(),
      wallets.admin.privateKey,
      lifecycleOperator,
      lifecycleOperatorKeyHash,
      wallets.principal.address,
    );
    await (
      await identityRegistry.registerOperator(
        lifecycleOperator,
        lifecycleOperatorKeyHash,
        wallets.principal.address,
        lifecycleOperatorBindingProof,
      )
    ).wait();
    const lifecycleRecordBefore = await identityRegistry.getOperator(lifecycleOperator);
    await (await identityRegistry.deactivateOperator(lifecycleOperator)).wait();
    const replacementOperatorBindingProof = await operatorBindingSignature(
      chainId,
      await identityRegistry.getAddress(),
      wallets.admin.privateKey,
      lifecycleOperator,
      replacementOperatorKeyHash,
      wallets.outsider.address,
    );
    await (
      await identityRegistry.registerOperator(
        lifecycleOperator,
        replacementOperatorKeyHash,
        wallets.outsider.address,
        replacementOperatorBindingProof,
      )
    ).wait();
    const lifecycleRecordAfter = await identityRegistry.getOperator(lifecycleOperator);
    assert.equal(lifecycleRecordAfter.edKeyHash, replacementOperatorKeyHash);
    assert.equal(lifecycleRecordAfter.settlementKey, wallets.outsider.address);
    assert.equal(lifecycleRecordAfter.registeredAt >= lifecycleRecordBefore.registeredAt, true);
    assert.equal(lifecycleRecordAfter.active, true);
    checks.push({
      id: "identity.inactive_operator_reregistration_replaces_keys",
      outcome: "pass",
      note: "Inactive operator re-registration replaces reviewed key material and returns the record to active.",
    });

    const reentrantOperatorBindingProof = await operatorBindingSignature(
      chainId,
      await identityRegistry.getAddress(),
      wallets.admin.privateKey,
      await reentrantBondToken.getAddress(),
      reentrantOperatorKeyHash,
      await reentrantBondToken.getAddress(),
    );
    await (
      await identityRegistry.registerOperator(
        await reentrantBondToken.getAddress(),
        reentrantOperatorKeyHash,
        await reentrantBondToken.getAddress(),
        reentrantOperatorBindingProof,
      )
    ).wait();

    await (await identityRegistry.transferAdmin(wallets.outsider.address)).wait();
    assert.equal(await identityRegistry.admin(), wallets.admin.address);
    assert.equal(await identityRegistry.pendingAdmin(), wallets.outsider.address);
    await expectRevert("identity admin accept caller", async () => {
      await identityRegistry.acceptAdmin.staticCall();
    });
    await (await identityRegistry.connect(wallets.outsider).acceptAdmin()).wait();
    assert.equal(await identityRegistry.admin(), wallets.outsider.address);
    assert.equal(await identityRegistry.pendingAdmin(), ethers.ZeroAddress);
    await (await identityRegistry.connect(wallets.outsider).transferAdmin(wallets.admin.address)).wait();
    await (await identityRegistry.acceptAdmin()).wait();
    assert.equal(await identityRegistry.admin(), wallets.admin.address);
    checks.push({
      id: "identity.admin_handoff",
      outcome: "pass",
      note: "Identity registry admin handoff requires the nominated account to accept.",
    });

    await expectRevert("escrow token allowlist admin", async () => {
      await escrow
        .connect(wallets.outsider)
        .setTokenAllowed.staticCall(await mockUsdc.getAddress(), true);
    });
    await expectRevert("bond token allowlist admin", async () => {
      await bondVault
        .connect(wallets.outsider)
        .setTokenAllowed.staticCall(await mockUsdc.getAddress(), true);
    });
    await (await escrow.setTokenAllowed(await mockUsdc.getAddress(), true)).wait();
    await (await escrow.setTokenAllowed(await noReturnToken.getAddress(), true)).wait();
    await (await bondVault.setTokenAllowed(await mockUsdc.getAddress(), true)).wait();
    await (await bondVault.setTokenAllowed(await reentrantBondToken.getAddress(), true)).wait();
    assert.equal(await escrow.tokenAllowed(await mockUsdc.getAddress()), true);
    assert.equal(await bondVault.tokenAllowed(await mockUsdc.getAddress()), true);
    assert.equal(typeof escrow.transferAdmin, "function");
    assert.equal(typeof escrow.acceptAdmin, "function");
    assert.equal(typeof bondVault.transferAdmin, "function");
    assert.equal(typeof bondVault.acceptAdmin, "function");
    await expectRevert("escrow transfer zero admin", async () => {
      await escrow.transferAdmin.staticCall(ethers.ZeroAddress);
    });
    await (await escrow.transferAdmin(wallets.outsider.address)).wait();
    assert.equal(await escrow.admin(), wallets.admin.address);
    assert.equal(await escrow.pendingAdmin(), wallets.outsider.address);
    await expectRevert("escrow admin accept caller", async () => {
      await escrow.acceptAdmin.staticCall();
    });
    await (await escrow.connect(wallets.outsider).acceptAdmin()).wait();
    assert.equal(await escrow.admin(), wallets.outsider.address);
    assert.equal(await escrow.pendingAdmin(), ethers.ZeroAddress);
    await expectRevert("escrow old admin allowlist", async () => {
      await escrow.setTokenAllowed.staticCall(await feeToken.getAddress(), true);
    });
    await (await escrow.connect(wallets.outsider).transferAdmin(wallets.admin.address)).wait();
    await (await escrow.acceptAdmin()).wait();
    assert.equal(await escrow.admin(), wallets.admin.address);
    await expectRevert("bond transfer zero admin", async () => {
      await bondVault.transferAdmin.staticCall(ethers.ZeroAddress);
    });
    await (await bondVault.transferAdmin(wallets.outsider.address)).wait();
    assert.equal(await bondVault.admin(), wallets.admin.address);
    assert.equal(await bondVault.pendingAdmin(), wallets.outsider.address);
    await expectRevert("bond admin accept caller", async () => {
      await bondVault.acceptAdmin.staticCall();
    });
    await (await bondVault.connect(wallets.outsider).acceptAdmin()).wait();
    assert.equal(await bondVault.admin(), wallets.outsider.address);
    assert.equal(await bondVault.pendingAdmin(), ethers.ZeroAddress);
    await expectRevert("bond old admin allowlist", async () => {
      await bondVault.setTokenAllowed.staticCall(await feeToken.getAddress(), true);
    });
    await (await bondVault.connect(wallets.outsider).transferAdmin(wallets.admin.address)).wait();
    await (await bondVault.acceptAdmin()).wait();
    assert.equal(await bondVault.admin(), wallets.admin.address);
    assert.equal(typeof escrow.setPaused, "function");
    assert.equal(typeof bondVault.setPaused, "function");
    await expectRevert("escrow pause admin", async () => {
      await escrow.connect(wallets.outsider).setPaused.staticCall(true);
    });
    await expectRevert("bond pause admin", async () => {
      await bondVault.connect(wallets.outsider).setPaused.staticCall(true);
    });
    const pausedEscrowTerms = {
      capabilityId: toBytes32Label("capability:paused"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 50_000n,
      deadline: BigInt(now + 7200),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    const escrowPausedTx = await escrow.setPaused(true);
    const escrowPausedReceipt = await waitForReceipt(provider, escrowPausedTx);
    const escrowPausedEvent = await findContractEvent(escrowPausedReceipt, escrow, "PausedSet");
    assert.equal(escrowPausedEvent.args.admin, wallets.admin.address);
    assert.equal(escrowPausedEvent.args.paused, true);
    await expectRevertSelector(
      "paused escrow create",
      async () => {
        await escrow.connect(wallets.depositor).createEscrow.staticCall(pausedEscrowTerms);
      },
      PAUSED_SELECTOR,
    );
    await expectRevertSelector(
      "paused escrow permit create",
      async () => {
        await escrow
          .connect(wallets.depositor)
          .createEscrowWithPermit.staticCall(pausedEscrowTerms, BigInt(now + 3600), 27, ZERO_BYTES32, ZERO_BYTES32);
      },
      PAUSED_SELECTOR,
    );
    const escrowUnpausedTx = await escrow.setPaused(false);
    const escrowUnpausedReceipt = await waitForReceipt(provider, escrowUnpausedTx);
    const escrowUnpausedEvent = await findContractEvent(escrowUnpausedReceipt, escrow, "PausedSet");
    assert.equal(escrowUnpausedEvent.args.admin, wallets.admin.address);
    assert.equal(escrowUnpausedEvent.args.paused, false);
    const pausedBondTerms = {
      bondId: toBytes32Label("bond:paused"),
      facilityId: toBytes32Label("facility:paused"),
      principal: wallets.principal.address,
      token: await mockUsdc.getAddress(),
      collateralAmount: 50_000n,
      reserveRequirementAmount: 12_500n,
      expiresAt: BigInt(now + 7200),
      reserveRequirementRatioBps: 2500,
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    const bondPausedTx = await bondVault.setPaused(true);
    const bondPausedReceipt = await waitForReceipt(provider, bondPausedTx);
    const bondPausedEvent = await findContractEvent(bondPausedReceipt, bondVault, "PausedSet");
    assert.equal(bondPausedEvent.args.admin, wallets.admin.address);
    assert.equal(bondPausedEvent.args.paused, true);
    await expectRevertSelector(
      "paused bond lock",
      async () => {
        await bondVault.connect(wallets.principal).lockBond.staticCall(pausedBondTerms);
      },
      PAUSED_SELECTOR,
    );
    const bondUnpausedTx = await bondVault.setPaused(false);
    const bondUnpausedReceipt = await waitForReceipt(provider, bondUnpausedTx);
    const bondUnpausedEvent = await findContractEvent(bondUnpausedReceipt, bondVault, "PausedSet");
    assert.equal(bondUnpausedEvent.args.admin, wallets.admin.address);
    assert.equal(bondUnpausedEvent.args.paused, false);

    const identityRegistryAddress = await identityRegistry.getAddress();
    const entityBindingDomainValue = entityBindingDomain(chainId, identityRegistryAddress);
    const unsignedEntityId = toBytes32Label("chio-unsigned-entity");
    await expectRevert("entity unsigned binding", async () => {
      await identityRegistry
        .connect(wallets.operator)
        .registerEntity.staticCall(
          unsignedEntityId,
          wallets.beneficiary.address,
          ethers.toUtf8Bytes("binding:unsigned"),
        );
    });
    const zeroEntityBindingSignature = await new ethers.Wallet(wallets.admin.privateKey).signTypedData(
      entityBindingDomainValue,
      ENTITY_BINDING_TYPES,
      {
        chioEntityId: ZERO_BYTES32,
        settlementAddress: wallets.beneficiary.address,
        operator: wallets.operator.address,
      },
    );
    await expectRevert("entity zero id", async () => {
      await identityRegistry
        .connect(wallets.operator)
        .registerEntity.staticCall(
          ZERO_BYTES32,
          wallets.beneficiary.address,
          zeroEntityBindingSignature,
        );
    });
    const beneficiaryEntityBindingSignature = await new ethers.Wallet(wallets.admin.privateKey).signTypedData(
      entityBindingDomainValue,
      ENTITY_BINDING_TYPES,
      {
        chioEntityId: beneficiaryEntityId,
        settlementAddress: wallets.beneficiary.address,
        operator: wallets.operator.address,
      },
    );
    await (
      await identityRegistry
        .connect(wallets.operator)
        .registerEntity(
          beneficiaryEntityId,
          wallets.beneficiary.address,
          beneficiaryEntityBindingSignature,
        )
    ).wait();
    assert.equal(await identityRegistry.getEntityAddress(beneficiaryEntityId), wallets.beneficiary.address);
    await expectRevert("duplicate entity binding", async () => {
      await identityRegistry
        .connect(wallets.operator)
        .registerEntity.staticCall(
          beneficiaryEntityId,
          wallets.beneficiary.address,
          beneficiaryEntityBindingSignature,
        );
    });
    assert.equal(typeof identityRegistry.deactivateEntity, "function");
    assert.equal(typeof identityRegistry.reassignEntity, "function");
    await expectRevert("entity deactivate caller", async () => {
      await identityRegistry.connect(wallets.operator).deactivateEntity.staticCall(beneficiaryEntityId);
    });
    await (await identityRegistry.deactivateEntity(beneficiaryEntityId)).wait();
    await expectRevert("inactive entity resolution", async () => {
      await identityRegistry.getEntityAddress.staticCall(beneficiaryEntityId);
    });
    const reassignedEntitySignature = await new ethers.Wallet(wallets.admin.privateKey).signTypedData(
      entityBindingDomainValue,
      ENTITY_BINDING_TYPES,
      {
        chioEntityId: beneficiaryEntityId,
        settlementAddress: wallets.depositor.address,
        operator: wallets.operator.address,
      },
    );
    await (
      await identityRegistry.reassignEntity(
        beneficiaryEntityId,
        wallets.depositor.address,
        wallets.operator.address,
        reassignedEntitySignature,
      )
    ).wait();
    assert.equal(await identityRegistry.getEntityAddress(beneficiaryEntityId), wallets.depositor.address);
    checks.push({
      id: "identity.entity_registration",
      outcome: "pass",
      note: "Entity bindings require current-admin authorization and can be deactivated or reassigned by the admin.",
    });

    logStep("authorizing and exercising root publication");
    const delegateWindowBase = await latestTimestamp(provider);
    const shortLivedDelegateExpiry = BigInt(delegateWindowBase + 60);
    const shortLivedDelegates = [
      "0x00000000000000000000000000000000000000D1",
      "0x00000000000000000000000000000000000000D2",
      "0x00000000000000000000000000000000000000D3",
    ].map(ethers.getAddress);
    const replacementDelegate = ethers.getAddress("0x00000000000000000000000000000000000000D4");
    for (const delegateAddress of shortLivedDelegates) {
      await (
        await rootRegistry
          .connect(wallets.operator)
          .registerDelegate(delegateAddress, shortLivedDelegateExpiry)
      ).wait();
    }
    await expectRevert("active delegate cap", async () => {
      await rootRegistry
        .connect(wallets.operator)
        .registerDelegate.staticCall(replacementDelegate, BigInt(delegateWindowBase + 3600));
    });
    await mineAt(provider, Number(shortLivedDelegateExpiry));
    assert.equal(
      await rootRegistry.isAuthorizedPublisher(wallets.operator.address, shortLivedDelegates[0]),
      false,
    );
    await (
      await rootRegistry
        .connect(wallets.operator)
        .registerDelegate(replacementDelegate, BigInt(delegateWindowBase + 3600), {
          gasLimit: 250_000n,
        })
    ).wait();
    checks.push({
      id: "anchor.expired_delegate_slots",
      outcome: "pass",
      note: "Expired delegates do not consume the active delegate cap.",
    });

    const delegateExpiry = BigInt(now + 3600);
    gasEstimates.register_delegate = (
      await rootRegistry
        .connect(wallets.operator)
        .registerDelegate.estimateGas(wallets.delegate.address, delegateExpiry)
    ).toString();
    await (
      await rootRegistry
        .connect(wallets.operator)
        .registerDelegate(wallets.delegate.address, delegateExpiry)
    ).wait();
    checks.push({
      id: "anchor.delegate_registration",
      outcome: "pass",
      note: "Root registry accepted a bounded delegate publisher for the operator.",
    });

    await expectRevert("unauthorized root publication", async () => {
      await rootRegistry
        .connect(wallets.outsider)
        .publishRoot(wallets.operator.address, toBytes32Label("unauthorized-root"), 1, 1, 1, 1, operatorEdKeyHash);
    });
    await expectRevertSelector(
      "zero operator key root publication",
      async () => {
        await rootRegistry
          .connect(wallets.operator)
          .publishRoot.staticCall(
            wallets.operator.address,
            toBytes32Label("zero-key-root"),
            1,
            1,
            1,
            1,
            ZERO_BYTES32,
          );
      },
      OPERATOR_KEY_HASH_MISMATCH_SELECTOR,
    );
    await expectRevert("missing latest root", async () => {
      await rootRegistry.getLatestRoot(wallets.outsider.address);
    });
    checks.push({
      id: "anchor.unauthorized_publish_denied",
      outcome: "pass",
      note: "Unauthorized publishers revert fail closed.",
    });

    const operatorRoot = toBytes32Label("checkpoint-root-operator");
    gasEstimates.publish_root_operator = (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot.estimateGas(
          wallets.operator.address,
          operatorRoot,
          1,
          1,
          1,
          1,
          operatorEdKeyHash,
        )
    ).toString();
    const operatorRootReceipt = await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, operatorRoot, 1, 1, 1, 1, operatorEdKeyHash)
    ).wait();
    const operatorRootEvent = await findContractEvent(operatorRootReceipt, rootRegistry, "RootPublished");
    assert.equal(operatorRootEvent.args.operatorEpoch, operatorEpoch);
    assert.equal((await rootRegistry.getRoot(wallets.operator.address, 1)).operatorEpoch, operatorEpoch);

    const delegateReceiptHash = toBytes32Label("delegate-proof-leaf");
    gasEstimates.publish_root_delegate = (
      await rootRegistry
        .connect(wallets.delegate)
        .publishRoot.estimateGas(
          wallets.operator.address,
          delegateReceiptHash,
          2,
          2,
          2,
          1,
          operatorEdKeyHash,
        )
    ).toString();
    await (
      await rootRegistry
        .connect(wallets.delegate)
        .publishRoot(
          wallets.operator.address,
          delegateReceiptHash,
          2,
          2,
          2,
          1,
          operatorEdKeyHash,
        )
    ).wait();
    checks.push({
      id: "anchor.delegate_publish",
      outcome: "pass",
      note: "Authorized delegate published a root against the operator namespace with canonical publisher traceability.",
    });

    const proofLeafA = toBytes32Label("proof-leaf-a");
    const proofLeafB = toBytes32Label("proof-leaf-b");
    const twoLeafRoot = rfc6962Node(proofLeafA, proofLeafB);
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, twoLeafRoot, 3, 3, 4, 2, operatorEdKeyHash)
    ).wait();
    await expectRevert("legacy detailed verifier disabled", async () => {
      await rootRegistry.verifyInclusionDetailed(
        { auditPath: [proofLeafB], leafIndex: 0, treeSize: 2 },
        twoLeafRoot,
        proofLeafA,
        wallets.operator.address,
      );
    });
    assert.equal(
      await rootRegistry.verifyInclusionDetailedForKeyHash(
        { auditPath: [proofLeafB], leafIndex: 0, treeSize: 2 },
        twoLeafRoot,
        proofLeafA,
        wallets.operator.address,
        operatorEdKeyHash,
      ),
      true,
    );
    assert.equal(
      await rootRegistry.verifyInclusionDetailedForKeyHash(
        { auditPath: [], leafIndex: 0, treeSize: 1 },
        twoLeafRoot,
        twoLeafRoot,
        wallets.operator.address,
        operatorEdKeyHash,
      ),
      false,
    );
    await expectRevert("root checkpoint gap", async () => {
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot.staticCall(
          wallets.operator.address,
          toBytes32Label("checkpoint-gap-root"),
          5,
          5,
          5,
          1,
          operatorEdKeyHash,
        );
    });
    await expectRevert("root batch gap", async () => {
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot.staticCall(
          wallets.operator.address,
          toBytes32Label("batch-gap-root"),
          4,
          6,
          6,
          1,
          operatorEdKeyHash,
        );
    });
    await expectRevert("root batch overlap", async () => {
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot.staticCall(
          wallets.operator.address,
          toBytes32Label("batch-overlap-root"),
          4,
          4,
          4,
          1,
          operatorEdKeyHash,
        );
    });
    await expectRevertSelector(
      "duplicate root publication",
      async () => {
        await rootRegistry
          .connect(wallets.operator)
          .publishRoot.staticCall(
            wallets.operator.address,
            operatorRoot,
            4,
            5,
            5,
            1,
            operatorEdKeyHash,
          );
      },
      INVALID_MERKLE_ROOT_SELECTOR,
    );
    const terminalBatchEndSeq = (1n << 64n) - 1n;
    await expectRevertSelector(
      "terminal batch end root publication",
      async () => {
        await rootRegistry
          .connect(wallets.operator)
          .publishRoot.staticCall(
            wallets.operator.address,
            toBytes32Label("terminal-batch-end-root"),
            4,
            5,
            terminalBatchEndSeq,
            1,
            operatorEdKeyHash,
          );
      },
      INVALID_BATCH_RANGE_SELECTOR,
    );
    await expectRevertSelector(
      "delegate terminal batch end root publication",
      async () => {
        await rootRegistry
          .connect(wallets.delegate)
          .publishRoot.staticCall(
            wallets.operator.address,
            toBytes32Label("delegate-terminal-batch-end-root"),
            4,
            5,
            terminalBatchEndSeq,
            1,
            operatorEdKeyHash,
          );
      },
      INVALID_BATCH_RANGE_SELECTOR,
    );
    const wideRangeSingleLeaf = toBytes32Label("wide-range-single-leaf-root");
    await rootRegistry
      .connect(wallets.operator)
      .publishRoot.staticCall(
        wallets.operator.address,
        wideRangeSingleLeaf,
        4,
        5,
        104,
        1,
        operatorEdKeyHash,
      );
    const excessiveBatchCount = 33;
    await expectRevert("root batch cap", async () => {
      await rootRegistry
        .connect(wallets.operator)
        .publishRootBatch.staticCall(
          wallets.operator.address,
          Array.from({ length: excessiveBatchCount }, (_, index) => toBytes32Label(`batch-root:${index}`)),
          Array.from({ length: excessiveBatchCount }, (_, index) => 4 + index),
          Array.from({ length: excessiveBatchCount }, (_, index) => 4 + index),
          Array.from({ length: excessiveBatchCount }, (_, index) => 4 + index),
          Array.from({ length: excessiveBatchCount }, () => 1),
          operatorEdKeyHash,
        );
    });
    await expectRevert("missing checkpoint root", async () => {
      await rootRegistry.getRoot(wallets.operator.address, 4);
    });
    checks.push({
      id: "anchor.tree_size_bound_proof",
      outcome: "pass",
      note: "Root registry rejects proof metadata that does not match the published root geometry.",
    });

    await (await rootRegistry.connect(wallets.operator).revokeDelegate(wallets.delegate.address)).wait();
    await expectRevert("revoked delegate publication", async () => {
      await rootRegistry
        .connect(wallets.delegate)
        .publishRoot(
          wallets.operator.address,
          toBytes32Label("revoked-root"),
          3,
          3,
          3,
          1,
          operatorEdKeyHash,
        );
    });
    checks.push({
      id: "anchor.delegate_revocation",
      outcome: "pass",
      note: "Revoked delegates can no longer publish roots.",
    });

    logStep("configuring token and price feeds");
    await (await mockUsdc.mint(wallets.depositor.address, 5_000_000n * USDC_UNITS)).wait();
    await (await mockUsdc.mint(wallets.principal.address, 5_000_000n * USDC_UNITS)).wait();
    await (await noReturnToken.mint(wallets.depositor.address, 500_000n)).wait();
    await (await feeToken.mint(wallets.depositor.address, 500_000n)).wait();
    await (await feeToken.mint(wallets.principal.address, 500_000n)).wait();
    await (await reentrantBondToken.mint(wallets.principal.address, 1_000_000n)).wait();

    const priceResolverAdmin = priceResolver;
    const priceResolverOutsider = priceResolver.connect(outsiderRpcSigner);
    assert.equal(typeof priceResolver.transferAdmin, "function");
    assert.equal(typeof priceResolver.acceptAdmin, "function");
    await expectRevert("price admin zero handoff", async () => {
      await priceResolverAdmin.transferAdmin.staticCall(ethers.ZeroAddress);
    });
    assert.equal(await priceResolver.pendingAdmin(), ethers.ZeroAddress);
    const priceAdminStartReceipt = await (
      await priceResolverAdmin.transferAdmin(wallets.outsider.address)
    ).wait();
    const priceAdminStartEvent = await findContractEvent(
      priceAdminStartReceipt,
      priceResolver,
      "AdminTransferStarted",
    );
    assert.equal(priceAdminStartEvent.args.currentAdmin, wallets.admin.address);
    assert.equal(priceAdminStartEvent.args.pendingAdmin, wallets.outsider.address);
    assert.equal(await priceResolver.admin(), wallets.admin.address);
    assert.equal(await priceResolver.pendingAdmin(), wallets.outsider.address);
    await expectRevert("price admin accept caller", async () => {
      await priceResolverAdmin.acceptAdmin.staticCall();
    });
    const priceAdminAcceptReceipt = await (
      await priceResolverOutsider.acceptAdmin()
    ).wait();
    const priceAdminAcceptEvent = await findContractEvent(
      priceAdminAcceptReceipt,
      priceResolver,
      "AdminTransferred",
    );
    assert.equal(priceAdminAcceptEvent.args.previousAdmin, wallets.admin.address);
    assert.equal(priceAdminAcceptEvent.args.newAdmin, wallets.outsider.address);
    assert.equal(await priceResolver.admin(), wallets.outsider.address);
    assert.equal(await priceResolver.pendingAdmin(), ethers.ZeroAddress);
    await expectRevert("price old admin handoff", async () => {
      await priceResolverAdmin.transferAdmin.staticCall(wallets.depositor.address);
    });
    await expectRevert("price old admin register feed", async () => {
      await priceResolverAdmin.registerFeed.staticCall(
        priceBase,
        priceQuote,
        await ethUsdFeed.getAddress(),
        3600,
      );
    });
    await (await priceResolverOutsider.transferAdmin(wallets.admin.address)).wait();
    await (await priceResolverAdmin.acceptAdmin()).wait();
    assert.equal(await priceResolver.admin(), wallets.admin.address);
    checks.push({
      id: "oracle.admin_handoff",
      outcome: "pass",
      note: "Price resolver admin handoff requires the nominated account to accept.",
    });

    await expectRevert("price zero staleness", async () => {
      await priceResolver.registerFeed.staticCall(
        priceBase,
        priceQuote,
        await ethUsdFeed.getAddress(),
        0,
      );
    });
    const maxFeedStaleness = await priceResolver.MAX_FEED_STALENESS_SECONDS();
    await expectRevert("price excessive staleness", async () => {
      await priceResolver.registerFeed.staticCall(
        priceBase,
        priceQuote,
        await ethUsdFeed.getAddress(),
        maxFeedStaleness + 1n,
      );
    });
    gasEstimates.register_feed = (
      await priceResolver.registerFeed.estimateGas(
        priceBase,
        priceQuote,
        await ethUsdFeed.getAddress(),
        3600,
      )
    ).toString();
    await (
      await priceResolver.registerFeed(
        priceBase,
        priceQuote,
        await ethUsdFeed.getAddress(),
        3600,
      )
    ).wait();

    const oracleWindowBase = await latestTimestamp(provider);
    await (
      await sequencerFeed.setRoundData(
        1,
        0n,
        BigInt(oracleWindowBase - 7200),
        BigInt(oracleWindowBase - 7200),
        1,
      )
    ).wait();

    gasEstimates.price_read = (
      await priceResolver.getPrice.estimateGas(priceBase, priceQuote)
    ).toString();
    const [price, decimals, updatedAt] = await priceResolver.getPrice(priceBase, priceQuote);
    assert.equal(price.toString(), (3000n * 10n ** 8n).toString());
    assert.equal(Number(decimals), 8);
    assert.ok(updatedAt > 0n);
    checks.push({
      id: "oracle.price_read",
      outcome: "pass",
      note: "Price resolver returned the configured feed value under healthy sequencer conditions.",
    });

    await (
      await ethUsdFeed.setRoundData(2, 0n, BigInt(oracleWindowBase), BigInt(oracleWindowBase), 2)
    ).wait();
    await expectRevert("non-positive price", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    });
    await (
      await ethUsdFeed.setRoundData(3, 3000n * 10n ** 8n, BigInt(oracleWindowBase), 0n, 3)
    ).wait();
    await expectRevert("zero price timestamp", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    });
    await (
      await ethUsdFeed.setRoundData(
        4,
        3000n * 10n ** 8n,
        BigInt(oracleWindowBase + 60),
        BigInt(oracleWindowBase + 60),
        4,
      )
    ).wait();
    await expectRevert("future price timestamp", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    });
    await (
      await ethUsdFeed.setRoundData(
        10,
        3000n * 10n ** 8n,
        BigInt(oracleWindowBase),
        BigInt(oracleWindowBase),
        9,
      )
    ).wait();
    await expectRevertSelector("price answered in stale round", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    }, INVALID_ROUND_SELECTOR);
    await (
      await ethUsdFeed.setRoundData(
        0,
        3000n * 10n ** 8n,
        BigInt(oracleWindowBase),
        BigInt(oracleWindowBase),
        0,
      )
    ).wait();
    await expectRevertSelector("zero price round", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    }, INVALID_ROUND_SELECTOR);
    await (
      await ethUsdFeed.setRoundData(
        11,
        3000n * 10n ** 8n,
        BigInt(oracleWindowBase + 30),
        BigInt(oracleWindowBase),
        11,
      )
    ).wait();
    await expectRevertSelector("price started after update", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    }, INVALID_TIMESTAMP_SELECTOR);
    await (await ethUsdFeed.setAnswer(3000n * 10n ** 8n)).wait();

    await (
      await ethUsdFeed.setRoundData(5, 3000n * 10n ** 8n, BigInt(now - 7200), BigInt(now - 7200), 5)
    ).wait();
    await expectRevert("stale price", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    });
    await (await ethUsdFeed.setAnswer(3000n * 10n ** 8n)).wait();
    await (
      await sequencerFeed.setRoundData(2, 1n, BigInt(now), BigInt(now), 2)
    ).wait();
    await expectRevert("sequencer down", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    });
    const sequencerRecoveredAt = await latestTimestamp(provider);
    await (
      await sequencerFeed.setRoundData(3, 0n, 0n, BigInt(sequencerRecoveredAt), 3)
    ).wait();
    await expectRevertSelector("zero sequencer timestamp", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    }, INVALID_TIMESTAMP_SELECTOR);
    await (
      await sequencerFeed.setRoundData(
        4,
        0n,
        BigInt(sequencerRecoveredAt + 60),
        BigInt(sequencerRecoveredAt + 60),
        4,
      )
    ).wait();
    await expectRevertSelector("future sequencer timestamp", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    }, INVALID_TIMESTAMP_SELECTOR);
    await (
      await sequencerFeed.setRoundData(
        10,
        0n,
        BigInt(sequencerRecoveredAt - 7200),
        BigInt(sequencerRecoveredAt - 7200),
        9,
      )
    ).wait();
    await expectRevertSelector("sequencer answered in stale round", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    }, INVALID_ROUND_SELECTOR);
    await (
      await sequencerFeed.setRoundData(
        0,
        0n,
        BigInt(sequencerRecoveredAt - 7200),
        BigInt(sequencerRecoveredAt - 7200),
        0,
      )
    ).wait();
    await expectRevertSelector("zero sequencer round", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    }, INVALID_ROUND_SELECTOR);
    await (
      await sequencerFeed.setRoundData(
        11,
        0n,
        BigInt(sequencerRecoveredAt - 7000),
        BigInt(sequencerRecoveredAt - 7200),
        11,
      )
    ).wait();
    await expectRevertSelector("sequencer started after update", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    }, INVALID_TIMESTAMP_SELECTOR);
    await (
      await sequencerFeed.setRoundData(
        5,
        0n,
        BigInt(sequencerRecoveredAt),
        BigInt(sequencerRecoveredAt),
        5,
      )
    ).wait();
    await expectRevert("sequencer grace period", async () => {
      await priceResolver.getPrice(priceBase, priceQuote);
    });
    await (
      await sequencerFeed.setRoundData(
        6,
        0n,
        BigInt(sequencerRecoveredAt - 7200),
        BigInt(sequencerRecoveredAt - 7200),
        6,
      )
    ).wait();
    checks.push({
      id: "oracle.fail_closed",
      outcome: "pass",
      note: "Price resolver rejects invalid feeds, stale feeds, stale round metadata, zero or future sequencer timestamps, sequencer downtime, and sequencer grace-period reads.",
    });

    const oneLeafProof = { auditPath: [], leafIndex: 0, treeSize: 1 };
    const rotatingOperatorKeyA = toBytes32Label("chio-rotating-operator-key-a");
    const rotatingOperatorKeyB = toBytes32Label("chio-rotating-operator-key-b");
    logStep("escrow: exercising rotated-key publication denial");
    const rotatingOperatorBindingProofA = await operatorBindingSignature(
      chainId,
      await identityRegistry.getAddress(),
      wallets.admin.privateKey,
      wallets.rotatingOperator.address,
      rotatingOperatorKeyA,
      wallets.rotatingOperator.address,
    );
    await (
      await identityRegistry.registerOperator(
        wallets.rotatingOperator.address,
        rotatingOperatorKeyA,
        wallets.rotatingOperator.address,
        rotatingOperatorBindingProofA,
      )
    ).wait();
    const rotatingDelegateExpiry = BigInt(now + 3600);
    await (
      await rootRegistry
        .connect(wallets.rotatingOperator)
        .registerDelegate(wallets.delegate.address, rotatingDelegateExpiry)
    ).wait();
    assert.equal(
      await rootRegistry.isAuthorizedPublisherForKeyHash(
        wallets.rotatingOperator.address,
        wallets.delegate.address,
        rotatingOperatorKeyA,
      ),
      true,
    );
    const rotatedEscrowTerms = {
      capabilityId: toBytes32Label("capability:rotated-key"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 100_000n,
      deadline: BigInt(now + 7200),
      operator: wallets.rotatingOperator.address,
      operatorKeyHash: rotatingOperatorKeyB,
    };
    const rotatedEscrowId = await escrow
      .connect(wallets.depositor)
      .deriveEscrowId(rotatedEscrowTerms);
    const rotatedReceiptHash = toBytes32Label("rotated-key-escrow-receipt");
    const rotatedLeaf = escrowProofLeaf(
      chainId,
      await escrow.getAddress(),
      rotatedEscrowId,
      rotatedEscrowTerms.token,
      rotatedEscrowTerms.beneficiary,
      rotatedEscrowTerms.operatorKeyHash,
      rotatedReceiptHash,
      rotatedEscrowTerms.maxAmount,
      false,
    );
    const rotatedBondTerms = {
      bondId: toBytes32Label("bond:rotated-key"),
      facilityId: toBytes32Label("facility:rotated-key"),
      principal: wallets.principal.address,
      token: await mockUsdc.getAddress(),
      collateralAmount: 100_000n,
      reserveRequirementAmount: 25_000n,
      expiresAt: BigInt(now + 7200),
      reserveRequirementRatioBps: 2500,
      operator: wallets.rotatingOperator.address,
      operatorKeyHash: rotatingOperatorKeyB,
    };
    const rotatedBondVaultId = await bondVault
      .connect(wallets.principal)
      .deriveVaultId(rotatedBondTerms);
    const rotatedBondEvidenceHash = toBytes32Label("rotated-key-bond-evidence");
    const rotatedBondReleaseLeaf = bondProofLeaf(
      chainId,
      await bondVault.getAddress(),
      rotatedBondVaultId,
      rotatedBondTerms.operatorKeyHash,
      rotatedBondEvidenceHash,
      BOND_ACTION_RELEASE,
      0n,
      ZERO_BYTES32,
    );
    const staleKeyEscrowTerms = {
      capabilityId: toBytes32Label("capability:stale-key"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 100_000n,
      deadline: BigInt(now + 7200),
      operator: wallets.rotatingOperator.address,
      operatorKeyHash: rotatingOperatorKeyA,
    };
    const staleKeyEscrowId = await escrow
      .connect(wallets.depositor)
      .deriveEscrowId(staleKeyEscrowTerms);
    const staleKeyReceiptHash = toBytes32Label("stale-key-escrow-receipt");
    const staleKeyEscrowLeaf = escrowProofLeaf(
      chainId,
      await escrow.getAddress(),
      staleKeyEscrowId,
      staleKeyEscrowTerms.token,
      staleKeyEscrowTerms.beneficiary,
      staleKeyEscrowTerms.operatorKeyHash,
      staleKeyReceiptHash,
      staleKeyEscrowTerms.maxAmount,
      false,
    );
    const staleKeyBondTerms = {
      bondId: toBytes32Label("bond:stale-key"),
      facilityId: toBytes32Label("facility:stale-key"),
      principal: wallets.principal.address,
      token: await mockUsdc.getAddress(),
      collateralAmount: 100_000n,
      reserveRequirementAmount: 25_000n,
      expiresAt: BigInt(now + 7200),
      reserveRequirementRatioBps: 2500,
      operator: wallets.rotatingOperator.address,
      operatorKeyHash: rotatingOperatorKeyA,
    };
    const staleKeyBondVaultId = await bondVault
      .connect(wallets.principal)
      .deriveVaultId(staleKeyBondTerms);
    const staleKeyBondEvidenceHash = toBytes32Label("stale-key-bond-evidence");
    const staleKeyBondReleaseLeaf = bondProofLeaf(
      chainId,
      await bondVault.getAddress(),
      staleKeyBondVaultId,
      staleKeyBondTerms.operatorKeyHash,
      staleKeyBondEvidenceHash,
      BOND_ACTION_RELEASE,
      0n,
      ZERO_BYTES32,
    );
    await (
      await rootRegistry
        .connect(wallets.rotatingOperator)
        .publishRoot(
          wallets.rotatingOperator.address,
          rotatedLeaf,
          1,
          1,
          1,
          1,
          rotatingOperatorKeyA,
        )
    ).wait();
    await (
      await rootRegistry
        .connect(wallets.rotatingOperator)
        .publishRoot(
          wallets.rotatingOperator.address,
          rotatedBondReleaseLeaf,
          2,
          2,
          2,
          1,
          rotatingOperatorKeyA,
        )
    ).wait();
    await (
      await rootRegistry
        .connect(wallets.rotatingOperator)
        .publishRoot(
          wallets.rotatingOperator.address,
          staleKeyEscrowLeaf,
          3,
          3,
          3,
          1,
          rotatingOperatorKeyA,
        )
    ).wait();
    await (
      await rootRegistry
        .connect(wallets.rotatingOperator)
        .publishRoot(
          wallets.rotatingOperator.address,
          staleKeyBondReleaseLeaf,
          4,
          4,
          4,
          1,
          rotatingOperatorKeyA,
        )
    ).wait();
    assert.equal(
      await rootRegistry.verifyInclusionDetailedForKeyHash(
        oneLeafProof,
        rotatedLeaf,
        rotatedLeaf,
        wallets.rotatingOperator.address,
        rotatingOperatorKeyA,
      ),
      true,
    );
    await (
      await mockUsdc
        .connect(wallets.depositor)
        .approve(await escrow.getAddress(), staleKeyEscrowTerms.maxAmount)
    ).wait();
    await (await escrow.connect(wallets.depositor).createEscrow(staleKeyEscrowTerms)).wait();
    await (
      await mockUsdc
        .connect(wallets.principal)
        .approve(await bondVault.getAddress(), staleKeyBondTerms.collateralAmount)
    ).wait();
    await (await bondVault.connect(wallets.principal).lockBond(staleKeyBondTerms)).wait();
    const rotatingOperatorEpochA = (await identityRegistry.getOperator(wallets.rotatingOperator.address))
      .operatorEpoch;
    const staleEpochSignatureReceiptHash = toBytes32Label("stale-key-epoch-signature-receipt");
    const staleEpochSignature = ethers.Signature.from(
      await new ethers.Wallet(wallets.rotatingOperator.privateKey).signTypedData(
        escrowReleaseDomain(chainId, await escrow.getAddress()),
        ESCROW_RELEASE_TYPES,
        {
          escrowId: staleKeyEscrowId,
          receiptHash: staleEpochSignatureReceiptHash,
          amount: staleKeyEscrowTerms.maxAmount,
          operatorEpoch: rotatingOperatorEpochA,
        },
      ),
    );
    await (await identityRegistry.deactivateOperator(wallets.rotatingOperator.address)).wait();
    assert.equal(
      await rootRegistry.verifyInclusionDetailedForKeyHash(
        oneLeafProof,
        staleKeyEscrowLeaf,
        staleKeyEscrowLeaf,
        wallets.rotatingOperator.address,
        rotatingOperatorKeyA,
      ),
      false,
    );
    await (await identityRegistry.reactivateOperator(wallets.rotatingOperator.address)).wait();
    assert.equal(
      await rootRegistry.isAuthorizedPublisherForKeyHash(
        wallets.rotatingOperator.address,
        wallets.delegate.address,
        rotatingOperatorKeyA,
      ),
      false,
    );
    assert.equal(
      await rootRegistry.verifyInclusionDetailedForKeyHash(
        oneLeafProof,
        staleKeyEscrowLeaf,
        staleKeyEscrowLeaf,
        wallets.rotatingOperator.address,
        rotatingOperatorKeyA,
      ),
      true,
    );
    await escrow
      .connect(wallets.beneficiary)
      .releaseWithProofDetailed.staticCall(
        staleKeyEscrowId,
        oneLeafProof,
        staleKeyEscrowLeaf,
        staleKeyReceiptHash,
        staleKeyEscrowTerms.maxAmount,
      );
    await expectRevertSelector(
      "same-key reactivated stale signature",
      async () => {
        await escrow
          .connect(wallets.beneficiary)
          .releaseWithSignature.staticCall(
            staleKeyEscrowId,
            staleEpochSignatureReceiptHash,
            staleKeyEscrowTerms.maxAmount,
            rotatingOperatorEpochA,
            staleEpochSignature.yParity + 27,
            staleEpochSignature.r,
            staleEpochSignature.s,
          );
      },
      OPERATOR_KEY_HASH_MISMATCH_SELECTOR,
    );
    await expectRevert("same-key reactivated stale delegate publication", async () => {
      await rootRegistry
        .connect(wallets.delegate)
        .publishRoot.staticCall(
          wallets.rotatingOperator.address,
          toBytes32Label("same-key-reactivated-stale-delegate-root"),
          5,
          5,
          5,
          1,
          rotatingOperatorKeyA,
        );
    });
    await (await identityRegistry.deactivateOperator(wallets.rotatingOperator.address)).wait();
    const rotatingOperatorReregisterBindingProofA = await operatorBindingSignature(
      chainId,
      await identityRegistry.getAddress(),
      wallets.admin.privateKey,
      wallets.rotatingOperator.address,
      rotatingOperatorKeyA,
      wallets.rotatingOperator.address,
    );
    await (
      await identityRegistry.registerOperator(
        wallets.rotatingOperator.address,
        rotatingOperatorKeyA,
        wallets.rotatingOperator.address,
        rotatingOperatorReregisterBindingProofA,
      )
    ).wait();
    const rotatingReregisterEpoch = (await identityRegistry.getOperator(wallets.rotatingOperator.address))
      .operatorEpoch;
    assert.equal(
      await rootRegistry.isAuthorizedPublisherForKeyHash(
        wallets.rotatingOperator.address,
        wallets.delegate.address,
        rotatingOperatorKeyA,
      ),
      false,
    );
    assert.equal(
      await rootRegistry.verifyInclusionDetailedForKeyHash(
        oneLeafProof,
        staleKeyEscrowLeaf,
        staleKeyEscrowLeaf,
        wallets.rotatingOperator.address,
        rotatingOperatorKeyA,
      ),
      true,
    );
    await escrow
      .connect(wallets.beneficiary)
      .releaseWithProofDetailed.staticCall(
        staleKeyEscrowId,
        oneLeafProof,
        staleKeyEscrowLeaf,
        staleKeyReceiptHash,
        staleKeyEscrowTerms.maxAmount,
      );
    await expectRevertSelector(
      "same-key reregistered stale signature",
      async () => {
        await escrow
          .connect(wallets.beneficiary)
          .releaseWithSignature.staticCall(
            staleKeyEscrowId,
            staleEpochSignatureReceiptHash,
            staleKeyEscrowTerms.maxAmount,
            rotatingOperatorEpochA,
            staleEpochSignature.yParity + 27,
            staleEpochSignature.r,
            staleEpochSignature.s,
          );
      },
      OPERATOR_KEY_HASH_MISMATCH_SELECTOR,
    );
    await expectRevert("same-key reregistered stale delegate publication", async () => {
      await rootRegistry
        .connect(wallets.delegate)
        .publishRoot.staticCall(
          wallets.rotatingOperator.address,
          toBytes32Label("same-key-reregistered-stale-delegate-root"),
          5,
          5,
          5,
          1,
          rotatingOperatorKeyA,
        );
    });
    assert.ok(rotatingReregisterEpoch > rotatingOperatorEpochA);
    await (await identityRegistry.deactivateOperator(wallets.rotatingOperator.address)).wait();
    const rotatingOperatorBindingProofB = await operatorBindingSignature(
      chainId,
      await identityRegistry.getAddress(),
      wallets.admin.privateKey,
      wallets.rotatingOperator.address,
      rotatingOperatorKeyB,
      wallets.rotatingOperator.address,
    );
    await (
      await identityRegistry.registerOperator(
        wallets.rotatingOperator.address,
        rotatingOperatorKeyB,
        wallets.rotatingOperator.address,
        rotatingOperatorBindingProofB,
      )
    ).wait();
    assert.equal(
      await rootRegistry.isAuthorizedPublisher(wallets.rotatingOperator.address, wallets.delegate.address),
      false,
    );
    assert.equal(
      await rootRegistry.isAuthorizedPublisherForKeyHash(
        wallets.rotatingOperator.address,
        wallets.delegate.address,
        rotatingOperatorKeyA,
      ),
      false,
    );
    assert.equal(
      await rootRegistry.isAuthorizedPublisherForKeyHash(
        wallets.rotatingOperator.address,
        wallets.delegate.address,
        rotatingOperatorKeyB,
      ),
      false,
    );
    await expectRevert("stale delegate key-epoch publication", async () => {
      await rootRegistry
        .connect(wallets.delegate)
        .publishRoot.staticCall(
          wallets.rotatingOperator.address,
          toBytes32Label("stale-delegate-key-root"),
          5,
          5,
          5,
          1,
          rotatingOperatorKeyB,
        );
    });
    await (
      await rootRegistry
        .connect(wallets.rotatingOperator)
        .registerDelegate(wallets.delegate.address, rotatingDelegateExpiry)
    ).wait();
    assert.equal(
      await rootRegistry.isAuthorizedPublisherForKeyHash(
        wallets.rotatingOperator.address,
        wallets.delegate.address,
        rotatingOperatorKeyB,
      ),
      true,
    );
    await rootRegistry
      .connect(wallets.delegate)
      .publishRoot.staticCall(
        wallets.rotatingOperator.address,
        toBytes32Label("rotated-delegate-key-root"),
        5,
        5,
        5,
        1,
        rotatingOperatorKeyB,
      );
    await expectRevertSelector(
      "stale-key escrow release after rotation",
      async () => {
        await escrow
          .connect(wallets.beneficiary)
          .releaseWithProofDetailed.staticCall(
            staleKeyEscrowId,
            oneLeafProof,
            staleKeyEscrowLeaf,
            staleKeyReceiptHash,
            staleKeyEscrowTerms.maxAmount,
          );
      },
      OPERATOR_KEY_HASH_MISMATCH_SELECTOR,
    );
    await expectRevertSelector(
      "stale-key bond release after rotation",
      async () => {
        await bondVault
          .connect(wallets.rotatingOperator)
          .releaseBondDetailed.staticCall(
            staleKeyBondVaultId,
            oneLeafProof,
            staleKeyBondReleaseLeaf,
            staleKeyBondEvidenceHash,
          );
      },
      OPERATOR_KEY_HASH_MISMATCH_SELECTOR,
    );
    await (
      await mockUsdc
        .connect(wallets.depositor)
        .approve(await escrow.getAddress(), rotatedEscrowTerms.maxAmount)
    ).wait();
    await (await escrow.connect(wallets.depositor).createEscrow(rotatedEscrowTerms)).wait();
    assert.equal(
      await rootRegistry.verifyInclusionDetailedForKeyHash(
        oneLeafProof,
        rotatedLeaf,
        rotatedLeaf,
        wallets.rotatingOperator.address,
        rotatingOperatorKeyB,
      ),
      false,
    );
    await expectRevertSelector(
      "rotated-key old root replay",
      async () => {
        await escrow
          .connect(wallets.beneficiary)
          .releaseWithProofDetailed.staticCall(
            rotatedEscrowId,
            oneLeafProof,
            rotatedLeaf,
            rotatedReceiptHash,
            rotatedEscrowTerms.maxAmount,
          );
      },
      INVALID_SIGNATURE_SELECTOR,
    );
    await (
      await rootRegistry
        .connect(wallets.rotatingOperator)
        .publishRoot(
          wallets.rotatingOperator.address,
          rotatedLeaf,
          5,
          5,
          5,
          1,
          rotatingOperatorKeyB,
        )
    ).wait();
    assert.equal(
      await rootRegistry.verifyInclusionDetailedForKeyHash(
        oneLeafProof,
        rotatedLeaf,
        rotatedLeaf,
        wallets.rotatingOperator.address,
        rotatingOperatorKeyB,
      ),
      true,
    );
    await escrow
      .connect(wallets.beneficiary)
      .releaseWithProofDetailed.staticCall(
        rotatedEscrowId,
        oneLeafProof,
        rotatedLeaf,
        rotatedReceiptHash,
          rotatedEscrowTerms.maxAmount,
      );
    await (
      await mockUsdc
        .connect(wallets.principal)
        .approve(await bondVault.getAddress(), rotatedBondTerms.collateralAmount)
    ).wait();
    await (await bondVault.connect(wallets.principal).lockBond(rotatedBondTerms)).wait();
    assert.equal(
      await rootRegistry.verifyInclusionDetailedForKeyHash(
        oneLeafProof,
        rotatedBondReleaseLeaf,
        rotatedBondReleaseLeaf,
        wallets.rotatingOperator.address,
        rotatingOperatorKeyB,
      ),
      false,
    );
    await expectRevert("rotated-key old bond root replay", async () => {
      await bondVault
        .connect(wallets.rotatingOperator)
        .releaseBondDetailed.staticCall(
          rotatedBondVaultId,
          oneLeafProof,
          rotatedBondReleaseLeaf,
          rotatedBondEvidenceHash,
        );
    });
    await (
      await rootRegistry
        .connect(wallets.rotatingOperator)
        .publishRoot(
          wallets.rotatingOperator.address,
          rotatedBondReleaseLeaf,
          6,
          6,
          6,
          1,
          rotatingOperatorKeyB,
        )
    ).wait();
    await bondVault
      .connect(wallets.rotatingOperator)
      .releaseBondDetailed.staticCall(
        rotatedBondVaultId,
        oneLeafProof,
        rotatedBondReleaseLeaf,
        rotatedBondEvidenceHash,
      );
    checks.push({
      id: "escrow_and_bond.rotated_key_root_replay_denied",
      outcome: "pass",
      note: "Escrow and bond proof roots must be published under the operator key epoch they claim.",
    });

    const inactiveOperatorKeyHash = toBytes32Label("chio-inactive-operator-key");
    logStep("escrow: setting up inactive-operator release denial");
    const inactiveOperatorBindingProof = await operatorBindingSignature(
      chainId,
      await identityRegistry.getAddress(),
      wallets.admin.privateKey,
      wallets.outsider.address,
      inactiveOperatorKeyHash,
      wallets.outsider.address,
    );
    await (
      await identityRegistry.registerOperator(
        wallets.outsider.address,
        inactiveOperatorKeyHash,
        wallets.outsider.address,
        inactiveOperatorBindingProof,
      )
    ).wait();
    const inactiveOperatorReceiptHash = toBytes32Label("inactive-operator-escrow-receipt");
    const inactiveOperatorSigner = await provider.getSigner(wallets.outsider.address);
    await (
      await rootRegistry
        .connect(inactiveOperatorSigner)
        .publishRoot(
          wallets.outsider.address,
          inactiveOperatorReceiptHash,
          1,
          1,
          1,
          1,
          inactiveOperatorKeyHash,
          { gasLimit: 500_000n },
        )
    ).wait();
    const inactiveOperatorEscrowTerms = {
      capabilityId: toBytes32Label("capability:inactive-operator"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 100_000n,
      deadline: BigInt(now + 7200),
      operator: wallets.outsider.address,
      operatorKeyHash: inactiveOperatorKeyHash,
    };
    await (
      await mockUsdc
        .connect(wallets.depositor)
        .approve(await escrow.getAddress(), inactiveOperatorEscrowTerms.maxAmount)
    ).wait();
    const inactiveOperatorEscrowId = await escrow
      .connect(wallets.depositor)
      .deriveEscrowId(inactiveOperatorEscrowTerms);
    await (
      await escrow.connect(wallets.depositor).createEscrow(inactiveOperatorEscrowTerms)
    ).wait();
    await (await identityRegistry.deactivateOperator(wallets.outsider.address)).wait();
    const inactiveBeneficiarySigner = await provider.getSigner(wallets.beneficiary.address);
    await expectRevert("inactive operator escrow release", async () => {
      const tx = await escrow
        .connect(inactiveBeneficiarySigner)
        .releaseWithProofDetailed(
          inactiveOperatorEscrowId,
          oneLeafProof,
          inactiveOperatorReceiptHash,
          inactiveOperatorReceiptHash,
          inactiveOperatorEscrowTerms.maxAmount,
          { gasLimit: 500_000n },
        );
      await tx.wait();
    });
    checks.push({
      id: "escrow.inactive_operator_release_denied",
      outcome: "pass",
      note: "Escrow release rechecks operator activation before moving funds.",
    });

    const inactiveBondOperatorKeyHash = toBytes32Label("chio-inactive-bond-operator-key");
    const inactiveBondOperatorBindingProof = await operatorBindingSignature(
      chainId,
      await identityRegistry.getAddress(),
      wallets.admin.privateKey,
      wallets.delegate.address,
      inactiveBondOperatorKeyHash,
      wallets.delegate.address,
    );
    await (
      await identityRegistry.registerOperator(
        wallets.delegate.address,
        inactiveBondOperatorKeyHash,
        wallets.delegate.address,
        inactiveBondOperatorBindingProof,
      )
    ).wait();
    const inactiveBondEvidenceHash = toBytes32Label("inactive-operator-bond-evidence");
    const inactiveBondOperatorSigner = await provider.getSigner(wallets.delegate.address);
    const inactiveOperatorBondTerms = {
      bondId: toBytes32Label("bond:inactive-operator"),
      facilityId: toBytes32Label("facility:inactive-operator"),
      principal: wallets.principal.address,
      token: await mockUsdc.getAddress(),
      collateralAmount: 100_000n,
      reserveRequirementAmount: 25_000n,
      expiresAt: BigInt(now + 7200),
      reserveRequirementRatioBps: 2500,
      operator: wallets.delegate.address,
      operatorKeyHash: inactiveBondOperatorKeyHash,
    };
    const inactiveOperatorVaultId = await bondVault
      .connect(wallets.principal)
      .deriveVaultId(inactiveOperatorBondTerms);
    const inactiveBondReleaseLeaf = bondProofLeaf(
      chainId,
      await bondVault.getAddress(),
      inactiveOperatorVaultId,
      inactiveBondOperatorKeyHash,
      inactiveBondEvidenceHash,
      BOND_ACTION_RELEASE,
      0n,
      ZERO_BYTES32,
    );
    await (
      await rootRegistry
        .connect(inactiveBondOperatorSigner)
        .publishRoot(
          wallets.delegate.address,
          inactiveBondReleaseLeaf,
          1,
          1,
          1,
          1,
          inactiveBondOperatorKeyHash,
          { gasLimit: 500_000n },
        )
    ).wait();
    await (
      await mockUsdc
        .connect(wallets.principal)
        .approve(await bondVault.getAddress(), inactiveOperatorBondTerms.collateralAmount)
    ).wait();
    await (await bondVault.connect(wallets.principal).lockBond(inactiveOperatorBondTerms)).wait();
    await (await identityRegistry.deactivateOperator(wallets.delegate.address)).wait();
    await expectRevert("inactive operator bond release", async () => {
      const tx = await bondVault
        .connect(inactiveBondOperatorSigner)
        .releaseBondDetailed(
          inactiveOperatorVaultId,
          oneLeafProof,
          inactiveBondReleaseLeaf,
          inactiveBondEvidenceHash,
          { gasLimit: 500_000n },
        );
      await tx.wait();
    });
    await expectRevert("inactive operator bond impairment", async () => {
      const tx = await bondVault
        .connect(inactiveBondOperatorSigner)
        .impairBondDetailed(
          inactiveOperatorVaultId,
          50_000n,
          [wallets.beneficiary.address],
          [50_000n],
          oneLeafProof,
          inactiveBondEvidenceHash,
          inactiveBondEvidenceHash,
          { gasLimit: 500_000n },
        );
      await tx.wait();
    });
    checks.push({
      id: "bond.inactive_operator_release_and_impair_denied",
      outcome: "pass",
      note: "Bond release and impairment recheck operator activation before moving collateral.",
    });

    const noReturnEscrowTerms = {
      capabilityId: toBytes32Label("capability:no-return-token"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await noReturnToken.getAddress(),
      maxAmount: 100_000n,
      deadline: BigInt(now + 7200),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    await (
      await noReturnToken
        .connect(wallets.depositor)
        .approve(await escrow.getAddress(), noReturnEscrowTerms.maxAmount)
    ).wait();
    const noReturnEscrowId = await escrow
      .connect(wallets.depositor)
      .deriveEscrowId(noReturnEscrowTerms);
    await (await escrow.connect(wallets.depositor).createEscrow(noReturnEscrowTerms)).wait();
    const noReturnReceiptHash = toBytes32Label("no-return-escrow-receipt");
    const noReturnProofLeaf = escrowProofLeaf(
      chainId,
      await escrow.getAddress(),
      noReturnEscrowId,
      noReturnEscrowTerms.token,
      noReturnEscrowTerms.beneficiary,
      noReturnEscrowTerms.operatorKeyHash,
      noReturnReceiptHash,
      noReturnEscrowTerms.maxAmount,
      false,
    );
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, noReturnProofLeaf, 4, 5, 5, 1, operatorEdKeyHash)
    ).wait();
    await (
      await escrow
        .connect(wallets.beneficiary)
        .releaseWithProofDetailed(
          noReturnEscrowId,
          oneLeafProof,
          noReturnProofLeaf,
          noReturnReceiptHash,
          noReturnEscrowTerms.maxAmount,
        )
    ).wait();
    assert.equal(await noReturnToken.balanceOf(wallets.beneficiary.address), noReturnEscrowTerms.maxAmount);
    checks.push({
      id: "escrow.optional_return_token",
      outcome: "pass",
      note: "Escrow custody accepts ERC20 transfers that succeed without return data.",
    });

    const feeEscrowTerms = {
      capabilityId: toBytes32Label("capability:fee-token"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await feeToken.getAddress(),
      maxAmount: 100_000n,
      deadline: BigInt(now + 7200),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    const unlistedEscrowTerms = {
      ...feeEscrowTerms,
      capabilityId: toBytes32Label("capability:unlisted-token"),
    };
    await (
      await feeToken
        .connect(wallets.depositor)
        .approve(await escrow.getAddress(), feeEscrowTerms.maxAmount)
    ).wait();
    await expectRevert("unlisted token escrow", async () => {
      await escrow.connect(wallets.depositor).createEscrow.staticCall(unlistedEscrowTerms);
    });
    await (await escrow.setTokenAllowed(await feeToken.getAddress(), true)).wait();
    await expectRevert("fee token short escrow deposit", async () => {
      await escrow.connect(wallets.depositor).createEscrow.staticCall(feeEscrowTerms);
    });
    checks.push({
      id: "escrow.rejects_short_token_receipts",
      outcome: "pass",
      note: "Escrow custody rejects deposits whose received token balance is below the requested amount.",
    });

    const feeBondTerms = {
      bondId: toBytes32Label("bond:fee-token"),
      facilityId: toBytes32Label("facility:fee-token"),
      principal: wallets.principal.address,
      token: await feeToken.getAddress(),
      collateralAmount: 100_000n,
      reserveRequirementAmount: 25_000n,
      expiresAt: BigInt(now + 7200),
      reserveRequirementRatioBps: 2500,
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    await expectRevert("unlisted token bond", async () => {
      await bondVault.connect(wallets.principal).lockBond.staticCall(feeBondTerms);
    });
    await (await bondVault.setTokenAllowed(await feeToken.getAddress(), true)).wait();
    await (
      await feeToken
        .connect(wallets.principal)
        .approve(await bondVault.getAddress(), feeBondTerms.collateralAmount)
    ).wait();
    await expectRevert("fee token short bond collateral", async () => {
      await bondVault.connect(wallets.principal).lockBond.staticCall(feeBondTerms);
    });
    checks.push({
      id: "bond.rejects_short_token_receipts",
      outcome: "pass",
      note: "Bond vault custody rejects collateral whose received token balance is below the requested amount.",
    });

    const permitAllowanceTerms = {
      capabilityId: toBytes32Label("capability:permit-allowance"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 70_000n,
      deadline: BigInt(now + 7200),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    await (
      await mockUsdc
        .connect(wallets.depositor)
        .approve(await escrow.getAddress(), permitAllowanceTerms.maxAmount)
    ).wait();
    const permitAllowanceEscrowId = await escrow
      .connect(wallets.depositor)
      .deriveEscrowId(permitAllowanceTerms);
    const permitAllowanceTx = await escrow
      .connect(wallets.depositor)
      .createEscrowWithPermit(
        permitAllowanceTerms,
        BigInt(now + 3600),
        27,
        ZERO_BYTES32,
        ZERO_BYTES32,
      );
    const permitAllowanceReceipt = await waitForReceipt(provider, permitAllowanceTx);
    const permitAllowanceEvent = await findContractEvent(permitAllowanceReceipt, escrow, "EscrowCreated");
    assert.equal(permitAllowanceEvent.args.escrowId, permitAllowanceEscrowId);
    const [, permitAllowanceDeposited] = await escrow.getEscrow(permitAllowanceEscrowId);
    assert.equal(permitAllowanceDeposited, permitAllowanceTerms.maxAmount);
    checks.push({
      id: "escrow.permit_allowance_fallback",
      outcome: "pass",
      note: "Escrow permit creation accepts an already-sufficient allowance if the permit call is unavailable.",
    });

    logStep("exercising escrow lifecycle");
    const escrowTerms = {
      capabilityId: toBytes32Label("capability:devnet"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 1_500_000n,
      deadline: BigInt(now + 7200),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    await expectRevert("zero operator key escrow", async () => {
      await escrow.connect(wallets.depositor).createEscrow.staticCall({
        ...escrowTerms,
        capabilityId: toBytes32Label("capability:zero-operator-key"),
        operatorKeyHash: ZERO_BYTES32,
      });
    });

    await (
      await mockUsdc.connect(wallets.depositor).approve(await escrow.getAddress(), escrowTerms.maxAmount)
    ).wait();
    logStep("escrow: approved token allowance");
    const escrowId = await escrow.connect(wallets.depositor).deriveEscrowId(escrowTerms);
    gasEstimates.create_escrow = (
      await escrow.connect(wallets.depositor).createEscrow.estimateGas(escrowTerms)
    ).toString();
    logStep("escrow: creating primary escrow");
    const createEscrowTx = await escrow.connect(wallets.depositor).createEscrow(escrowTerms);
    const createEscrowReceipt = await waitForReceipt(provider, createEscrowTx);
    const createdEscrow = await findContractEvent(createEscrowReceipt, escrow, "EscrowCreated");
    assert.equal(createdEscrow.args.escrowId, escrowId);
    logStep("escrow: primary escrow created");

    await expectRevert("proof metadata required", async () => {
      await escrow
        .connect(wallets.beneficiary)
        .releaseWithProof(escrowId, [], delegateReceiptHash, delegateReceiptHash, 100_000n);
    });
    logStep("escrow: under-specified proof path reverted as expected");

    const legacyPartialProofLeaf = legacyEscrowProofLeaf(
      chainId,
      await escrow.getAddress(),
      escrowId,
      delegateReceiptHash,
      500_000n,
      true,
    );
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, legacyPartialProofLeaf, 5, 6, 6, 1, operatorEdKeyHash)
    ).wait();
    await expectRevertSelector(
      "under-bound escrow proof leaf",
      async () => {
        await escrow
          .connect(wallets.beneficiary)
          .partialReleaseWithProofDetailed.staticCall(
            escrowId,
            oneLeafProof,
            legacyPartialProofLeaf,
            delegateReceiptHash,
            500_000n,
          );
      },
      INVALID_SIGNATURE_SELECTOR,
    );
    const partialProofLeaf = escrowProofLeaf(
      chainId,
      await escrow.getAddress(),
      escrowId,
      escrowTerms.token,
      escrowTerms.beneficiary,
      escrowTerms.operatorKeyHash,
      delegateReceiptHash,
      500_000n,
      true,
    );
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, partialProofLeaf, 6, 7, 7, 1, operatorEdKeyHash)
    ).wait();
    await expectRevert("unbound escrow proof amount", async () => {
      await escrow
        .connect(wallets.beneficiary)
        .partialReleaseWithProofDetailed.staticCall(
          escrowId,
          oneLeafProof,
          partialProofLeaf,
          delegateReceiptHash,
          600_000n,
        );
    });
    await (await escrow.connect(adminRpcSigner).setPaused(true)).wait();
    await expectRevertSelector(
      "paused escrow partial release",
      async () => {
        await escrow
          .connect(wallets.beneficiary)
          .partialReleaseWithProofDetailed.staticCall(
            escrowId,
            oneLeafProof,
            partialProofLeaf,
            delegateReceiptHash,
            500_000n,
          );
      },
      PAUSED_SELECTOR,
    );
    await (await escrow.connect(adminRpcSigner).setPaused(false)).wait();
    gasEstimates.merkle_partial_release = (
      await escrow
        .connect(wallets.beneficiary)
        .partialReleaseWithProofDetailed.estimateGas(
          escrowId,
          oneLeafProof,
          partialProofLeaf,
          delegateReceiptHash,
          500_000n,
        )
    ).toString();
    await (
      await escrow
        .connect(wallets.beneficiary)
        .partialReleaseWithProofDetailed(
          escrowId,
          oneLeafProof,
          partialProofLeaf,
          delegateReceiptHash,
          500_000n,
        )
    ).wait();
    logStep("escrow: merkle partial release completed");
    await expectRevert("replayed partial release receipt", async () => {
      await escrow
        .connect(wallets.beneficiary)
        .partialReleaseWithProofDetailed.staticCall(
          escrowId,
          oneLeafProof,
          partialProofLeaf,
          delegateReceiptHash,
          500_000n,
        );
    });
    const crossReplayEscrowTerms = {
      capabilityId: toBytes32Label("capability:cross-replay"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 100_000n,
      deadline: BigInt(now + 10800),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    await (
      await mockUsdc
        .connect(wallets.depositor)
        .approve(await escrow.getAddress(), crossReplayEscrowTerms.maxAmount)
    ).wait();
    const crossReplayEscrowId = await escrow
      .connect(wallets.depositor)
      .deriveEscrowId(crossReplayEscrowTerms);
    await (await escrow.connect(wallets.depositor).createEscrow(crossReplayEscrowTerms)).wait();
    const crossReplaySignature = ethers.Signature.from(
      await new ethers.Wallet(wallets.operator.privateKey).signTypedData(
        escrowReleaseDomain(chainId, await escrow.getAddress()),
        ESCROW_RELEASE_TYPES,
        {
          escrowId: crossReplayEscrowId,
          receiptHash: delegateReceiptHash,
          amount: crossReplayEscrowTerms.maxAmount,
          operatorEpoch,
        },
      ),
    );
    await expectRevertSelector(
      "cross-escrow receipt replay",
      async () => {
        await escrow
          .connect(wallets.beneficiary)
          .releaseWithSignature.staticCall(
            crossReplayEscrowId,
            delegateReceiptHash,
            crossReplayEscrowTerms.maxAmount,
            operatorEpoch,
            crossReplaySignature.yParity + 27,
            crossReplaySignature.r,
            crossReplaySignature.s,
          );
      },
      RECEIPT_ALREADY_USED_SELECTOR,
    );
    checks.push({
      id: "escrow.merkle_partial_release",
      outcome: "pass",
      note: "Escrow accepts the detailed RFC6962 proof path and supports partial settlement.",
    });

    const finalReceiptHash = toBytes32Label("escrow-final-receipt");
    const signatureValue = {
      escrowId,
      receiptHash: finalReceiptHash,
      amount: 1_000_000n,
      operatorEpoch,
    };
    const signatureDigest = ethers.solidityPackedKeccak256(
      ["uint256", "address", "bytes32", "bytes32", "uint256", "uint64"],
      [
        chainId,
        await escrow.getAddress(),
        signatureValue.escrowId,
        signatureValue.receiptHash,
        signatureValue.amount,
        signatureValue.operatorEpoch,
      ],
    );
    const rawOperatorSignature = new ethers.SigningKey(wallets.operator.privateKey).sign(signatureDigest);
    const typedOperatorSignature = ethers.Signature.from(
      await new ethers.Wallet(wallets.operator.privateKey).signTypedData(
        escrowReleaseDomain(chainId, await escrow.getAddress()),
        ESCROW_RELEASE_TYPES,
        signatureValue,
      ),
    );
    const malleatedTypedSignatureS = ethers.toBeHex(
      SECP256K1_ORDER - BigInt(typedOperatorSignature.s),
      32,
    );
    const malleatedTypedSignatureV = 27 + (typedOperatorSignature.yParity === 0 ? 1 : 0);
    const outsiderSignature = ethers.Signature.from(
      await new ethers.Wallet(wallets.outsider.privateKey).signTypedData(
        escrowReleaseDomain(chainId, await escrow.getAddress()),
        ESCROW_RELEASE_TYPES,
        signatureValue,
      ),
    );
    const zeroReceiptSignatureValue = {
      ...signatureValue,
      receiptHash: ZERO_BYTES32,
    };
    const zeroReceiptSignature = ethers.Signature.from(
      await new ethers.Wallet(wallets.operator.privateKey).signTypedData(
        escrowReleaseDomain(chainId, await escrow.getAddress()),
        ESCROW_RELEASE_TYPES,
        zeroReceiptSignatureValue,
      ),
    );
    const partialSignatureValue = {
      ...signatureValue,
      receiptHash: toBytes32Label("escrow-dual-sign-partial-receipt"),
      amount: 1n,
    };
    const partialTypedSignature = ethers.Signature.from(
      await new ethers.Wallet(wallets.operator.privateKey).signTypedData(
        escrowReleaseDomain(chainId, await escrow.getAddress()),
        ESCROW_RELEASE_TYPES,
        partialSignatureValue,
      ),
    );

    await (await escrow.connect(adminRpcSigner).setPaused(true)).wait();
    await expectRevertSelector(
      "paused escrow signature release",
      async () => {
        await escrow
          .connect(wallets.beneficiary)
          .releaseWithSignature.staticCall(
            signatureValue.escrowId,
            signatureValue.receiptHash,
            signatureValue.amount,
            signatureValue.operatorEpoch,
            typedOperatorSignature.yParity + 27,
            typedOperatorSignature.r,
            typedOperatorSignature.s,
          );
      },
      PAUSED_SELECTOR,
    );
    await (await escrow.connect(adminRpcSigner).setPaused(false)).wait();

    await expectRevert("invalid signature", async () => {
      await escrow
        .connect(wallets.beneficiary)
        .releaseWithSignature(
          escrowId,
          finalReceiptHash,
          1_000_000n,
          signatureValue.operatorEpoch,
          outsiderSignature.yParity + 27,
          outsiderSignature.r,
          outsiderSignature.s,
        );
    });
    await expectRevert("raw digest signature", async () => {
      await escrow
        .connect(wallets.beneficiary)
        .releaseWithSignature.staticCall(
          signatureValue.escrowId,
          signatureValue.receiptHash,
          signatureValue.amount,
          signatureValue.operatorEpoch,
          rawOperatorSignature.yParity + 27,
          rawOperatorSignature.r,
          rawOperatorSignature.s,
        );
    });
    await expectRevert("malleable typed signature", async () => {
      await escrow
        .connect(wallets.beneficiary)
        .releaseWithSignature.staticCall(
          signatureValue.escrowId,
          signatureValue.receiptHash,
          signatureValue.amount,
          signatureValue.operatorEpoch,
          malleatedTypedSignatureV,
          typedOperatorSignature.r,
          malleatedTypedSignatureS,
        );
    });
    await expectRevertSelector(
      "zero receipt hash signature release",
      async () => {
        await escrow
          .connect(wallets.beneficiary)
          .releaseWithSignature.staticCall(
            zeroReceiptSignatureValue.escrowId,
            zeroReceiptSignatureValue.receiptHash,
            zeroReceiptSignatureValue.amount,
            zeroReceiptSignatureValue.operatorEpoch,
            zeroReceiptSignature.yParity + 27,
            zeroReceiptSignature.r,
            zeroReceiptSignature.s,
          );
      },
      INVALID_SIGNATURE_SELECTOR,
    );
    await expectRevertSelector(
      "partial amount through dual-sign release",
      async () => {
        await escrow
          .connect(wallets.beneficiary)
          .releaseWithSignature.staticCall(
            partialSignatureValue.escrowId,
            partialSignatureValue.receiptHash,
            partialSignatureValue.amount,
            partialSignatureValue.operatorEpoch,
            partialTypedSignature.yParity + 27,
            partialTypedSignature.r,
            partialTypedSignature.s,
          );
      },
      INVALID_RELEASE_AMOUNT_SELECTOR,
    );
    logStep("escrow: invalid signature rejected");

    logStep("escrow: estimating valid dual-sign release gas");
    gasEstimates.dual_sign_release = (
      await escrow
        .connect(wallets.beneficiary)
        .releaseWithSignature.estimateGas(
          signatureValue.escrowId,
          signatureValue.receiptHash,
          signatureValue.amount,
          signatureValue.operatorEpoch,
          typedOperatorSignature.yParity + 27,
          typedOperatorSignature.r,
          typedOperatorSignature.s,
        )
    ).toString();
    logStep("escrow: validating valid dual-sign release via static call");
    await escrow
      .connect(wallets.beneficiary)
      .releaseWithSignature.staticCall(
        signatureValue.escrowId,
        signatureValue.receiptHash,
        signatureValue.amount,
        signatureValue.operatorEpoch,
        typedOperatorSignature.yParity + 27,
        typedOperatorSignature.r,
        typedOperatorSignature.s,
      );
    logStep("escrow: dual-sign release accepted by static validation");
    checks.push({
      id: "escrow.dual_sign_release",
      outcome: "pass",
      note: "Escrow accepts the operator-bound dual-signature release path and rejects mismatched signers.",
    });

    logStep("escrow: publishing final proof root");
    const finalProofLeaf = escrowProofLeaf(
      chainId,
      await escrow.getAddress(),
      escrowId,
      escrowTerms.token,
      escrowTerms.beneficiary,
      escrowTerms.operatorKeyHash,
      finalReceiptHash,
      1_000_000n,
      false,
    );
    const finalRootPublishGas = await rootRegistry
      .connect(wallets.operator)
      .publishRoot.estimateGas(
        wallets.operator.address,
        finalProofLeaf,
        7,
        8,
        8,
        1,
        operatorEdKeyHash,
      );
    const finalRootPublishTx = await rootRegistry
      .connect(wallets.operator)
      .publishRoot(
        wallets.operator.address,
        finalProofLeaf,
        7,
        8,
        8,
        1,
        operatorEdKeyHash,
        { gasLimit: (finalRootPublishGas * 12n) / 10n + 50_000n },
      );
    await waitForReceipt(provider, finalRootPublishTx);
    logStep("escrow: root published for final proof release");

    const beneficiaryRpcSigner = await provider.getSigner(wallets.beneficiary.address);
    await (await escrow.connect(adminRpcSigner).setPaused(true)).wait();
    await expectRevertSelector(
      "paused escrow proof release",
      async () => {
        await escrow
          .connect(beneficiaryRpcSigner)
          .releaseWithProofDetailed.staticCall(
            escrowId,
            oneLeafProof,
            finalProofLeaf,
            finalReceiptHash,
            1_000_000n,
          );
      },
      PAUSED_SELECTOR,
    );
    await (await escrow.connect(adminRpcSigner).setPaused(false)).wait();
    await expectRevertSelector(
      "non-partial proof release must cover full remaining escrow balance",
      async () => {
        await escrow
          .connect(beneficiaryRpcSigner)
          .releaseWithProofDetailed.staticCall(
            escrowId,
            oneLeafProof,
            finalProofLeaf,
            finalReceiptHash,
            999_999n,
          );
      },
      INVALID_RELEASE_AMOUNT_SELECTOR,
    );
    logStep("escrow: submitting final proof-backed release");
    const finalProofReleaseGas = await escrow
      .connect(beneficiaryRpcSigner)
      .releaseWithProofDetailed.estimateGas(
        escrowId,
        oneLeafProof,
        finalProofLeaf,
        finalReceiptHash,
        1_000_000n,
      );
    const finalProofReleaseTx = await escrow
      .connect(beneficiaryRpcSigner)
      .releaseWithProofDetailed(
        escrowId,
        oneLeafProof,
        finalProofLeaf,
        finalReceiptHash,
        1_000_000n,
        { gasLimit: (finalProofReleaseGas * 12n) / 10n + 50_000n },
      );
    await waitForReceipt(provider, finalProofReleaseTx);
    logStep("escrow: final proof-backed release completed");

    const refundDeadlineBase = Number((await provider.getBlock("latest")).timestamp) + 5;
    const refundTerms = {
      capabilityId: toBytes32Label("capability:refund"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 750_000n,
      deadline: BigInt(refundDeadlineBase),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    await (
      await mockUsdc.connect(wallets.depositor).approve(await escrow.getAddress(), refundTerms.maxAmount)
    ).wait();
    logStep("escrow: approved refund-escrow allowance");
    const refundEscrowId = await escrow.connect(wallets.depositor).deriveEscrowId(refundTerms);
    logStep("escrow: creating refund escrow");
    const refundCreateTx = await escrow.connect(wallets.depositor).createEscrow(refundTerms);
    const refundCreateReceipt = await waitForReceipt(provider, refundCreateTx);
    const refundCreatedEscrow = await findContractEvent(refundCreateReceipt, escrow, "EscrowCreated");
    assert.equal(refundCreatedEscrow.args.escrowId, refundEscrowId);
    logStep("escrow: refund escrow created");
    await expectRevert("refund before expiry", async () => {
      await escrow.refund(refundEscrowId);
    });
    logStep("escrow: premature refund rejected");
    await provider.send("evm_increaseTime", [10]);
    await provider.send("evm_mine", []);
    logStep(`escrow: waiting past refund deadline ${refundTerms.deadline}`);
    const refundRpcSigner = await provider.getSigner(wallets.outsider.address);
    await (await escrow.connect(adminRpcSigner).setPaused(true)).wait();
    assert.equal(
      await escrow.paused(),
      true,
      "escrow pause must be active while proving timeout refund remains open",
    );
    logStep("escrow: submitting refund transaction");
    const refundTx = await escrow
      .connect(refundRpcSigner)
      .refund(refundEscrowId, { gasLimit: 250_000n });
    const refundReceipt = await waitForReceipt(provider, refundTx);
    const refundEvent = await findContractEvent(refundReceipt, escrow, "EscrowRefunded");
    assert.equal(refundEvent.args.escrowId, refundEscrowId);
    assert.equal(refundEvent.args.amount, refundTerms.maxAmount);
    const [, , refundReleased, refundClosed] = await escrow.getEscrow(refundEscrowId);
    assert.equal(refundReleased, 0n);
    assert.equal(refundClosed, true);
    await (await escrow.connect(adminRpcSigner).setPaused(false)).wait();
    logStep("escrow: refund completed");
    checks.push({
      id: "escrow.timeout_refund",
      outcome: "pass",
      note: "Escrow refunds only after expiry and not before.",
    });
    checks.push({
      id: "escrow.paused_timeout_refund_exit",
      outcome: "pass",
      note: "Expired escrow refund remains open while contract pause is active; pause gates create and release paths, not deadline recovery.",
    });

    logStep("escrow: qualifying deterministic identity under interleaving and replay");
    const driftEscrowTermsA = {
      capabilityId: toBytes32Label("capability:drift:a"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 210_000n,
      deadline: BigInt(now + 10800),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    const driftEscrowTermsB = {
      capabilityId: toBytes32Label("capability:drift:b"),
      depositor: wallets.depositor.address,
      beneficiary: wallets.beneficiary.address,
      token: await mockUsdc.getAddress(),
      maxAmount: 220_000n,
      deadline: BigInt(now + 10800),
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    await (
      await mockUsdc
        .connect(wallets.depositor)
        .approve(await escrow.getAddress(), driftEscrowTermsA.maxAmount + driftEscrowTermsB.maxAmount)
    ).wait();
    const predictedEscrowA = await escrow.connect(wallets.depositor).deriveEscrowId(driftEscrowTermsA);
    const predictedEscrowB = await escrow.connect(wallets.depositor).deriveEscrowId(driftEscrowTermsB);
    const driftEscrowBTx = await escrow.connect(wallets.depositor).createEscrow(driftEscrowTermsB);
    const driftEscrowBReceipt = await waitForReceipt(provider, driftEscrowBTx);
    const driftEscrowBEvent = await findContractEvent(driftEscrowBReceipt, escrow, "EscrowCreated");
    assert.equal(driftEscrowBEvent.args.escrowId, predictedEscrowB);
    const driftEscrowATx = await escrow.connect(wallets.depositor).createEscrow(driftEscrowTermsA);
    const driftEscrowAReceipt = await waitForReceipt(provider, driftEscrowATx);
    const driftEscrowAEvent = await findContractEvent(driftEscrowAReceipt, escrow, "EscrowCreated");
    assert.equal(driftEscrowAEvent.args.escrowId, predictedEscrowA);
    await expectRevert("duplicate escrow replay", async () => {
      const tx = await escrow.connect(wallets.depositor).createEscrow(driftEscrowTermsA);
      await tx.wait();
    });
    checks.push({
      id: "escrow.identity_reconciliation_under_nonce_drift",
      outcome: "pass",
      note: "Escrow identity remains deterministic under interleaving submissions and duplicate replays fail closed.",
    });

    logStep("exercising bond lifecycle");
    const bondTerms = {
      bondId: toBytes32Label("bond:primary"),
      facilityId: toBytes32Label("facility:primary"),
      principal: wallets.principal.address,
      token: await mockUsdc.getAddress(),
      collateralAmount: 2_000_000n,
      reserveRequirementAmount: 500_000n,
      expiresAt: BigInt(now + 7200),
      reserveRequirementRatioBps: 2500,
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    await (
      await mockUsdc.connect(wallets.principal).approve(await bondVault.getAddress(), bondTerms.collateralAmount)
    ).wait();
    logStep("bond: approved primary collateral allowance");
    const bondVaultId = await bondVault.connect(wallets.principal).deriveVaultId(bondTerms);
    gasEstimates.lock_bond = (
      await bondVault.connect(wallets.principal).lockBond.estimateGas(bondTerms)
    ).toString();
    const bondLockTx = await bondVault.connect(wallets.principal).lockBond(bondTerms);
    const bondLockReceipt = await waitForReceipt(provider, bondLockTx);
    logStep("bond: primary collateral locked");
    const lockedBond = await findContractEvent(bondLockReceipt, bondVault, "BondLocked");
    assert.equal(lockedBond.args.vaultId, bondVaultId);
    const [storedBondTerms, lockedAmount, slashedAmount, released, expired] = await bondVault.getBond(
      bondVaultId,
    );
    assert.equal(storedBondTerms.reserveRequirementAmount, bondTerms.reserveRequirementAmount);
    assert.equal(
      Number(storedBondTerms.reserveRequirementRatioBps),
      bondTerms.reserveRequirementRatioBps,
    );
    assert.equal(lockedAmount, bondTerms.collateralAmount);
    assert.equal(slashedAmount, 0n);
    assert.equal(released, false);
    assert.equal(expired, false);
    checks.push({
      id: "bond.reserve_requirement_metadata_parity",
      outcome: "pass",
      note: "Bond vault locks collateral on-chain while preserving reserve requirement metadata from the signed Chio bond terms for parity and review.",
    });

    await expectRevert("bond proof metadata required", async () => {
      await bondVault
        .connect(wallets.operator)
        .releaseBond(bondVaultId, [], toBytes32Label("bond-root"), toBytes32Label("bond-proof"));
    });

    const bondEvidenceHash = toBytes32Label("bond-release-evidence");
    const bondReleaseLeaf = bondProofLeaf(
      CHAIN_ID,
      await bondVault.getAddress(),
      bondVaultId,
      operatorEdKeyHash,
      bondEvidenceHash,
      BOND_ACTION_RELEASE,
      0n,
      ZERO_BYTES32,
    );
    const bondRootPublishGas = await rootRegistry
      .connect(wallets.operator)
      .publishRoot.estimateGas(
        wallets.operator.address,
        bondEvidenceHash,
        8,
        9,
        9,
        1,
        operatorEdKeyHash,
      );
    const bondRootPublishTx = await rootRegistry
      .connect(wallets.operator)
      .publishRoot(
        wallets.operator.address,
        bondEvidenceHash,
        8,
        9,
        9,
        1,
        operatorEdKeyHash,
        { gasLimit: (bondRootPublishGas * 12n) / 10n + 50_000n },
      );
    await waitForReceipt(provider, bondRootPublishTx);
    logStep("bond: root published for primary release");
    await expectRevert("unbound bond release evidence", async () => {
      await bondVault
        .connect(wallets.operator)
        .releaseBondDetailed.staticCall(
          bondVaultId,
          oneLeafProof,
          bondEvidenceHash,
          bondEvidenceHash,
        );
    });
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, bondReleaseLeaf, 9, 10, 10, 1, operatorEdKeyHash)
    ).wait();
    await (await bondVault.connect(adminRpcSigner).setPaused(true)).wait();
    await expectRevertSelector(
      "paused bond release",
      async () => {
        await bondVault
          .connect(wallets.operator)
          .releaseBondDetailed.staticCall(
            bondVaultId,
            oneLeafProof,
            bondReleaseLeaf,
            bondEvidenceHash,
          );
      },
      PAUSED_SELECTOR,
    );
    await (await bondVault.connect(adminRpcSigner).setPaused(false)).wait();
    gasEstimates.bond_release = (
      await bondVault
        .connect(wallets.operator)
        .releaseBondDetailed.estimateGas(
          bondVaultId,
          oneLeafProof,
          bondReleaseLeaf,
          bondEvidenceHash,
        )
    ).toString();
    const bondReleaseTx = await bondVault
      .connect(wallets.operator)
      .releaseBondDetailed(
        bondVaultId,
        oneLeafProof,
        bondReleaseLeaf,
        bondEvidenceHash,
        { gasLimit: (BigInt(gasEstimates.bond_release) * 12n) / 10n + 50_000n },
      );
    await waitForReceipt(provider, bondReleaseTx);
    logStep("bond: primary release completed");
    checks.push({
      id: "bond.release_with_proof",
      outcome: "pass",
      note: "Bond vault releases collateral only on the detailed proof path and rejects the under-specified interface.",
    });

    const reentrantBondTerms = {
      bondId: toBytes32Label("bond:reentrant"),
      facilityId: toBytes32Label("facility:reentrant"),
      principal: wallets.principal.address,
      token: await reentrantBondToken.getAddress(),
      collateralAmount: 1_000_000n,
      reserveRequirementAmount: 250_000n,
      expiresAt: BigInt(now + 7200),
      reserveRequirementRatioBps: 2500,
      operator: await reentrantBondToken.getAddress(),
      operatorKeyHash: reentrantOperatorKeyHash,
    };
    await (
      await reentrantBondToken
        .connect(wallets.principal)
        .approve(await bondVault.getAddress(), reentrantBondTerms.collateralAmount)
    ).wait();
    logStep("bond: approved reentrant collateral allowance");
    const reentrantVaultId = await bondVault
      .connect(wallets.principal)
      .deriveVaultId(reentrantBondTerms);
    await (await bondVault.connect(wallets.principal).lockBond(reentrantBondTerms)).wait();
    logStep("bond: reentrant collateral locked");
    const reentrantSlashEvidenceHash = toBytes32Label("bond-reentrant-slash");
    const reentrantReleaseEvidenceHash = toBytes32Label("bond-reentrant-release");
    const reentrantSlashLeaf = bondProofLeaf(
      CHAIN_ID,
      await bondVault.getAddress(),
      reentrantVaultId,
      reentrantOperatorKeyHash,
      reentrantSlashEvidenceHash,
      BOND_ACTION_IMPAIR,
      400_000n,
      bondDistributionHash([wallets.beneficiary.address], [400_000n]),
    );
    const reentrantReleaseLeaf = bondProofLeaf(
      CHAIN_ID,
      await bondVault.getAddress(),
      reentrantVaultId,
      reentrantOperatorKeyHash,
      reentrantReleaseEvidenceHash,
      BOND_ACTION_RELEASE,
      0n,
      ZERO_BYTES32,
    );
    const reentrantBondTokenAdmin = reentrantBondToken.connect(adminRpcSigner);
    await (
      await reentrantBondTokenAdmin.publishRoot(
        await rootRegistry.getAddress(),
        reentrantSlashLeaf,
        1,
        1,
        1,
        1,
        reentrantOperatorKeyHash,
        { gasLimit: 500_000n },
      )
    ).wait();
    logStep("bond: reentrant slash root published");
    await (
      await reentrantBondTokenAdmin.publishRoot(
        await rootRegistry.getAddress(),
        reentrantReleaseLeaf,
        2,
        2,
        2,
        1,
        reentrantOperatorKeyHash,
        { gasLimit: 500_000n },
      )
    ).wait();
    logStep("bond: reentrant release root published");
    await (
      await reentrantBondTokenAdmin.configureReleaseReentry(
        await bondVault.getAddress(),
        reentrantVaultId,
        oneLeafProof,
        reentrantReleaseLeaf,
        reentrantReleaseEvidenceHash,
        { gasLimit: 500_000n },
      )
    ).wait();
    logStep("bond: release reentry armed");
    await expectRevert("bond impairment reentry", async () => {
      const tx = await reentrantBondTokenAdmin.impairBond(
        await bondVault.getAddress(),
        reentrantVaultId,
        400_000n,
        [wallets.beneficiary.address],
        [400_000n],
        oneLeafProof,
        reentrantSlashLeaf,
        reentrantSlashEvidenceHash,
        { gasLimit: 3_000_000n },
      );
      await tx.wait();
    });
    const [, reentrantLocked, reentrantSlashed, reentrantReleased, reentrantExpired] =
      await bondVault.getBond(reentrantVaultId);
    assert.equal(reentrantLocked, reentrantBondTerms.collateralAmount);
    assert.equal(reentrantSlashed, 0n);
    assert.equal(reentrantReleased, false);
    assert.equal(reentrantExpired, false);
    assert.equal(await reentrantBondToken.balanceOf(await bondVault.getAddress()), reentrantBondTerms.collateralAmount);
    checks.push({
      id: "bond.impair_release_reentry_accounting",
      outcome: "pass",
      note: "Bond impairment rejects token callbacks that reenter release.",
    });

    logStep("bond: qualifying deterministic identity under interleaving and replay");
    const driftBondTermsA = {
      bondId: toBytes32Label("bond:drift:a"),
      facilityId: toBytes32Label("facility:drift:a"),
      principal: wallets.principal.address,
      token: await mockUsdc.getAddress(),
      collateralAmount: 1_100_000n,
      reserveRequirementAmount: 275_000n,
      expiresAt: BigInt(now + 10800),
      reserveRequirementRatioBps: 2500,
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    const driftBondTermsB = {
      bondId: toBytes32Label("bond:drift:b"),
      facilityId: toBytes32Label("facility:drift:b"),
      principal: wallets.principal.address,
      token: await mockUsdc.getAddress(),
      collateralAmount: 1_200_000n,
      reserveRequirementAmount: 300_000n,
      expiresAt: BigInt(now + 10800),
      reserveRequirementRatioBps: 2500,
      operator: wallets.operator.address,
      operatorKeyHash: operatorEdKeyHash,
    };
    await (
      await mockUsdc
        .connect(wallets.principal)
        .approve(await bondVault.getAddress(), driftBondTermsA.collateralAmount + driftBondTermsB.collateralAmount)
    ).wait();
    const predictedVaultA = await bondVault.connect(wallets.principal).deriveVaultId(driftBondTermsA);
    const predictedVaultB = await bondVault.connect(wallets.principal).deriveVaultId(driftBondTermsB);
    const driftBondBTx = await bondVault.connect(wallets.principal).lockBond(driftBondTermsB);
    const driftBondBReceipt = await waitForReceipt(provider, driftBondBTx);
    const driftBondBEvent = await findContractEvent(driftBondBReceipt, bondVault, "BondLocked");
    assert.equal(driftBondBEvent.args.vaultId, predictedVaultB);
    const driftBondATx = await bondVault.connect(wallets.principal).lockBond(driftBondTermsA);
    const driftBondAReceipt = await waitForReceipt(provider, driftBondATx);
    const driftBondAEvent = await findContractEvent(driftBondAReceipt, bondVault, "BondLocked");
    assert.equal(driftBondAEvent.args.vaultId, predictedVaultA);
    await expectRevert("duplicate bond replay", async () => {
      const tx = await bondVault.connect(wallets.principal).lockBond(driftBondTermsA);
      await tx.wait();
    });

    const bondImpairEvidenceHash = toBytes32Label("bond-impair-evidence");
    const bondImpairDistributionHash = bondDistributionHash([wallets.beneficiary.address], [100_000n]);
    const bondImpairLeaf = bondProofLeaf(
      CHAIN_ID,
      await bondVault.getAddress(),
      predictedVaultA,
      operatorEdKeyHash,
      bondImpairEvidenceHash,
      BOND_ACTION_IMPAIR,
      100_000n,
      bondImpairDistributionHash,
    );
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, bondImpairEvidenceHash, 10, 11, 11, 1, operatorEdKeyHash)
    ).wait();
    await expectRevert("unbound bond impairment evidence", async () => {
      await bondVault
        .connect(wallets.operator)
        .impairBondDetailed.staticCall(
          predictedVaultA,
          125_000n,
          [wallets.beneficiary.address],
          [125_000n],
          oneLeafProof,
          bondImpairEvidenceHash,
          bondImpairEvidenceHash,
        );
    });
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, bondImpairLeaf, 11, 12, 12, 1, operatorEdKeyHash)
    ).wait();
    await (await bondVault.connect(adminRpcSigner).setPaused(true)).wait();
    await expectRevertSelector(
      "paused bond impairment",
      async () => {
        await bondVault
          .connect(wallets.operator)
          .impairBondDetailed.staticCall(
            predictedVaultA,
            100_000n,
            [wallets.beneficiary.address],
            [100_000n],
            oneLeafProof,
            bondImpairLeaf,
            bondImpairEvidenceHash,
          );
      },
      PAUSED_SELECTOR,
    );
    await (await bondVault.connect(adminRpcSigner).setPaused(false)).wait();
    await expectRevert("bond impairment leaf binds slash amount", async () => {
      await bondVault
        .connect(wallets.operator)
        .impairBondDetailed.staticCall(
          predictedVaultA,
          125_000n,
          [wallets.beneficiary.address],
          [125_000n],
          oneLeafProof,
          bondImpairLeaf,
          bondImpairEvidenceHash,
        );
    });
    await expectRevert("bond impairment leaf binds distribution", async () => {
      await bondVault
        .connect(wallets.operator)
        .impairBondDetailed.staticCall(
          predictedVaultA,
          100_000n,
          [wallets.outsider.address],
          [100_000n],
          oneLeafProof,
          bondImpairLeaf,
          bondImpairEvidenceHash,
        );
    });
    const excessiveImpairBeneficiaries = Array.from({ length: 17 }, (_, index) =>
      deterministicAddress(0x2000 + index),
    );
    const excessiveImpairShares = Array.from({ length: 17 }, () => 10_000n);
    const excessiveImpairEvidenceHash = toBytes32Label("bond-impair-excessive-beneficiaries");
    const excessiveImpairLeaf = bondProofLeaf(
      CHAIN_ID,
      await bondVault.getAddress(),
      predictedVaultA,
      operatorEdKeyHash,
      excessiveImpairEvidenceHash,
      BOND_ACTION_IMPAIR,
      170_000n,
      bondDistributionHash(excessiveImpairBeneficiaries, excessiveImpairShares),
    );
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, excessiveImpairLeaf, 12, 13, 13, 1, operatorEdKeyHash)
    ).wait();
    await expectRevert("bond impairment beneficiary cap", async () => {
      await bondVault
        .connect(wallets.operator)
        .impairBondDetailed.staticCall(
          predictedVaultA,
          170_000n,
          excessiveImpairBeneficiaries,
          excessiveImpairShares,
          oneLeafProof,
          excessiveImpairLeaf,
          excessiveImpairEvidenceHash,
        );
    });
    const zeroBeneficiaryEvidenceHash = toBytes32Label("bond-impair-zero-beneficiary");
    const zeroBeneficiaryLeaf = bondProofLeaf(
      CHAIN_ID,
      await bondVault.getAddress(),
      predictedVaultA,
      operatorEdKeyHash,
      zeroBeneficiaryEvidenceHash,
      BOND_ACTION_IMPAIR,
      100_000n,
      bondDistributionHash([ethers.ZeroAddress], [100_000n]),
    );
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, zeroBeneficiaryLeaf, 13, 14, 14, 1, operatorEdKeyHash)
    ).wait();
    await expectRevertSelector(
      "bond impairment zero beneficiary",
      async () => {
        await bondVault
          .connect(wallets.operator)
          .impairBondDetailed.staticCall(
            predictedVaultA,
            100_000n,
            [ethers.ZeroAddress],
            [100_000n],
            oneLeafProof,
            zeroBeneficiaryLeaf,
            zeroBeneficiaryEvidenceHash,
          );
      },
      INVALID_SLASH_DISTRIBUTION_SELECTOR,
    );
    const zeroEvidenceLeaf = bondProofLeaf(
      CHAIN_ID,
      await bondVault.getAddress(),
      predictedVaultA,
      operatorEdKeyHash,
      ZERO_BYTES32,
      BOND_ACTION_IMPAIR,
      100_000n,
      bondImpairDistributionHash,
    );
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, zeroEvidenceLeaf, 14, 15, 15, 1, operatorEdKeyHash)
    ).wait();
    await expectRevertSelector(
      "bond impairment zero evidence hash",
      async () => {
        await bondVault
          .connect(wallets.operator)
          .impairBondDetailed.staticCall(
            predictedVaultA,
            100_000n,
            [wallets.beneficiary.address],
            [100_000n],
            oneLeafProof,
            zeroEvidenceLeaf,
            ZERO_BYTES32,
          );
      },
      INVALID_EVIDENCE_SELECTOR,
    );
    await (
      await bondVault
        .connect(wallets.operator)
        .impairBondDetailed(
          predictedVaultA,
          100_000n,
          [wallets.beneficiary.address],
          [100_000n],
          oneLeafProof,
          bondImpairLeaf,
          bondImpairEvidenceHash,
        )
    ).wait();
    await expectRevert("replayed bond impairment evidence", async () => {
      await bondVault
        .connect(wallets.operator)
        .impairBondDetailed.staticCall(
          predictedVaultA,
          100_000n,
          [wallets.beneficiary.address],
          [100_000n],
          oneLeafProof,
          bondImpairLeaf,
          bondImpairEvidenceHash,
        );
    });
    const crossReplayBondImpairLeaf = bondProofLeaf(
      CHAIN_ID,
      await bondVault.getAddress(),
      predictedVaultB,
      operatorEdKeyHash,
      bondImpairEvidenceHash,
      BOND_ACTION_IMPAIR,
      100_000n,
      bondImpairDistributionHash,
    );
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, crossReplayBondImpairLeaf, 15, 16, 16, 1, operatorEdKeyHash)
    ).wait();
    await expectRevertSelector(
      "cross-vault bond evidence replay",
      async () => {
        await bondVault
          .connect(wallets.operator)
          .impairBondDetailed.staticCall(
            predictedVaultB,
            100_000n,
            [wallets.beneficiary.address],
            [100_000n],
            oneLeafProof,
            crossReplayBondImpairLeaf,
            bondImpairEvidenceHash,
          );
      },
      EVIDENCE_ALREADY_USED_SELECTOR,
    );
    const expiredReleaseEvidenceHash = toBytes32Label("bond-expired-release");
    const expiredReleaseLeaf = bondProofLeaf(
      CHAIN_ID,
      await bondVault.getAddress(),
      predictedVaultA,
      operatorEdKeyHash,
      expiredReleaseEvidenceHash,
      BOND_ACTION_RELEASE,
      0n,
      ZERO_BYTES32,
    );
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, expiredReleaseLeaf, 16, 17, 17, 1, operatorEdKeyHash)
    ).wait();
    const expiredImpairEvidenceHash = toBytes32Label("bond-expired-impair");
    const expiredImpairLeaf = bondProofLeaf(
      CHAIN_ID,
      await bondVault.getAddress(),
      predictedVaultA,
      operatorEdKeyHash,
      expiredImpairEvidenceHash,
      BOND_ACTION_IMPAIR,
      100_000n,
      bondImpairDistributionHash,
    );
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, expiredImpairLeaf, 17, 18, 18, 1, operatorEdKeyHash)
    ).wait();
    await mineAt(provider, Number(driftBondTermsA.expiresAt) + 1);
    await expectRevertSelector(
      "expired bond proof release",
      async () => {
        await bondVault
          .connect(wallets.operator)
          .releaseBondDetailed.staticCall(
            predictedVaultA,
            oneLeafProof,
            expiredReleaseLeaf,
            expiredReleaseEvidenceHash,
          );
      },
      BOND_NO_LONGER_LIVE_SELECTOR,
    );
    await expectRevertSelector(
      "expired bond proof impairment",
      async () => {
        await bondVault
          .connect(wallets.operator)
          .impairBondDetailed.staticCall(
            predictedVaultA,
            100_000n,
            [wallets.beneficiary.address],
            [100_000n],
            oneLeafProof,
            expiredImpairLeaf,
            expiredImpairEvidenceHash,
          );
      },
      BOND_NO_LONGER_LIVE_SELECTOR,
    );
    await (await bondVault.connect(adminRpcSigner).setPaused(true)).wait();
    assert.equal(
      await bondVault.paused(),
      true,
      "bond pause must be active while proving expired principal exit remains open",
    );
    const expiryTx = await bondVault
      .connect(await provider.getSigner(wallets.outsider.address))
      .expireRelease(predictedVaultA, { gasLimit: 250_000n });
    const expiryReceipt = await waitForReceipt(provider, expiryTx);
    const expiredEvent = await findContractEvent(expiryReceipt, bondVault, "BondExpired");
    assert.equal(expiredEvent.args.vaultId, predictedVaultA);
    assert.equal(expiredEvent.args.returnedAmount, driftBondTermsA.collateralAmount - 100_000n);
    const [, , expiredBondSlashed, expiredBondReleased, expiredBondExpired] =
      await bondVault.getBond(predictedVaultA);
    assert.equal(expiredBondSlashed, 100_000n);
    assert.equal(expiredBondReleased, false);
    assert.equal(expiredBondExpired, true);
    await (await bondVault.connect(adminRpcSigner).setPaused(false)).wait();
    checks.push({
      id: "bond.paused_expiry_principal_exit",
      outcome: "pass",
      note: "Expired bond principal recovery remains open while contract pause is active; pause gates lock, release, and impair paths, not post-expiry principal exit.",
    });
    checks.push({
      id: "bond.identity_reconciliation_under_nonce_drift",
      outcome: "pass",
      note: "Bond identity remains deterministic under interleaving submissions and duplicate replays fail closed.",
    });

    assertGasBudgets(gasEstimates);
    checks.push({
      id: "deployment.gas_budget",
      outcome: "pass",
      note: "Local-devnet gas estimates are within the deployment policy budgets.",
    });

    logStep("writing deployment and qualification reports");
    const localDeployment = {
      manifest_id: "chio.web3-deployment.local-devnet.v1",
      network_name: "Ganache Local Devnet",
      chain_id: `eip155:${chainId}`,
      rpc_url: RPC_URL,
      deployed_at: new Date().toISOString(),
      operator_address: wallets.operator.address,
      operator_epoch: Number(operatorEpoch),
      delegate_address: wallets.delegate.address,
      settlement_token_symbol: "mUSDC",
      settlement_token_address: await mockUsdc.getAddress(),
      contracts: {
        identity_registry: await identityRegistry.getAddress(),
        root_registry: await rootRegistry.getAddress(),
        escrow: await escrow.getAddress(),
        bond_vault: await bondVault.getAddress(),
        price_resolver: await priceResolver.getAddress(),
      },
      deployed_runtime_codehashes: deployedRuntimeCodehashes,
      mocks: {
        eth_usd_feed: await ethUsdFeed.getAddress(),
        sequencer_uptime_feed: await sequencerFeed.getAddress(),
      },
    };

    const qualificationReport = {
      report_id: "chio.web3-contract-qualification.local-devnet.v1",
      status: "pass",
      scope: "local-devnet",
      environment: "local-devnet",
      network_tier: "development",
      note: "Ephemeral local-devnet test run.",
      generated_at: new Date().toISOString(),
      chain_id: `eip155:${chainId}`,
      gas_estimates: gasEstimates,
      deployed_runtime_codehashes: deployedRuntimeCodehashes,
      checks,
    };

    fs.writeFileSync(
      path.join(deploymentsDir, "local-devnet.json"),
      `${JSON.stringify(normalizeBigints(localDeployment), null, 2)}\n`,
    );
    fs.writeFileSync(
      path.join(reportsDir, "local-devnet-qualification.json"),
      `${JSON.stringify(normalizeBigints(qualificationReport), null, 2)}\n`,
    );

    console.log(
      `Wrote Chio web3 local-devnet fixture at ${RPC_URL}. Reports written to contracts/deployments/local-devnet.json and contracts/reports/local-devnet-qualification.json.`,
    );
  } finally {
    provider?.destroy?.();
    server.close();
  }
}

await main();
