import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";
import ganache from "ganache";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const artifactsDir = path.join(rootDir, "artifacts");
const deploymentsDir = path.join(rootDir, "deployments");
const reportsDir = path.join(rootDir, "reports");

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
  ],
};
const ENTITY_BINDING_TYPES = {
  ChioEntityBinding: [
    { name: "chioEntityId", type: "bytes32" },
    { name: "settlementAddress", type: "address" },
    { name: "operator", type: "address" },
  ],
};
const BOND_PROOF_LEAF_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes(
    "ChioBondProof(uint256 chainId,address vault,bytes32 vaultId,bytes32 evidenceHash,uint8 action,uint256 slashAmount,bytes32 distributionHash)",
  ),
);
const ZERO_BYTES32 = ethers.ZeroHash;
const BOND_ACTION_RELEASE = 0;
const BOND_ACTION_IMPAIR = 1;
const PAUSED_SELECTOR = ethers.id("Paused()").slice(0, 10);
const INVALID_SIGNATURE_SELECTOR = ethers.id("InvalidSignature()").slice(0, 10);
const INVALID_TIMESTAMP_SELECTOR = ethers.id("InvalidTimestamp()").slice(0, 10);
const INVALID_SLASH_DISTRIBUTION_SELECTOR = ethers.id("InvalidSlashDistribution()").slice(0, 10);
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const ACCOUNT_CONFIG = [
  { name: "admin", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000001" },
  { name: "operator", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000002" },
  { name: "delegate", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000003" },
  { name: "beneficiary", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000004" },
  { name: "depositor", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000005" },
  { name: "principal", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000006" },
  { name: "outsider", privateKey: "0x1000000000000000000000000000000000000000000000000000000000000007" },
];

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function artifactPath(name) {
  return path.join(artifactsDir, `${name}.json`);
}

function readArtifact(name) {
  return JSON.parse(fs.readFileSync(artifactPath(name), "utf8"));
}

async function deploy(name, signer, ...args) {
  const artifact = readArtifact(name);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
  const contract = await factory.deploy(...args);
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

function bondProofLeaf(chainId, bondVaultAddress, vaultId, evidenceHash, action, slashAmount, distributionHash) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "address", "bytes32", "bytes32", "uint8", "uint256", "bytes32"],
      [
        BOND_PROOF_LEAF_TYPEHASH,
        BigInt(chainId),
        bondVaultAddress,
        vaultId,
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
    const escrow = await deploy(
      "ChioEscrow",
      wallets.admin,
      await rootRegistry.getAddress(),
      await identityRegistry.getAddress(),
      wallets.admin.address,
    );
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
    const bondVault = await deploy(
      "ChioBondVault",
      wallets.admin,
      await rootRegistry.getAddress(),
      await identityRegistry.getAddress(),
      wallets.admin.address,
    );
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
    checks.push({
      id: "deployment.constructor_wiring",
      outcome: "pass",
      note: "Root registry, escrow, and bond vault reject zero or non-contract registry addresses at construction.",
    });

    logStep("registering identity bindings");
    gasEstimates.register_operator = (
      await identityRegistry.registerOperator.estimateGas(
        wallets.operator.address,
        operatorEdKeyHash,
        wallets.operator.address,
        ethers.toUtf8Bytes("binding:operator"),
      )
    ).toString();
    await (
      await identityRegistry.registerOperator(
        wallets.operator.address,
        operatorEdKeyHash,
        wallets.operator.address,
        ethers.toUtf8Bytes("binding:operator"),
      )
    ).wait();
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
    const registerContractAdminOperatorCall = contractAdminRegistry.interface.encodeFunctionData(
      "registerOperator",
      [
        wallets.operator.address,
        contractAdminOperatorKeyHash,
        wallets.operator.address,
        ethers.toUtf8Bytes("binding:contract-admin-operator"),
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
    await (
      await identityRegistry.registerOperator(
        lifecycleOperator,
        lifecycleOperatorKeyHash,
        wallets.principal.address,
        ethers.toUtf8Bytes("binding:lifecycle-operator"),
      )
    ).wait();
    const lifecycleRecordBefore = await identityRegistry.getOperator(lifecycleOperator);
    await (await identityRegistry.deactivateOperator(lifecycleOperator)).wait();
    await (
      await identityRegistry.registerOperator(
        lifecycleOperator,
        replacementOperatorKeyHash,
        wallets.outsider.address,
        ethers.toUtf8Bytes("binding:replacement-operator"),
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

    await (
      await identityRegistry.registerOperator(
        await reentrantBondToken.getAddress(),
        reentrantOperatorKeyHash,
        await reentrantBondToken.getAddress(),
        ethers.toUtf8Bytes("binding:reentrant-operator"),
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
    await (
      await rootRegistry
        .connect(wallets.operator)
        .publishRoot(wallets.operator.address, operatorRoot, 1, 1, 1, 1, operatorEdKeyHash)
    ).wait();

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
    assert.equal(
      await rootRegistry.verifyInclusionDetailed(
        { auditPath: [proofLeafB], leafIndex: 0, treeSize: 2 },
        twoLeafRoot,
        proofLeafA,
        wallets.operator.address,
      ),
      true,
    );
    assert.equal(
      await rootRegistry.verifyInclusionDetailed(
        { auditPath: [], leafIndex: 0, treeSize: 1 },
        twoLeafRoot,
        twoLeafRoot,
        wallets.operator.address,
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
      note: "Price resolver rejects invalid feeds, stale feeds, zero or future sequencer timestamps, sequencer downtime, and sequencer grace-period reads.",
    });

    const oneLeafProof = { auditPath: [], leafIndex: 0, treeSize: 1 };
    const inactiveOperatorKeyHash = toBytes32Label("chio-inactive-operator-key");
    logStep("escrow: setting up inactive-operator release denial");
    await (
      await identityRegistry.registerOperator(
        wallets.outsider.address,
        inactiveOperatorKeyHash,
        wallets.outsider.address,
        ethers.toUtf8Bytes("binding:inactive-operator"),
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
    await (
      await identityRegistry.registerOperator(
        wallets.delegate.address,
        inactiveBondOperatorKeyHash,
        wallets.delegate.address,
        ethers.toUtf8Bytes("binding:inactive-bond-operator"),
      )
    ).wait();
    const inactiveBondEvidenceHash = toBytes32Label("inactive-operator-bond-evidence");
    const inactiveBondOperatorSigner = await provider.getSigner(wallets.delegate.address);
    await (
      await rootRegistry
        .connect(inactiveBondOperatorSigner)
        .publishRoot(
          wallets.delegate.address,
          inactiveBondEvidenceHash,
          1,
          1,
          1,
          1,
          inactiveBondOperatorKeyHash,
          { gasLimit: 500_000n },
        )
    ).wait();
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
    };
    await (
      await mockUsdc
        .connect(wallets.principal)
        .approve(await bondVault.getAddress(), inactiveOperatorBondTerms.collateralAmount)
    ).wait();
    const inactiveOperatorVaultId = await bondVault
      .connect(wallets.principal)
      .deriveVaultId(inactiveOperatorBondTerms);
    await (await bondVault.connect(wallets.principal).lockBond(inactiveOperatorBondTerms)).wait();
    await (await identityRegistry.deactivateOperator(wallets.delegate.address)).wait();
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
      id: "bond.inactive_operator_impair_denied",
      outcome: "pass",
      note: "Bond impairment rechecks operator activation before moving collateral.",
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
    };
    const signatureDigest = ethers.solidityPackedKeccak256(
      ["uint256", "address", "bytes32", "bytes32", "uint256"],
      [chainId, await escrow.getAddress(), signatureValue.escrowId, signatureValue.receiptHash, signatureValue.amount],
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
          malleatedTypedSignatureV,
          typedOperatorSignature.r,
          malleatedTypedSignatureS,
        );
    });
    logStep("escrow: invalid signature rejected");

    logStep("escrow: estimating valid dual-sign release gas");
    gasEstimates.dual_sign_release = (
      await escrow
        .connect(wallets.beneficiary)
        .releaseWithSignature.estimateGas(
          signatureValue.escrowId,
          signatureValue.receiptHash,
          signatureValue.amount,
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
    logStep("escrow: submitting refund transaction");
    const refundTx = await escrow
      .connect(refundRpcSigner)
      .refund(refundEscrowId, { gasLimit: 250_000n });
    await waitForReceipt(provider, refundTx);
    await (await escrow.connect(adminRpcSigner).setPaused(false)).wait();
    logStep("escrow: refund completed");
    checks.push({
      id: "escrow.timeout_refund",
      outcome: "pass",
      note: "Escrow refunds only after expiry and not before.",
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
      reentrantSlashEvidenceHash,
      BOND_ACTION_IMPAIR,
      400_000n,
      bondDistributionHash([wallets.beneficiary.address], [400_000n]),
    );
    const reentrantReleaseLeaf = bondProofLeaf(
      CHAIN_ID,
      await bondVault.getAddress(),
      reentrantVaultId,
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
    await (await bondVault.connect(adminRpcSigner).setPaused(true)).wait();
    await mineAt(provider, Number(driftBondTermsA.expiresAt) + 1);
    await (
      await bondVault
        .connect(await provider.getSigner(wallets.outsider.address))
        .expireRelease(predictedVaultA, { gasLimit: 250_000n })
    ).wait();
    const [, , expiredBondSlashed, expiredBondReleased, expiredBondExpired] =
      await bondVault.getBond(predictedVaultA);
    assert.equal(expiredBondSlashed, 100_000n);
    assert.equal(expiredBondReleased, false);
    assert.equal(expiredBondExpired, true);
    await (await bondVault.connect(adminRpcSigner).setPaused(false)).wait();
    checks.push({
      id: "bond.identity_reconciliation_under_nonce_drift",
      outcome: "pass",
      note: "Bond identity remains deterministic under interleaving submissions and duplicate replays fail closed.",
    });

    logStep("writing deployment and qualification reports");
    const localDeployment = {
      manifest_id: "chio.web3-deployment.local-devnet.v1",
      network_name: "Ganache Local Devnet",
      chain_id: `eip155:${chainId}`,
      rpc_url: RPC_URL,
      deployed_at: new Date().toISOString(),
      operator_address: wallets.operator.address,
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
