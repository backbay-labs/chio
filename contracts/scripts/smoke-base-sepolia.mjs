import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const contractsDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(contractsDir, "..");

const BASE_SEPOLIA_CHAIN_ID = 84532n;
const BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const ESCROW_PROOF_LEAF_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes(
    "ChioEscrowProof(uint256 chainId,address escrow,bytes32 escrowId,address token,address beneficiary,bytes32 operatorKeyHash,bytes32 receiptHash,uint256 amount,bool partial)"
  )
);
const ENTITY_BINDING_TYPES = {
  ChioEntityBinding: [
    { name: "chioEntityId", type: "bytes32" },
    { name: "settlementAddress", type: "address" },
    { name: "operator", type: "address" }
  ]
};
const OPERATOR_BINDING_TYPES = {
  ChioOperatorBinding: [
    { name: "operatorAddress", type: "address" },
    { name: "edKeyHash", type: "bytes32" },
    { name: "settlementKey", type: "address" }
  ]
};
const ERC20_ABI = [
  "function balanceOf(address account) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)"
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

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
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

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(normalize(value), null, 2)}\n`);
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

function readArtifact(name) {
  return readJson(path.join(contractsDir, "artifacts", name));
}

function labelHash(label) {
  return ethers.keccak256(ethers.toUtf8Bytes(label));
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
  isPartial
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
        "bool"
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
        isPartial
      ]
    )
  );
}

function entityBindingDomain(chainId, identityRegistryAddress) {
  return {
    name: "ChioIdentityRegistry",
    version: "1",
    chainId,
    verifyingContract: identityRegistryAddress
  };
}

async function waitForReceipt(tx) {
  const receipt = await tx.wait();
  if (receipt.status !== 1) {
    throw new Error(`transaction ${tx.hash} failed`);
  }
  return receipt;
}

async function waitForBlockAfter(provider, deadline, timeoutMs = 120_000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const block = await provider.getBlock("latest");
    if (BigInt(block.timestamp) > deadline) {
      return block;
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  throw new Error(`timed out waiting for block timestamp to pass ${deadline}`);
}

function txSummary(id, tx, receipt, extra = {}) {
  return {
    id,
    tx_hash: tx.hash,
    block_number: receipt.blockNumber,
    gas_used: receipt.gasUsed,
    ...extra
  };
}

function existingTxSummary(id, txHash, source, extra = {}) {
  if (!txHash) {
    return null;
  }
  return {
    id,
    tx_hash: txHash,
    source,
    ...extra
  };
}

async function refreshMockFeeds({ signer, dependenciesPath }) {
  if (!fs.existsSync(dependenciesPath)) {
    return [];
  }

  const dependencies = readJson(dependenciesPath);
  const artifact = readArtifact("mocks/MockAggregatorV3.json");
  const refreshed = [];
  for (const [name, feed] of Object.entries(dependencies.mock_chainlink_feeds ?? {})) {
    const contract = new ethers.Contract(feed.address, artifact.abi, signer);
    let tx;
    let extra = {
      address: feed.address,
      answer: BigInt(feed.answer)
    };
    if (name === "sequencer_uptime_feed") {
      const latestBlock = await signer.provider.getBlock("latest");
      const updatedAt = BigInt(latestBlock.timestamp);
      const startedAt = updatedAt > 7200n ? updatedAt - 7200n : 1n;
      const roundId = BigInt(feed.round_id ?? 1);
      tx = await contract.setRoundData(roundId, BigInt(feed.answer), startedAt, updatedAt, roundId);
      extra = {
        ...extra,
        started_at: startedAt,
        updated_at: updatedAt
      };
    } else {
      tx = await contract.setAnswer(BigInt(feed.answer));
    }
    const receipt = await waitForReceipt(tx);
    refreshed.push(txSummary(`feed.${name}.refresh`, tx, receipt, extra));
  }
  return refreshed;
}

async function readPrices(priceResolver) {
  const prices = {};
  for (const pair of ["ETH/USD", "BTC/USD", "USDC/USD", "LINK/USD"]) {
    const [base, quote] = pair.split("/");
    const result = await priceResolver.getPrice(labelHash(base), labelHash(quote));
    prices[pair] = {
      price: result[0],
      decimals: Number(result[1]),
      updated_at: result[2]
    };
  }
  return prices;
}

async function main() {
  const args = parseArgs(process.argv);
  const rpcUrl = requireValue("--rpc-url or CHIO_BASE_SEPOLIA_RPC_URL", args["rpc-url"] ?? process.env.CHIO_BASE_SEPOLIA_RPC_URL);
  const deployerKey = requireValue(
    "--deployer-key or CHIO_BASE_SEPOLIA_DEPLOYER_KEY",
    args["deployer-key"] ?? process.env.CHIO_BASE_SEPOLIA_DEPLOYER_KEY
  );
  const deploymentPath = args.deployment
    ? path.resolve(repoRoot, args.deployment)
    : path.join(repoRoot, "target", "web3-live-rollout", "base-sepolia", "promotion", "deployment.json");
  const dependenciesPath = args.dependencies
    ? path.resolve(repoRoot, args.dependencies)
    : path.join(repoRoot, "target", "web3-live-rollout", "base-sepolia", "dependencies", "dependencies.json");
  const outputPath = args.output
    ? path.resolve(repoRoot, args.output)
    : path.join(repoRoot, "target", "web3-live-rollout", "base-sepolia", "base-sepolia-smoke.json");

  const deployment = readJson(deploymentPath);
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = new ethers.Wallet(deployerKey, provider);

  try {
    const network = await provider.getNetwork();
    if (network.chainId !== BASE_SEPOLIA_CHAIN_ID) {
      throw new Error(`expected Base Sepolia chain id ${BASE_SEPOLIA_CHAIN_ID}, got ${network.chainId}`);
    }
    if (deployment.chain_id !== `eip155:${network.chainId}`) {
      throw new Error(`deployment chain id ${deployment.chain_id} does not match eip155:${network.chainId}`);
    }

    const addresses = deployment.deployed_contract_addresses;
    const identityRegistry = new ethers.Contract(
      requireValue("identity registry address", addresses["chio.identity-registry"]),
      readArtifact("ChioIdentityRegistry.json").abi,
      signer
    );
    const rootRegistry = new ethers.Contract(
      requireValue("root registry address", addresses["chio.root-registry"]),
      readArtifact("ChioRootRegistry.json").abi,
      signer
    );
    const escrow = new ethers.Contract(
      requireValue("escrow address", addresses["chio.escrow"]),
      readArtifact("ChioEscrow.json").abi,
      signer
    );
    const priceResolver = new ethers.Contract(
      requireValue("price resolver address", addresses["chio.price-resolver"]),
      readArtifact("ChioPriceResolver.json").abi,
      signer
    );
    const usdc = new ethers.Contract(BASE_SEPOLIA_USDC, ERC20_ABI, signer);

    const actor = await signer.getAddress();
    const identityAdmin = await identityRegistry.admin();
    let identityAdminSigner = signer;
    if (identityAdmin.toLowerCase() !== actor.toLowerCase()) {
      const identityAdminKey = requireValue(
        "--identity-admin-key or CHIO_BASE_SEPOLIA_IDENTITY_ADMIN_KEY",
        args["identity-admin-key"] ?? process.env.CHIO_BASE_SEPOLIA_IDENTITY_ADMIN_KEY
      );
      identityAdminSigner = new ethers.Wallet(identityAdminKey, provider);
      const suppliedAdmin = await identityAdminSigner.getAddress();
      if (suppliedAdmin.toLowerCase() !== identityAdmin.toLowerCase()) {
        throw new Error(`identity admin key resolves to ${suppliedAdmin}, expected ${identityAdmin}`);
      }
    }
    const operatorEdKeyHash = labelHash(process.env.CHIO_BASE_SEPOLIA_OPERATOR_ED_KEY_LABEL ?? "chio-base-sepolia-operator-ed25519-key");
    const runId = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
    const transactions = [];
    const checks = [];

    const initialEthBalance = await provider.getBalance(actor);
    const initialUsdcBalance = await usdc.balanceOf(actor);
    const totalRequiredUsdc = 300_000n;
    if (initialUsdcBalance < totalRequiredUsdc) {
      throw new Error(
        `Base Sepolia smoke requires at least ${ethers.formatUnits(totalRequiredUsdc, 6)} USDC for ${actor}; current balance is ${ethers.formatUnits(initialUsdcBalance, 6)}`
      );
    }

    const feedRefreshTransactions = await refreshMockFeeds({ signer, dependenciesPath });
    transactions.push(...feedRefreshTransactions);
    checks.push({
      id: "oracle.mock_feeds_refreshed",
      outcome: "pass",
      note: `Refreshed ${feedRefreshTransactions.length} mock Chainlink-compatible feeds before readback.`
    });

    const prices = await readPrices(priceResolver);
    checks.push({
      id: "oracle.price_readback",
      outcome: "pass",
      note: "Price resolver returned fresh ETH, BTC, USDC, and LINK prices."
    });

    const operatorRegistered = await identityRegistry.isOperator(actor);
    if (!operatorRegistered) {
      const tx = await identityRegistry.connect(identityAdminSigner).registerOperator(
        actor,
        operatorEdKeyHash,
        actor,
        await identityAdminSigner.signTypedData(
          entityBindingDomain(network.chainId, await identityRegistry.getAddress()),
          OPERATOR_BINDING_TYPES,
          {
            operatorAddress: actor,
            edKeyHash: operatorEdKeyHash,
            settlementKey: actor
          }
        )
      );
      const receipt = await waitForReceipt(tx);
      transactions.push(txSummary("identity.operator_registration", tx, receipt));
    } else {
      const priorOperatorTx = existingTxSummary(
        "identity.operator_registration",
        deployment.configuration_transactions?.operator_registration?.tx_hash,
        "deployment.configuration_transactions.operator_registration",
        { status: "already_registered" }
      );
      if (priorOperatorTx) {
        transactions.push(priorOperatorTx);
      }
    }
    checks.push({
      id: "identity.operator_registered",
      outcome: "pass",
      note: "Smoke signer is registered as the active Chio operator."
    });

    const entityId = labelHash(`base-sepolia-smoke-entity:${runId}`);
    const entityBindingSignature = await identityAdminSigner.signTypedData(
      entityBindingDomain(network.chainId, await identityRegistry.getAddress()),
      ENTITY_BINDING_TYPES,
      {
        chioEntityId: entityId,
        settlementAddress: actor,
        operator: actor
      }
    );
    const entityTx = await identityRegistry.registerEntity(
      entityId,
      actor,
      entityBindingSignature
    );
    const entityReceipt = await waitForReceipt(entityTx);
    transactions.push(txSummary("identity.entity_registration", entityTx, entityReceipt, { entity_id: entityId }));
    const entityAddress = await identityRegistry.getEntityAddress(entityId);
    if (entityAddress.toLowerCase() !== actor.toLowerCase()) {
      throw new Error(`registered entity ${entityId} resolved to ${entityAddress}, expected ${actor}`);
    }
    checks.push({
      id: "identity.entity_registration",
      outcome: "pass",
      note: "Operator registered a unique entity binding and read it back."
    });

    const authorizedPublisher = await rootRegistry.isAuthorizedPublisher(actor, actor);
    if (!authorizedPublisher) {
      const latestBlock = await provider.getBlock("latest");
      const delegateExpiry = BigInt(latestBlock.timestamp + 3600);
      const tx = await rootRegistry.registerDelegate(actor, delegateExpiry);
      const receipt = await waitForReceipt(tx);
      transactions.push(txSummary("anchor.delegate_registration", tx, receipt, { delegate_expiry: delegateExpiry }));
    }

    const partialReceiptHash = labelHash(`base-sepolia-smoke-partial:${runId}`);
    const finalReceiptHash = labelHash(`base-sepolia-smoke-final:${runId}`);

    if (!(await escrow.tokenAllowed(BASE_SEPOLIA_USDC))) {
      const allowTokenTx = await escrow.setTokenAllowed(BASE_SEPOLIA_USDC, true);
      const allowTokenReceipt = await waitForReceipt(allowTokenTx);
      transactions.push(txSummary("settlement.usdc_allowlist", allowTokenTx, allowTokenReceipt, {
        token: BASE_SEPOLIA_USDC
      }));
    }

    const allowance = await usdc.allowance(actor, await escrow.getAddress());
    if (allowance < totalRequiredUsdc) {
      const approveTx = await usdc.approve(await escrow.getAddress(), totalRequiredUsdc);
      const approveReceipt = await waitForReceipt(approveTx);
      transactions.push(txSummary("settlement.usdc_approval", approveTx, approveReceipt, {
        spender: await escrow.getAddress(),
        amount: totalRequiredUsdc
      }));
    }

    const latestBlock = await provider.getBlock("latest");
    const proof = { auditPath: [], leafIndex: 0, treeSize: 1 };
    const primaryTerms = {
      capabilityId: labelHash(`base-sepolia-smoke-primary:${runId}`),
      depositor: actor,
      beneficiary: actor,
      token: BASE_SEPOLIA_USDC,
      maxAmount: 200_000n,
      deadline: BigInt(latestBlock.timestamp + 3600),
      operator: actor,
      operatorKeyHash: operatorEdKeyHash
    };
    const primaryEscrowId = await escrow.deriveEscrowId(primaryTerms);
    const partialProofLeaf = escrowProofLeaf(
      network.chainId,
      await escrow.getAddress(),
      primaryEscrowId,
      primaryTerms.token,
      primaryTerms.beneficiary,
      primaryTerms.operatorKeyHash,
      partialReceiptHash,
      75_000n,
      true
    );
    const finalProofLeaf = escrowProofLeaf(
      network.chainId,
      await escrow.getAddress(),
      primaryEscrowId,
      primaryTerms.token,
      primaryTerms.beneficiary,
      primaryTerms.operatorKeyHash,
      finalReceiptHash,
      125_000n,
      false
    );
    const latestSeq = BigInt(await rootRegistry.getLatestSeq(actor));
    const partialRootTx = await rootRegistry.publishRoot(
      actor,
      partialProofLeaf,
      latestSeq + 1n,
      latestSeq + 1n,
      latestSeq + 1n,
      1n,
      operatorEdKeyHash
    );
    const partialRootReceipt = await waitForReceipt(partialRootTx);
    transactions.push(txSummary("anchor.partial_root_publish", partialRootTx, partialRootReceipt, {
      checkpoint_seq: latestSeq + 1n,
      root: partialProofLeaf,
      receipt_hash: partialReceiptHash
    }));

    const finalRootTx = await rootRegistry.publishRoot(
      actor,
      finalProofLeaf,
      latestSeq + 2n,
      latestSeq + 2n,
      latestSeq + 2n,
      1n,
      operatorEdKeyHash
    );
    const finalRootReceipt = await waitForReceipt(finalRootTx);
    transactions.push(txSummary("anchor.final_root_publish", finalRootTx, finalRootReceipt, {
      checkpoint_seq: latestSeq + 2n,
      root: finalProofLeaf,
      receipt_hash: finalReceiptHash
    }));
    checks.push({
      id: "anchor.root_publication",
      outcome: "pass",
      note: "Operator published fresh partial and final roots for proof-backed releases."
    });
    const createPrimaryTx = await escrow.createEscrow(primaryTerms);
    const createPrimaryReceipt = await waitForReceipt(createPrimaryTx);
    transactions.push(txSummary("settlement.primary_escrow_create", createPrimaryTx, createPrimaryReceipt, {
      escrow_id: primaryEscrowId,
      amount: primaryTerms.maxAmount
    }));

    const partialReleaseTx = await escrow.partialReleaseWithProofDetailed(
      primaryEscrowId,
      proof,
      partialProofLeaf,
      partialReceiptHash,
      75_000n
    );
    const partialReleaseReceipt = await waitForReceipt(partialReleaseTx);
    transactions.push(txSummary("settlement.partial_release", partialReleaseTx, partialReleaseReceipt, {
      escrow_id: primaryEscrowId,
      amount: 75_000n
    }));

    const finalReleaseTx = await escrow.releaseWithProofDetailed(
      primaryEscrowId,
      proof,
      finalProofLeaf,
      finalReceiptHash,
      125_000n
    );
    const finalReleaseReceipt = await waitForReceipt(finalReleaseTx);
    transactions.push(txSummary("settlement.final_release", finalReleaseTx, finalReleaseReceipt, {
      escrow_id: primaryEscrowId,
      amount: 125_000n
    }));
    const primarySnapshot = await escrow.getEscrow(primaryEscrowId);
    if (primarySnapshot.released !== primaryTerms.maxAmount) {
      throw new Error(`primary escrow released ${primarySnapshot.released}, expected ${primaryTerms.maxAmount}`);
    }
    checks.push({
      id: "settlement.partial_and_final_release",
      outcome: "pass",
      note: "USDC escrow was created, partially released by proof, then fully released by proof."
    });

    const refundStartBlock = await provider.getBlock("latest");
    const refundTerms = {
      capabilityId: labelHash(`base-sepolia-smoke-refund:${runId}`),
      depositor: actor,
      beneficiary: actor,
      token: BASE_SEPOLIA_USDC,
      maxAmount: 100_000n,
      deadline: BigInt(refundStartBlock.timestamp + 10),
      operator: actor,
      operatorKeyHash: operatorEdKeyHash
    };
    const refundEscrowId = await escrow.deriveEscrowId(refundTerms);
    const refundCreateTx = await escrow.createEscrow(refundTerms);
    const refundCreateReceipt = await waitForReceipt(refundCreateTx);
    transactions.push(txSummary("settlement.refund_escrow_create", refundCreateTx, refundCreateReceipt, {
      escrow_id: refundEscrowId,
      amount: refundTerms.maxAmount,
      deadline: refundTerms.deadline
    }));

    await waitForBlockAfter(provider, refundTerms.deadline);
    const refundTx = await escrow.refund(refundEscrowId);
    const refundReceipt = await waitForReceipt(refundTx);
    transactions.push(txSummary("settlement.timeout_refund", refundTx, refundReceipt, {
      escrow_id: refundEscrowId,
      amount: refundTerms.maxAmount
    }));
    const refundSnapshot = await escrow.getEscrow(refundEscrowId);
    if (!refundSnapshot.refunded) {
      throw new Error(`refund escrow ${refundEscrowId} was not marked refunded`);
    }
    checks.push({
      id: "settlement.timeout_refund",
      outcome: "pass",
      note: "Short-deadline USDC escrow was refunded after Base Sepolia block time passed the deadline."
    });

    const finalEthBalance = await provider.getBalance(actor);
    const finalUsdcBalance = await usdc.balanceOf(actor);
    writeJson(outputPath, {
      report_id: "chio.web3-base-sepolia-smoke.v1",
      generated_at: new Date().toISOString(),
      status: "pass",
      chain_id: `eip155:${network.chainId}`,
      deployment_path: repoRelative(deploymentPath),
      deployment_id: deployment.deployment_id,
      actor,
      contracts: addresses,
      balances: {
        initial_eth: ethers.formatEther(initialEthBalance),
        final_eth: ethers.formatEther(finalEthBalance),
        initial_usdc: ethers.formatUnits(initialUsdcBalance, 6),
        final_usdc: ethers.formatUnits(finalUsdcBalance, 6)
      },
      prices,
      checks,
      transactions,
      escrows: {
        primary: {
          escrow_id: primaryEscrowId,
          deposited: primarySnapshot.deposited,
          released: primarySnapshot.released,
          refunded: primarySnapshot.refunded
        },
        refund: {
          escrow_id: refundEscrowId,
          deposited: refundSnapshot.deposited,
          released: refundSnapshot.released,
          refunded: refundSnapshot.refunded
        }
      }
    });

    process.stdout.write(`${JSON.stringify({ status: "pass", output: repoRelative(outputPath), transactions: transactions.length }, null, 2)}\n`);
  } finally {
    const destroyResult = provider.destroy?.();
    if (destroyResult && typeof destroyResult.then === "function") {
      await destroyResult;
    }
  }
}

await main();
