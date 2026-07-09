import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";
import ganache from "ganache";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const artifactsDir = path.join(rootDir, "artifacts");
const deploymentsDir = process.env.CHIO_RUNTIME_DEPLOYMENT_DIR
  ? path.resolve(process.env.CHIO_RUNTIME_DEPLOYMENT_DIR)
  : path.join(rootDir, "deployments");

const PORT = Number(process.env.CHIO_DEVNET_PORT ?? "8547");
const RPC_URL = `http://127.0.0.1:${PORT}`;
const CHAIN_ID = 31337;
const USDC_UNITS = 10n ** 6n;
const DEPLOYMENT_NAME = process.env.CHIO_RUNTIME_DEPLOYMENT_NAME ?? "runtime-devnet.json";
const OPERATOR_ED_KEY_HASH = process.env.CHIO_OPERATOR_ED_KEY_HASH;
const OPERATOR_BINDING_TYPES = {
  ChioOperatorBinding: [
    { name: "operatorAddress", type: "address" },
    { name: "edKeyHash", type: "bytes32" },
    { name: "settlementKey", type: "address" },
  ],
};

if (!OPERATOR_ED_KEY_HASH) {
  throw new Error("CHIO_OPERATOR_ED_KEY_HASH is required");
}

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

async function operatorBindingSignature(chainId, identityRegistryAddress, adminPrivateKey, operatorAddress, edKeyHash, settlementKey) {
  return new ethers.Wallet(adminPrivateKey).signTypedData(
    {
      name: "ChioIdentityRegistry",
      version: "1",
      chainId,
      verifyingContract: identityRegistryAddress,
    },
    OPERATOR_BINDING_TYPES,
    { operatorAddress, edKeyHash, settlementKey },
  );
}

function toHexBalance(amount) {
  return ethers.toBeHex(amount);
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

let server;
let provider;

async function main() {
  ensureDir(deploymentsDir);

  server = ganache.server({
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

  const nowBlock = await provider.getBlock("latest");
  const now = Number(nowBlock.timestamp);

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
  const identityRegistry = await deploy("ChioIdentityRegistry", wallets.admin, wallets.admin.address);
  const rootRegistry = await deploy(
    "ChioRootRegistry",
    wallets.admin,
    await identityRegistry.getAddress(),
  );
  const escrow = await deploy(
    "ChioEscrow",
    wallets.admin,
    await rootRegistry.getAddress(),
    await identityRegistry.getAddress(),
    wallets.admin.address,
  );
  const bondVault = await deploy(
    "ChioBondVault",
    wallets.admin,
    await rootRegistry.getAddress(),
    await identityRegistry.getAddress(),
    wallets.admin.address,
  );
  const priceResolver = await deploy(
    "ChioPriceResolver",
    wallets.admin,
    wallets.admin.address,
    await sequencerFeed.getAddress(),
  );

  await (
    await identityRegistry.registerOperator(
      wallets.operator.address,
      OPERATOR_ED_KEY_HASH,
      wallets.operator.address,
      await operatorBindingSignature(
        CHAIN_ID,
        await identityRegistry.getAddress(),
        wallets.admin.privateKey,
        wallets.operator.address,
        OPERATOR_ED_KEY_HASH,
        wallets.operator.address,
      ),
    )
  ).wait();
  const operatorRecord = await identityRegistry.getOperator(wallets.operator.address);
  await (await escrow.setTokenAllowed(await mockUsdc.getAddress(), true)).wait();
  await (await bondVault.setTokenAllowed(await mockUsdc.getAddress(), true)).wait();
  await (
    await rootRegistry
      .connect(wallets.operator)
      .registerDelegate(wallets.delegate.address, BigInt(now + 3600))
  ).wait();

  await (await mockUsdc.mint(wallets.depositor.address, 5_000_000n * USDC_UNITS)).wait();
  await (await mockUsdc.mint(wallets.principal.address, 5_000_000n * USDC_UNITS)).wait();
  await (
    await priceResolver.registerFeed(
      ethers.keccak256(ethers.toUtf8Bytes("ETH")),
      ethers.keccak256(ethers.toUtf8Bytes("USD")),
      await ethUsdFeed.getAddress(),
      3600,
    )
  ).wait();

  const deploymentPath = path.join(deploymentsDir, DEPLOYMENT_NAME);
  const deployment = {
    manifest_id: "chio.web3-deployment.runtime-devnet.v1",
    network_name: "Ganache Runtime Devnet",
    chain_id: `eip155:${CHAIN_ID}`,
    rpc_url: RPC_URL,
    deployed_at: new Date().toISOString(),
    operator_address: wallets.operator.address,
    operator_epoch: Number(operatorRecord.operatorEpoch),
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
    accounts: Object.fromEntries(
      Object.entries(wallets).map(([name, wallet]) => [name, wallet.address]),
    ),
  };

  fs.writeFileSync(deploymentPath, `${JSON.stringify(normalizeBigints(deployment), null, 2)}\n`);
  console.log(`CHIO_DEVNET_READY ${deploymentPath}`);
}

function shutdown(code = 0) {
  Promise.resolve()
    .then(async () => {
      provider?.destroy?.();
      await new Promise((resolve) => server?.close(() => resolve()));
    })
    .finally(() => process.exit(code));
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));

await main();
await new Promise(() => {});
