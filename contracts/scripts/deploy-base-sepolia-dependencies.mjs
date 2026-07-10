import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const contractsDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(contractsDir, "..");

const BASE_SEPOLIA_CHAIN_ID = 84532n;
const BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const ERC8021_MARKER = "80218021802180218021802180218021";
const ERC20_BALANCE_ABI = ["function balanceOf(address account) view returns (uint256)"];

const MOCK_FEEDS = [
  {
    key: "base_sepolia_sequencer_uptime_feed",
    outputKey: "sequencer_uptime_feed",
    decimals: 0,
    description: "Base Sepolia Sequencer Uptime",
    answer: 0n
  },
  {
    key: "base_sepolia_eth_usd_feed",
    outputKey: "eth_usd_feed",
    decimals: 8,
    description: "ETH / USD",
    answer: 3000n * 10n ** 8n
  },
  {
    key: "base_sepolia_btc_usd_feed",
    outputKey: "btc_usd_feed",
    decimals: 8,
    description: "BTC / USD",
    answer: 65000n * 10n ** 8n
  },
  {
    key: "base_sepolia_usdc_usd_feed",
    outputKey: "usdc_usd_feed",
    decimals: 8,
    description: "USDC / USD",
    answer: 1n * 10n ** 8n
  },
  {
    key: "base_sepolia_link_usd_feed",
    outputKey: "link_usd_feed",
    decimals: 8,
    description: "LINK / USD",
    answer: 15n * 10n ** 8n
  }
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

function requireBytes32(label, value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be a bytes32 hex string`);
  }
  return value;
}

function readArtifact(name) {
  return readJson(path.join(contractsDir, "artifacts", name));
}

function createSigner(privateKey, provider) {
  const rawWallet = new ethers.Wallet(privateKey, provider);
  const signer = new ethers.NonceManager(rawWallet);
  signer.address = rawWallet.address;
  return signer;
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

async function deployArtifact({ artifact, signer, args }) {
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  const deploymentTx = contract.deploymentTransaction();
  const receipt = deploymentTx ? await deploymentTx.wait() : null;
  return {
    address: await contract.getAddress(),
    tx_hash: deploymentTx?.hash ?? null,
    block_number: receipt?.blockNumber ?? null,
    gas_used: receipt?.gasUsed ?? null
  };
}

async function readUsdcBalance(provider, address) {
  const usdc = new ethers.Contract(BASE_SEPOLIA_USDC, ERC20_BALANCE_ABI, provider);
  return await usdc.balanceOf(address);
}

async function main() {
  const args = parseArgs(process.argv);
  const rpcUrl = requireValue(
    "--rpc-url or CHIO_BASE_SEPOLIA_RPC_URL",
    args["rpc-url"] ?? process.env.CHIO_BASE_SEPOLIA_RPC_URL
  );
  const deployerKey = requireValue(
    "--deployer-key or CHIO_BASE_SEPOLIA_DEPLOYER_KEY",
    args["deployer-key"] ?? process.env.CHIO_BASE_SEPOLIA_DEPLOYER_KEY
  );
  const outputDir = args["output-dir"]
    ? path.resolve(repoRoot, args["output-dir"])
    : path.join(repoRoot, "target", "web3-live-rollout", "base-sepolia", "dependencies");
  const roleAddressInput =
    args["role-address"] ?? process.env.CHIO_BASE_SEPOLIA_ROLE_ADDRESS ?? process.env.CHIO_BASE_SEPOLIA_WALLET;
  const operatorEdKeyLabel =
    args["operator-ed-key-label"] ?? process.env.CHIO_BASE_SEPOLIA_OPERATOR_ED_KEY_LABEL ?? "chio-base-sepolia-operator-ed25519-key";
  const operatorKeyHash = requireBytes32(
    "--operator-key-hash or CHIO_BASE_SEPOLIA_OPERATOR_KEY_HASH",
    requireValue(
      "--operator-key-hash or CHIO_BASE_SEPOLIA_OPERATOR_KEY_HASH",
      args["operator-key-hash"] ?? process.env.CHIO_BASE_SEPOLIA_OPERATOR_KEY_HASH
    )
  );
  const delegateExpirySeconds = Number(
    args["delegate-expiry-seconds"] ?? process.env.CHIO_BASE_SEPOLIA_DELEGATE_EXPIRY_SECONDS ?? 3600
  );
  const builderCode = args["base-builder-code"] ?? process.env.CHIO_BASE_BUILDER_CODE ?? null;

  if (!Number.isFinite(delegateExpirySeconds) || delegateExpirySeconds <= 0) {
    throw new Error("delegate expiry seconds must be a positive integer");
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  try {
    const signer = createSigner(deployerKey, provider);
    const roleAddress = roleAddressInput ?? signer.address;
    if (!ethers.isAddress(roleAddress)) {
      throw new Error("role address must be a valid EVM address");
    }

    const network = await provider.getNetwork();
    if (network.chainId !== BASE_SEPOLIA_CHAIN_ID) {
      throw new Error(`expected Base Sepolia chain id ${BASE_SEPOLIA_CHAIN_ID}, got ${network.chainId}`);
    }

    const deployerBalance = await provider.getBalance(signer.address);
    const usdcBalance = await readUsdcBalance(provider, roleAddress);
    const preflightWarnings = [];
    if (deployerBalance < ethers.parseEther("0.001")) {
      preflightWarnings.push(
        "Deployer balance is below the recommended 0.001 Base Sepolia ETH buffer for dependency plus core rollout."
      );
    }

    const create2FactoryArtifact = readArtifact("mocks/ChioCreate2Factory.json");
    const mockFeedArtifact = readArtifact("mocks/MockAggregatorV3.json");

    const create2Factory = await deployArtifact({
      artifact: create2FactoryArtifact,
      signer,
      args: []
    });

    const feedDeployments = {};
    const placeholderValues = {};
    for (const feed of MOCK_FEEDS) {
      const deployment = await deployArtifact({
        artifact: mockFeedArtifact,
        signer,
        args: [feed.decimals, feed.description, feed.answer]
      });
      feedDeployments[feed.outputKey] = {
        ...deployment,
        placeholder: feed.key,
        decimals: feed.decimals,
        description: feed.description,
        answer: feed.answer
      };
      placeholderValues[feed.key] = deployment.address;
    }

    const dependenciesPath = path.join(outputDir, "dependencies.json");
    const reviewInputsPath = path.join(outputDir, "base-sepolia.review-inputs.json");
    const dataSuffix = builderCode ? encodeBaseBuilderDataSuffix(builderCode) : null;

    const dependencyReport = {
      report_id: "chio.web3-base-sepolia-dependencies.v1",
      generated_at: new Date().toISOString(),
      chain_id: `eip155:${network.chainId}`,
      deployer_address: signer.address,
      role_address: ethers.getAddress(roleAddress),
      preflight: {
        deployer_eth_balance: ethers.formatEther(deployerBalance),
        role_usdc_balance: ethers.formatUnits(usdcBalance, 6),
        warnings: preflightWarnings
      },
      create2_factory: create2Factory,
      mock_chainlink_feeds: feedDeployments,
      attribution: dataSuffix
        ? {
            base_builder_code: builderCode,
            data_suffix_sha256: ethers.sha256(dataSuffix),
            erc8021_marker: `0x${ERC8021_MARKER}`
          }
        : null,
      outputs: {
        review_inputs_path: repoRelative(reviewInputsPath)
      }
    };

    const reviewInputs = {
      role_address: ethers.getAddress(roleAddress),
      operator_ed_key_label: operatorEdKeyLabel,
      operator_key_hash: operatorKeyHash,
      delegate_expiry_seconds: delegateExpirySeconds,
      create2_factory_mode: "predeployed",
      create2_factory_address: create2Factory.address,
      placeholders: placeholderValues,
      testnet_dependency_source: {
        kind: "mock-chainlink-feeds",
        report_path: repoRelative(dependenciesPath),
        note: "Base Sepolia public-chain rehearsal uses deployed mock aggregators when canonical Chainlink testnet feed inventory is unavailable. Mainnet manifests must use reviewed live Chainlink feed addresses."
      }
    };

    if (builderCode) {
      reviewInputs.base_builder_code = builderCode;
    }

    writeJson(dependenciesPath, dependencyReport);
    writeJson(reviewInputsPath, reviewInputs);

    process.stdout.write(
      `${JSON.stringify(
        {
          dependencies_path: repoRelative(dependenciesPath),
          review_inputs_path: repoRelative(reviewInputsPath),
          create2_factory_address: create2Factory.address,
          warnings: preflightWarnings
        },
        null,
        2
      )}\n`
    );
  } finally {
    const destroyResult = provider.destroy?.();
    if (destroyResult && typeof destroyResult.then === "function") {
      await destroyResult;
    }
  }
}

await main();
