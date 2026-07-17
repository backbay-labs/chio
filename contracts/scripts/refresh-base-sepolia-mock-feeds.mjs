import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const contractsDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(contractsDir, "..");
const BASE_SEPOLIA_CHAIN_ID = 84532n;

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
  const dependenciesPath = args.dependencies
    ? path.resolve(repoRoot, args.dependencies)
    : path.join(repoRoot, "target", "web3-live-rollout", "base-sepolia", "dependencies", "dependencies.json");
  const outputPath = args.output
    ? path.resolve(repoRoot, args.output)
    : path.join(path.dirname(dependenciesPath), "feed-refresh.json");

  const dependencies = readJson(dependenciesPath);
  const artifact = readJson(path.join(contractsDir, "artifacts", "mocks", "MockAggregatorV3.json"));
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  try {
    const signer = new ethers.Wallet(deployerKey, provider);
    const network = await provider.getNetwork();
    if (network.chainId !== BASE_SEPOLIA_CHAIN_ID) {
      throw new Error(`expected Base Sepolia chain id ${BASE_SEPOLIA_CHAIN_ID}, got ${network.chainId}`);
    }
    if (dependencies.chain_id !== `eip155:${network.chainId}`) {
      throw new Error(`dependencies chain id ${dependencies.chain_id} does not match eip155:${network.chainId}`);
    }
    const refreshed = [];
    for (const [name, feed] of Object.entries(dependencies.mock_chainlink_feeds ?? {})) {
      const contract = new ethers.Contract(feed.address, artifact.abi, signer);
      let tx;
      const record = {
        name,
        address: feed.address,
        answer: BigInt(feed.answer)
      };
      if (name === "sequencer_uptime_feed") {
        const latestBlock = await provider.getBlock("latest");
        const updatedAt = BigInt(latestBlock.timestamp);
        const startedAt = updatedAt > 7200n ? updatedAt - 7200n : 1n;
        const roundId = BigInt(feed.round_id ?? 1);
        tx = await contract.setRoundData(roundId, BigInt(feed.answer), startedAt, updatedAt, roundId);
        record.started_at = startedAt;
        record.updated_at = updatedAt;
      } else {
        tx = await contract.setAnswer(BigInt(feed.answer));
      }
      const receipt = await tx.wait();
      refreshed.push({
        ...record,
        tx_hash: tx.hash,
        block_number: receipt.blockNumber,
        gas_used: receipt.gasUsed
      });
    }

    const report = {
      report_id: "chio.web3-base-sepolia-mock-feed-refresh.v1",
      generated_at: new Date().toISOString(),
      dependencies_path: repoRelative(dependenciesPath),
      chain_id: dependencies.chain_id,
      refreshed
    };
    writeJson(outputPath, report);
    process.stdout.write(`${JSON.stringify({ output: repoRelative(outputPath), refreshed: refreshed.length }, null, 2)}\n`);
  } finally {
    const destroyResult = provider.destroy?.();
    if (destroyResult && typeof destroyResult.then === "function") {
      await destroyResult;
    }
  }
}

await main();
