import fs from "node:fs";
import path from "node:path";
import { keccak256 } from "ethers";
import solc from "solc";

const root = new URL("..", import.meta.url).pathname;
const srcDir = path.join(root, "src");
const artifactsDir = path.join(root, "artifacts");

function walkSolidityFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkSolidityFiles(fullPath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".sol")) {
      files.push(fullPath);
    }
  }
  return files;
}

function toSourceKey(filePath) {
  return path.relative(root, filePath).replaceAll(path.sep, "/");
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function hashBytecode(bytecode) {
  if (!bytecode) {
    return "";
  }
  return keccak256(`0x${bytecode}`);
}

const sourceFiles = walkSolidityFiles(srcDir);
const sources = Object.fromEntries(
  sourceFiles.map((filePath) => [
    toSourceKey(filePath),
    { content: fs.readFileSync(filePath, "utf8") },
  ]),
);

const input = {
  language: "Solidity",
  sources,
  settings: {
    optimizer: { enabled: true, runs: 200 },
    evmVersion: "paris",
    outputSelection: {
      "*": {
        "*": [
          "abi",
          "evm.bytecode.object",
          "evm.deployedBytecode.object",
          "evm.deployedBytecode.immutableReferences",
          "metadata",
        ],
      },
    },
  },
};

const output = JSON.parse(solc.compile(JSON.stringify(input)));
if (output.errors) {
  let hasError = false;
  for (const error of output.errors) {
    const line = `${error.severity}: ${error.formattedMessage}`;
    if (error.severity === "error") {
      hasError = true;
      console.error(line);
    } else {
      console.warn(line);
    }
  }
  if (hasError) {
    process.exit(1);
  }
}

ensureDir(artifactsDir);
for (const [sourceName, contracts] of Object.entries(output.contracts ?? {})) {
  for (const [contractName, artifact] of Object.entries(contracts)) {
    const sourceStem = sourceName.replace(/^src\//, "").replace(/\.sol$/, "");
    const outDir = path.join(artifactsDir, path.dirname(sourceStem));
    const bytecode = artifact.evm?.bytecode?.object ?? "";
    const deployedBytecode = artifact.evm?.deployedBytecode?.object ?? "";
    const immutableReferences = artifact.evm?.deployedBytecode?.immutableReferences ?? {};
    ensureDir(outDir);
    fs.writeFileSync(
      path.join(outDir, `${contractName}.json`),
      `${JSON.stringify(
        {
          contractName,
          sourceName,
          abi: artifact.abi,
          bytecode,
          deployedBytecode,
          immutableReferences,
          creationBytecodeHash: hashBytecode(bytecode),
          deployedRuntimeCodehash: hashBytecode(deployedBytecode),
          metadata: artifact.metadata,
        },
        null,
        2,
      )}\n`,
    );
  }
}

console.log(`Compiled ${sourceFiles.length} Solidity sources.`);
