import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { dirname, extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJsonBytes } from "./canonical.js";
import type { Receipt_InclusionProof } from "./_generated/index.js";

export type ReceiptInclusionProof =
  Receipt_InclusionProof.ChioReceiptMerkleInclusionProof;

export type HexHash = `0x${string}`;

export interface ReplayManifest {
  schema_version: "v1";
  family: string;
  name: string;
  intent: string;
  clock: string;
  expected_verdict: string;
  expected_failure_class: string | null;
  fixed_nonce_seed_index: number;
  tags: string[];
}

export interface ReplayScenario {
  manifestPath: string;
  family: string;
  scenarioLeaf: string;
  name: string;
  manifest: ReplayManifest;
}

export interface ReplayReceipt {
  scenario: string;
  verdict: string;
  nonce: string;
}

export interface ReplayCheckpoint {
  scenario: string;
  clock: string;
  issuer: string;
}

export interface ReplayAnchoredRootTuple {
  receipt_id: string;
  leaf_hash: HexHash;
  inclusion_proof: ReceiptInclusionProof;
  root: HexHash;
}

export interface ReplayScenarioOutput {
  scenario: ReplayScenario;
  receipt: ReplayReceipt;
  checkpoint: ReplayCheckpoint;
  receiptBytes: Uint8Array;
  checkpointBytes: Uint8Array;
  phase1RootHex: string;
  anchoredRoot: ReplayAnchoredRootTuple;
}

export interface ReplayRunnerOptions {
  fixturesRoot?: string | URL;
  expectedCount?: number;
}

export type ReplayAnchoredRootTupleList = ReplayAnchoredRootTuple[];

export class ReplayScenarioError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReplayScenarioError";
  }
}

export const DEFAULT_REPLAY_FIXTURE_COUNT = 50;
export const REPLAY_SCHEMA_VERSION = "v1";
export const REPLAY_TEST_KEY_VERIFYING_KEY_HEX =
  "801e0fd63c1b9903dac8a19a6390321e571872eca0d049329baccdc6fe8e9c36";

const FIXED_CLOCK_EPOCH_MS = 1_767_225_600_000n;
const HASH_RE = /^0x[0-9a-f]{64}$/u;
const BARE_HASH_RE = /^[0-9a-f]{64}$/u;

export async function resolveDefaultReplayFixturesRoot(): Promise<string> {
  const starts = [
    process.cwd(),
    dirname(fileURLToPath(import.meta.url)),
  ];

  for (const start of starts) {
    const found = await findReplayFixturesRoot(start);
    if (found != null) {
      return found;
    }
  }

  throw new ReplayScenarioError(
    "could not find tests/replay/fixtures from the current working directory or module path",
  );
}

export async function enumerateReplayScenarios(
  fixturesRoot?: string | URL,
): Promise<ReplayScenario[]> {
  const root = fixturesRoot == null
    ? await resolveDefaultReplayFixturesRoot()
    : pathFromInput(fixturesRoot);

  const manifests = await walkJsonFiles(root);
  return Promise.all(manifests.map((manifestPath) => loadReplayScenario(manifestPath)));
}

export async function loadReplayScenario(
  manifestPath: string | URL,
): Promise<ReplayScenario> {
  const path = pathFromInput(manifestPath);
  const raw = await readFile(path, "utf8").catch((err: unknown) => {
    throw new ReplayScenarioError(`failed to read replay manifest ${path}: ${String(err)}`);
  });

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new ReplayScenarioError(`failed to parse replay manifest ${path}: ${String(err)}`);
  }

  const manifest = parseReplayManifest(parsed, path);
  const scenarioLeaf = leafFromScenarioName(manifest.name, path);
  return {
    manifestPath: path,
    family: manifest.family,
    scenarioLeaf,
    name: manifest.name,
    manifest,
  };
}

export function runReplayScenario(scenario: ReplayScenario): ReplayScenarioOutput {
  const receipt = buildReplayReceipt(scenario.manifest);
  const checkpoint = buildReplayCheckpoint(scenario.manifest);
  const receiptBytes = canonicalJsonBytes(receipt);
  const checkpointBytes = canonicalJsonBytes(checkpoint);
  const phase1RootHex = sha256Hex(concatBytes(receiptBytes, checkpointBytes));
  const anchoredRoot = buildAnchoredRootTuple({
    receiptId: scenario.name,
    receiptIndex: 0,
    receipts: [receiptBytes],
  });

  return {
    scenario,
    receipt,
    checkpoint,
    receiptBytes,
    checkpointBytes,
    phase1RootHex,
    anchoredRoot,
  };
}

export async function runReplayManifest(
  manifestPath: string | URL,
): Promise<ReplayScenarioOutput> {
  return runReplayScenario(await loadReplayScenario(manifestPath));
}

export async function runReplayScenarios(
  options: ReplayRunnerOptions = {},
): Promise<ReplayScenarioOutput[]> {
  const expectedCount = options.expectedCount ?? DEFAULT_REPLAY_FIXTURE_COUNT;
  const scenarios = await enumerateReplayScenarios(options.fixturesRoot);
  if (scenarios.length !== expectedCount) {
    throw new ReplayScenarioError(
      `expected ${expectedCount} replay manifests, found ${scenarios.length}`,
    );
  }
  return scenarios.map((scenario) => runReplayScenario(scenario));
}

export function anchoredRootTuplesForReplayOutputs(
  outputs: readonly ReplayScenarioOutput[],
): ReplayAnchoredRootTupleList {
  return outputs.map((output) => output.anchoredRoot);
}

export async function runReplayAnchoredRootTuples(
  options: ReplayRunnerOptions = {},
): Promise<ReplayAnchoredRootTupleList> {
  return anchoredRootTuplesForReplayOutputs(await runReplayScenarios(options));
}

export function buildReplayReceipt(manifest: ReplayManifest): ReplayReceipt {
  return {
    scenario: manifest.name,
    verdict: manifest.expected_verdict,
    nonce: nonceHexForSeedIndex(manifest.fixed_nonce_seed_index),
  };
}

export function buildReplayCheckpoint(manifest: ReplayManifest): ReplayCheckpoint {
  return {
    scenario: manifest.name,
    clock: manifest.clock,
    issuer: REPLAY_TEST_KEY_VERIFYING_KEY_HEX,
  };
}

export function buildAnchoredRootTuple(args: {
  receiptId: string;
  receipts: readonly Uint8Array[];
  receiptIndex: number;
}): ReplayAnchoredRootTuple {
  const { receiptId, receipts, receiptIndex } = args;
  if (receiptId.length === 0) {
    throw new ReplayScenarioError("receiptId must be non-empty");
  }
  if (!Number.isSafeInteger(receiptIndex) || receiptIndex < 0) {
    throw new ReplayScenarioError(`receiptIndex must be a non-negative safe integer: ${receiptIndex}`);
  }
  if (receiptIndex >= receipts.length) {
    throw new ReplayScenarioError(
      `receiptIndex ${receiptIndex} is outside receipt set of size ${receipts.length}`,
    );
  }

  const tree = buildMerkleTree(receipts);
  const leafHash = tree.leafHashes[receiptIndex];
  if (leafHash == null) {
    throw new ReplayScenarioError(`missing leaf hash at receiptIndex ${receiptIndex}`);
  }

  const inclusionProof: ReceiptInclusionProof = {
    tree_size: receipts.length,
    leaf_index: receiptIndex,
    audit_path: buildAuditPath(tree.levels, receiptIndex),
  };
  assertReceiptInclusionProof(inclusionProof);

  return {
    receipt_id: receiptId,
    leaf_hash: leafHash,
    inclusion_proof: inclusionProof,
    root: tree.root,
  };
}

export function assertReceiptInclusionProof(proof: ReceiptInclusionProof): void {
  if (!Number.isSafeInteger(proof.tree_size) || proof.tree_size < 1) {
    throw new ReplayScenarioError(`inclusion proof tree_size must be >= 1: ${proof.tree_size}`);
  }
  if (!Number.isSafeInteger(proof.leaf_index) || proof.leaf_index < 0) {
    throw new ReplayScenarioError(
      `inclusion proof leaf_index must be a non-negative safe integer: ${proof.leaf_index}`,
    );
  }
  if (proof.leaf_index >= proof.tree_size) {
    throw new ReplayScenarioError(
      `inclusion proof leaf_index ${proof.leaf_index} must be less than tree_size ${proof.tree_size}`,
    );
  }
  if (!Array.isArray(proof.audit_path)) {
    throw new ReplayScenarioError("inclusion proof audit_path must be an array");
  }
  for (const [index, hash] of proof.audit_path.entries()) {
    if (!isHexHash(hash)) {
      throw new ReplayScenarioError(
        `inclusion proof audit_path[${index}] must match ${HASH_RE.source}`,
      );
    }
  }
}

export function computeRootFromInclusionProof(
  leafHashValue: HexHash,
  proof: ReceiptInclusionProof,
): HexHash {
  if (!isHexHash(leafHashValue)) {
    throw new ReplayScenarioError(`leaf hash must match ${HASH_RE.source}`);
  }
  assertReceiptInclusionProof(proof);

  let current = leafHashValue;
  let index = proof.leaf_index;
  let size = proof.tree_size;
  let pathIndex = 0;

  while (size > 1) {
    if (index % 2 === 0) {
      if (index + 1 < size) {
        const sibling = requireProofHash(proof.audit_path, pathIndex);
        pathIndex += 1;
        current = nodeHash(current, sibling);
      }
    } else {
      const sibling = requireProofHash(proof.audit_path, pathIndex);
      pathIndex += 1;
      current = nodeHash(sibling, current);
    }

    index = Math.floor(index / 2);
    size = Math.ceil(size / 2);
  }

  if (pathIndex !== proof.audit_path.length) {
    throw new ReplayScenarioError(
      `inclusion proof used ${pathIndex} audit nodes but received ${proof.audit_path.length}`,
    );
  }

  return current;
}

export function verifyInclusionProof(
  leafHashValue: HexHash,
  proof: ReceiptInclusionProof,
  expectedRoot: HexHash,
): boolean {
  try {
    return computeRootFromInclusionProof(leafHashValue, proof) === expectedRoot;
  } catch {
    return false;
  }
}

export function leafHash(leafBytes: Uint8Array): HexHash {
  return prefixedSha256(new Uint8Array([0x00]), leafBytes);
}

export function nodeHash(left: HexHash, right: HexHash): HexHash {
  return prefixedSha256(new Uint8Array([0x01]), hashToBytes(left), hashToBytes(right));
}

function parseReplayManifest(value: unknown, manifestPath: string): ReplayManifest {
  if (!isRecord(value)) {
    throw new ReplayScenarioError(`manifest ${manifestPath} must be a JSON object`);
  }

  const manifest = {
    schema_version: requireString(value, "schema_version", manifestPath),
    family: requireString(value, "family", manifestPath),
    name: requireString(value, "name", manifestPath),
    intent: requireString(value, "intent", manifestPath),
    clock: requireString(value, "clock", manifestPath),
    expected_verdict: requireString(value, "expected_verdict", manifestPath),
    expected_failure_class: requireNullableString(value, "expected_failure_class", manifestPath),
    fixed_nonce_seed_index: requireNonNegativeInteger(
      value,
      "fixed_nonce_seed_index",
      manifestPath,
    ),
    tags: requireStringArray(value, "tags", manifestPath),
  };

  if (manifest.schema_version !== REPLAY_SCHEMA_VERSION) {
    throw new ReplayScenarioError(
      `manifest ${manifestPath} has unsupported schema_version ${manifest.schema_version}`,
    );
  }
  if (!manifest.name.startsWith(`${manifest.family}/`)) {
    throw new ReplayScenarioError(
      `manifest ${manifestPath} name ${manifest.name} must start with family ${manifest.family}/`,
    );
  }

  return manifest as ReplayManifest;
}

function nonceHexForSeedIndex(seedIndex: number): string {
  const nonce = new Uint8Array(16);
  const view = new DataView(nonce.buffer);
  view.setBigUint64(0, FIXED_CLOCK_EPOCH_MS, false);
  view.setBigUint64(8, BigInt(seedIndex), false);
  return Buffer.from(nonce).toString("hex");
}

function buildMerkleTree(receipts: readonly Uint8Array[]): {
  leafHashes: HexHash[];
  levels: HexHash[][];
  root: HexHash;
} {
  if (receipts.length === 0) {
    throw new ReplayScenarioError("cannot build a Merkle tree with zero receipts");
  }

  const leafHashes = receipts.map((receipt) => leafHash(receipt));
  const levels: HexHash[][] = [leafHashes];
  let current = leafHashes;

  while (current.length > 1) {
    const next: HexHash[] = [];
    for (let index = 0; index < current.length; index += 2) {
      const left = current[index];
      if (left == null) {
        throw new ReplayScenarioError(`missing Merkle node at index ${index}`);
      }
      const right = current[index + 1];
      next.push(right == null ? left : nodeHash(left, right));
    }
    levels.push(next);
    current = next;
  }

  const rootLevel = levels[levels.length - 1];
  const root = rootLevel?.[0];
  if (root == null) {
    throw new ReplayScenarioError("failed to compute Merkle root");
  }

  return { leafHashes, levels, root };
}

function buildAuditPath(levels: readonly HexHash[][], leafIndex: number): HexHash[] {
  const auditPath: HexHash[] = [];
  let index = leafIndex;

  for (const level of levels) {
    if (level.length <= 1) {
      break;
    }

    if (index % 2 === 0) {
      const sibling = level[index + 1];
      if (sibling != null) {
        auditPath.push(sibling);
      }
    } else {
      const sibling = level[index - 1];
      if (sibling == null) {
        throw new ReplayScenarioError(`missing Merkle sibling for index ${index}`);
      }
      auditPath.push(sibling);
    }

    index = Math.floor(index / 2);
  }

  return auditPath;
}

async function walkJsonFiles(root: string): Promise<string[]> {
  const rootStat = await stat(root).catch((err: unknown) => {
    throw new ReplayScenarioError(`failed to stat replay fixture root ${root}: ${String(err)}`);
  });
  if (!rootStat.isDirectory()) {
    throw new ReplayScenarioError(`replay fixture root is not a directory: ${root}`);
  }

  const files = await walkJsonFilesInner(root);
  return files.sort((a, b) => comparePathBytes(relativePath(root, a), relativePath(root, b)));
}

async function walkJsonFilesInner(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true }).catch((err: unknown) => {
    throw new ReplayScenarioError(`failed to read replay fixture directory ${dir}: ${String(err)}`);
  });
  entries.sort((a, b) => comparePathBytes(a.name, b.name));

  const out: string[] = [];
  for (const entry of entries) {
    const entryPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...await walkJsonFilesInner(entryPath));
    } else if (entry.isFile() && extname(entry.name).toLowerCase() === ".json") {
      out.push(entryPath);
    }
  }
  return out;
}

async function findReplayFixturesRoot(start: string): Promise<string | null> {
  let current = start;
  while (true) {
    const candidate = join(current, "tests", "replay", "fixtures");
    if (await isDirectory(candidate)) {
      return candidate;
    }

    const parent = dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}

async function isDirectory(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return false;
  }
}

function requireProofHash(path: readonly string[], index: number): HexHash {
  const value = path[index];
  if (!isHexHash(value)) {
    throw new ReplayScenarioError(`missing or invalid inclusion proof hash at audit_path[${index}]`);
  }
  return value;
}

function requireString(
  value: Record<string, unknown>,
  key: string,
  manifestPath: string,
): string {
  const field = value[key];
  if (typeof field !== "string" || field.length === 0) {
    throw new ReplayScenarioError(
      `manifest ${manifestPath} missing required non-empty string field ${key}`,
    );
  }
  return field;
}

function requireNullableString(
  value: Record<string, unknown>,
  key: string,
  manifestPath: string,
): string | null {
  const field = value[key];
  if (field === null) {
    return null;
  }
  if (typeof field !== "string") {
    throw new ReplayScenarioError(
      `manifest ${manifestPath} field ${key} must be a string or null`,
    );
  }
  return field;
}

function requireNonNegativeInteger(
  value: Record<string, unknown>,
  key: string,
  manifestPath: string,
): number {
  const field = value[key];
  if (typeof field !== "number" || !Number.isSafeInteger(field) || field < 0) {
    throw new ReplayScenarioError(
      `manifest ${manifestPath} field ${key} must be a non-negative safe integer`,
    );
  }
  return field;
}

function requireStringArray(
  value: Record<string, unknown>,
  key: string,
  manifestPath: string,
): string[] {
  const field = value[key];
  if (!Array.isArray(field) || !field.every((item) => typeof item === "string")) {
    throw new ReplayScenarioError(
      `manifest ${manifestPath} field ${key} must be an array of strings`,
    );
  }
  return field;
}

function leafFromScenarioName(name: string, manifestPath: string): string {
  const leaf = name.split("/").at(-1);
  if (leaf == null || leaf.length === 0) {
    throw new ReplayScenarioError(`manifest ${manifestPath} has invalid scenario name ${name}`);
  }
  return leaf;
}

function concatBytes(...chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function prefixedSha256(...chunks: readonly Uint8Array[]): HexHash {
  return `0x${sha256Hex(concatBytes(...chunks))}`;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(Buffer.from(bytes)).digest("hex");
}

function hashToBytes(hash: HexHash): Uint8Array {
  if (!isHexHash(hash)) {
    throw new ReplayScenarioError(`hash must match ${HASH_RE.source}`);
  }
  return Buffer.from(hash.slice(2), "hex");
}

function isHexHash(value: unknown): value is HexHash {
  return typeof value === "string" && HASH_RE.test(value);
}

function pathFromInput(input: string | URL): string {
  return input instanceof URL ? fileURLToPath(input) : input;
}

function comparePathBytes(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function relativePath(root: string, child: string): string {
  return relative(root, child).replaceAll("\\", "/");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function assertBareRootHex(rootHex: string): void {
  if (!BARE_HASH_RE.test(rootHex)) {
    throw new ReplayScenarioError(`root hex must match ${BARE_HASH_RE.source}`);
  }
}

export function phase1RootHexForOutput(output: ReplayScenarioOutput): string {
  assertBareRootHex(output.phase1RootHex);
  return output.phase1RootHex;
}
