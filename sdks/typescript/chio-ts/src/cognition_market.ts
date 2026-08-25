/** Single-operator cognition-market buyer and seller clients. */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const BUYER_SCHEMA = "chio.finding.buyer-client.v1";
const SELLER_SCHEMA = "chio.finding.seller-client.v1";
const PURCHASE_SCHEMA = "chio.finding.purchase-request.v1";
const VERIFIED_FIX_SUBMISSION_SCHEMA = "chio.finding.verified-fix-submission.v1";
const PURCHASE_DOMAIN = Buffer.from("chio.finding.public-purchase-request.v1\0", "utf8");
const VERIFIED_FIX_SUBMISSION_DOMAIN = Buffer.from(
  "chio.finding.verified-fix-submission-id.v1\0",
  "utf8",
);
const VOLUNTARY_RETRACTION_DOMAIN = Buffer.from(
  "chio.finding.voluntary-retraction-request-id.v1\0",
  "utf8",
);
const VERIFIED_FIX_PAYLOAD_SCHEMA = "chio.finding.verified-fix-payload.v1";
const VERIFIED_FIX_MEDIA_TYPE = "application/vnd.chio.verified-fix+json";
const PROOF_RESPONSE_MAX_BYTES = 24 * 1024 * 1024;
const PURCHASE_RESULT_MAX_BYTES = Math.ceil((257 * 1024 * 1024) / 3) * 4 + 2 * 1024 * 1024;
const JSON_RESPONSE_MAX_BYTES = 2 * 1024 * 1024;
const ERROR_RESPONSE_MAX_BYTES = 4096;

export class CognitionMarketError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CognitionMarketError";
  }
}

export interface CognitionMarketClientProfile {
  schema: string;
  endpoint: string;
  market: {
    statusFeedOperator: { feedId: string };
    [key: string]: unknown;
  };
  principalId: string;
  payer?: string;
  bearerToken: string;
  signingSeed?: string;
  payoutDestination: string;
}

export interface VerifiedFindingProof {
  findingId: string;
  proof: Uint8Array;
  verification: Record<string, unknown>;
}

export interface FindingSearchOptions {
  topicPrefix: string;
  limit?: number;
  cursor?: string;
}

export interface FindingPurchaseOptions {
  maxPriceUnits: number;
  currency?: string;
  deadlineSecs?: number;
}

export interface PurchasedVerifiedFix {
  findingId: string;
  repository: string;
  baseRevision: string;
  candidateRevision: string;
  patch: string;
  purchase: Record<string, unknown>;
}

type Fetch = typeof globalThis.fetch;

export class CognitionMarketBuyer {
  readonly profile: CognitionMarketClientProfile;
  readonly profilePath: string;
  readonly chioBinary: string;
  readonly fetch: Fetch;
  readonly timeoutMs: number;

  constructor(
    profilePath: string,
    options: { chioBinary?: string; fetch?: Fetch; timeoutMs?: number } = {},
  ) {
    this.profilePath = profilePath;
    this.profile = loadProfile(profilePath, BUYER_SCHEMA);
    this.chioBinary = options.chioBinary ?? "chio";
    this.fetch = options.fetch ?? globalThis.fetch;
    this.timeoutMs = requireTimeout(options.timeoutMs ?? 30_000);
  }

  async search(options: FindingSearchOptions): Promise<Record<string, unknown>> {
    if (options.topicPrefix.length === 0 || options.topicPrefix.trim() !== options.topicPrefix) {
      throw new CognitionMarketError("topicPrefix must be non-empty and trimmed");
    }
    const query = new URLSearchParams();
    query.set("limit", String(options.limit ?? 20));
    query.set("topicPrefix", options.topicPrefix);
    if (options.cursor !== undefined) query.set("cursor", options.cursor);
    return this.jsonRequest("GET", `/v1/findings/search?${query.toString()}`);
  }

  async proof(findingId: string): Promise<Uint8Array> {
    requireHex64(findingId, "findingId");
    const proof = await this.request(
      "GET",
      `/v1/findings/${findingId}/proof`,
      undefined,
      PROOF_RESPONSE_MAX_BYTES,
    );
    if (proof.length === 0) {
      throw new CognitionMarketError("proof bundle is empty or oversized");
    }
    return proof;
  }

  async verifyProof(proof: Uint8Array): Promise<VerifiedFindingProof> {
    if (proof.length === 0 || proof.length > 24 * 1024 * 1024) {
      throw new CognitionMarketError("proof bundle is empty or oversized");
    }
    const output = await runChio(
      this.chioBinary,
      [
        "finding",
        "verify-bundle",
        "--profile",
        this.profilePath,
        "--input",
        "-",
        "--json",
      ],
      proof,
    );
    const verification = parseObject(output, "Rust verifier response");
    const findingId = verification.findingId;
    if (typeof findingId !== "string") {
      throw new CognitionMarketError("Rust verifier omitted the Finding id");
    }
    return { findingId, proof, verification };
  }

  async verifiedProof(findingId: string): Promise<VerifiedFindingProof> {
    const verified = await this.verifyProof(await this.proof(findingId));
    if (verified.findingId !== findingId) {
      throw new CognitionMarketError("verified proof names a different Finding");
    }
    return verified;
  }

  async purchase(
    verified: VerifiedFindingProof,
    options: FindingPurchaseOptions,
  ): Promise<Record<string, unknown>> {
    const request = purchaseRequest(
      verified.findingId,
      options.maxPriceUnits,
      options.currency ?? "USD",
      buyerPayer(this.profile),
      options.deadlineSecs ?? 3600,
    );
    return this.jsonRequest(
      "POST",
      `/v1/findings/${verified.findingId}/purchase`,
      canonicalJson(request),
      PURCHASE_RESULT_MAX_BYTES,
    );
  }

  async purchaseVerifiedFix(
    verified: VerifiedFindingProof,
    options: FindingPurchaseOptions,
  ): Promise<PurchasedVerifiedFix> {
    const request = purchaseRequest(
      verified.findingId,
      options.maxPriceUnits,
      options.currency ?? "USD",
      buyerPayer(this.profile),
      options.deadlineSecs ?? 3600,
    );
    const purchase = await this.jsonRequest(
      "POST",
      `/v1/findings/${verified.findingId}/purchase`,
      canonicalJson(request),
      PURCHASE_RESULT_MAX_BYTES,
    );
    await this.verifyPurchaseTerminal(verified, request, purchase);
    return purchasedVerifiedFix(verified, purchase);
  }

  async status(findingId: string): Promise<Record<string, unknown>> {
    requireHex64(findingId, "findingId");
    const feed = this.profile.market.statusFeedOperator.feedId;
    if (typeof feed !== "string" || feed.length === 0) {
      throw new CognitionMarketError("client profile has no status feed id");
    }
    return this.jsonRequest(
      "GET",
      `/v1/findings/status/${encodeURIComponent(feed)}/proof/${findingId}`,
    );
  }

  async challenge(
    findingId: string,
    signedChallenge: Uint8Array,
  ): Promise<Record<string, unknown>> {
    requireHex64(findingId, "findingId");
    if (signedChallenge.length === 0 || signedChallenge.length > 1024 * 1024) {
      throw new CognitionMarketError("signed challenge is empty or oversized");
    }
    return this.jsonRequest(
      "POST",
      `/v1/findings/${findingId}/challenges`,
      signedChallenge,
    );
  }

  async challengeEvidenceInvalid(
    verified: VerifiedFindingProof,
    purchaseResult: Record<string, unknown>,
    options: { filedAt?: number } = {},
  ): Promise<Record<string, unknown>> {
    const filedAt = options.filedAt ?? Math.floor(Date.now() / 1000);
    const evidence = evidenceInvalidDocument(verified, purchaseResult, filedAt);
    const directory = mkdtempSync(join(tmpdir(), "chio-market-challenge-"));
    try {
      const evidencePath = join(directory, "evidence.json");
      const keyPath = join(directory, "challenger.seed");
      writeFileSync(evidencePath, canonicalJson(evidence));
      const signingSeed = this.profile.signingSeed;
      if (signingSeed === undefined) {
        throw new CognitionMarketError("buyer profile omitted its signing seed");
      }
      writeFileSync(keyPath, signingSeed, { encoding: "ascii", mode: 0o600 });
      chmodSync(keyPath, 0o600);
      const output = await runChio(
        this.chioBinary,
        [
          "finding", "challenge",
          "--finding", verified.findingId,
          "--class", "evidence-invalid",
          "--evidence", evidencePath,
          "--challenger-key", keyPath,
          "--control-url", this.profile.endpoint,
          "--json",
        ],
        undefined,
        { ...process.env, CHIO_CONTROL_TOKEN: this.profile.bearerToken },
      );
      return parseObject(output, "challenge filing response");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }

  private async jsonRequest(
    method: string,
    path: string,
    body?: Uint8Array,
    maximum = JSON_RESPONSE_MAX_BYTES,
  ): Promise<Record<string, unknown>> {
    return parseObject(await this.request(method, path, body, maximum), "operator response");
  }

  private async request(
    method: string,
    path: string,
    body?: Uint8Array,
    maximum = JSON_RESPONSE_MAX_BYTES,
  ): Promise<Uint8Array> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const init: RequestInit = {
      method,
      signal: controller.signal,
      headers: {
        authorization: `Bearer ${this.profile.bearerToken}`,
        "content-type": "application/json",
      },
    };
    if (body !== undefined) init.body = body;
    try {
      const response = await this.fetch(
        `${this.profile.endpoint.replace(/\/$/, "")}${path}`,
        init,
      );
      const responseMaximum = response.ok ? maximum : ERROR_RESPONSE_MAX_BYTES;
      const responseLabel = response.ok
        ? "operator response"
        : `operator HTTP ${response.status} error response`;
      const bytes = await readBoundedResponse(response, responseMaximum, responseLabel);
      if (!response.ok) {
        const text = Buffer.from(bytes).toString("utf8");
        throw new CognitionMarketError(`operator returned HTTP ${response.status}: ${text}`);
      }
      return bytes;
    } catch (error) {
      if (controller.signal.aborted) {
        throw new CognitionMarketError("operator request timed out");
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  private async verifyPurchaseTerminal(
    verified: VerifiedFindingProof,
    request: Record<string, unknown>,
    purchase: Record<string, unknown>,
  ): Promise<void> {
    const directory = mkdtempSync(join(tmpdir(), "chio-market-purchase-"));
    try {
      const proofPath = join(directory, "proof.json");
      const requestPath = join(directory, "request.json");
      const resultPath = join(directory, "result.json");
      writeFileSync(proofPath, verified.proof);
      writeFileSync(requestPath, canonicalJson(request));
      writeFileSync(resultPath, canonicalJson(purchase));
      const output = await runChio(this.chioBinary, [
        "finding", "verify-bundle",
        "--profile", this.profilePath,
        "--input", proofPath,
        "--purchase-request", requestPath,
        "--purchase-result", resultPath,
        "--json",
      ]);
      const report = parseObject(output, "Rust purchase verifier response");
      if (report.purchaseTerminalVerified !== true) {
        throw new CognitionMarketError("Rust purchase verifier did not authorize the terminal");
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
}

export class CognitionMarketSeller {
  readonly credential: CognitionMarketClientProfile;
  readonly fetch: Fetch;
  readonly timeoutMs: number;

  constructor(
    credentialPath: string,
    options: { fetch?: Fetch; timeoutMs?: number } = {},
  ) {
    this.credential = loadProfile(credentialPath, SELLER_SCHEMA);
    this.fetch = options.fetch ?? globalThis.fetch;
    this.timeoutMs = requireTimeout(options.timeoutMs ?? 300_000);
  }

  async packageVerifiedFix(input: {
    repository: string;
    base: string;
    candidate: string;
    tests: string[];
    topic: string;
    price?: number;
    output?: string;
  }): Promise<Record<string, unknown>> {
    if (input.output !== undefined) {
      throw new CognitionMarketError(
        "scoped seller packages are operator-owned and do not accept a local output path",
      );
    }
    const identity: Record<string, unknown> = {
      baseRevision: input.base,
      candidateRevision: input.candidate,
      priceUnits: input.price ?? 300,
      repository: resolve(input.repository),
      schema: VERIFIED_FIX_SUBMISSION_SCHEMA,
      tests: input.tests,
      topic: input.topic,
    };
    const requestId = createHash("sha256")
      .update(VERIFIED_FIX_SUBMISSION_DOMAIN)
      .update(canonicalJson(identity))
      .digest("hex");
    return { ...identity, requestId };
  }

  async admit(packageRequest: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.post("/v1/findings/operator/verified-fixes", packageRequest);
  }

  async retract(findingId: string): Promise<Record<string, unknown>> {
    requireHex64(findingId, "findingId");
    const requestId = createHash("sha256")
      .update(VOLUNTARY_RETRACTION_DOMAIN)
      .update(findingId, "ascii")
      .digest("hex");
    return this.post("/v1/findings/operator/retractions", {
      findingId,
      requestId,
      schema: "chio.finding.voluntary-retraction-request.v1",
    });
  }

  private async post(
    path: string,
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetch(
        `${this.credential.endpoint.replace(/\/$/, "")}${path}`,
        {
        method: "POST",
        signal: controller.signal,
        headers: {
          authorization: `Bearer ${this.credential.bearerToken}`,
          "content-type": "application/json",
        },
        body: canonicalJson(body),
        },
      );
      const responseMaximum = response.ok ? JSON_RESPONSE_MAX_BYTES : ERROR_RESPONSE_MAX_BYTES;
      const responseLabel = response.ok
        ? "operator response"
        : `operator HTTP ${response.status} error response`;
      const bytes = await readBoundedResponse(response, responseMaximum, responseLabel);
      if (!response.ok) {
        const text = Buffer.from(bytes).toString("utf8");
        throw new CognitionMarketError(`operator returned HTTP ${response.status}: ${text}`);
      }
      return parseObject(bytes, "Finding admission response");
    } catch (error) {
      if (controller.signal.aborted) {
        throw new CognitionMarketError("operator request timed out");
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
}

async function readBoundedResponse(
  response: Response,
  maximum: number,
  label: string,
): Promise<Uint8Array> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && /^\d+$/.test(contentLength)
      && BigInt(contentLength) > BigInt(maximum)) {
    throw new CognitionMarketError(`${label} exceeds the SDK size bound`);
  }
  if (response.body === null) return new Uint8Array();

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      if (total + value.byteLength > maximum) {
        await reader.cancel().catch(() => undefined);
        throw new CognitionMarketError(`${label} exceeds the SDK size bound`);
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function loadProfile(path: string, schema: string): CognitionMarketClientProfile {
  const raw = readFileSync(path);
  if (raw.length === 0 || raw.length > 1024 * 1024) {
    throw new CognitionMarketError("client profile is empty or oversized");
  }
  const value = parseObject(raw, "client profile");
  if (value.schema !== schema || typeof value.endpoint !== "string"
      || typeof value.bearerToken !== "string" || value.bearerToken.length === 0
      || value.bearerToken.trim() !== value.bearerToken || value.bearerToken.length > 4096
      || typeof value.principalId !== "string" || value.principalId.length === 0
      || value.principalId.trim() !== value.principalId
      || typeof value.payoutDestination !== "string"
      || !/^0x[0-9a-f]{40}$/.test(value.payoutDestination)) {
    throw new CognitionMarketError("client profile is invalid");
  }
  if (schema === BUYER_SCHEMA
      && (typeof value.signingSeed !== "string" || !/^[0-9a-f]{64}$/.test(value.signingSeed)
        || typeof value.payer !== "string" || !/^[0-9a-f]{64}$/.test(value.payer))) {
    throw new CognitionMarketError("client profile buyer identity is invalid");
  }
  if (schema === SELLER_SCHEMA && Object.hasOwn(value, "signingSeed")) {
    throw new CognitionMarketError("seller client profile must not contain a signing seed");
  }
  let endpoint: URL;
  try {
    endpoint = new URL(value.endpoint);
  } catch {
    throw new CognitionMarketError("client profile is invalid");
  }
  if (endpoint.protocol !== "http:" || endpoint.username !== "" || endpoint.password !== ""
      || endpoint.search !== "" || endpoint.hash !== ""
      || (endpoint.pathname !== "" && endpoint.pathname !== "/")) {
    throw new CognitionMarketError("client profile is invalid");
  }
  const market = value.market;
  if (market === null || Array.isArray(market) || typeof market !== "object") {
    throw new CognitionMarketError("client profile is invalid");
  }
  const status = (market as Record<string, unknown>).statusFeedOperator;
  if (status === null || Array.isArray(status) || typeof status !== "object"
      || typeof (status as Record<string, unknown>).feedId !== "string"
      || ((status as Record<string, unknown>).feedId as string).length === 0
      || ((status as Record<string, unknown>).feedId as string).trim()
        !== (status as Record<string, unknown>).feedId) {
    throw new CognitionMarketError("client profile is invalid");
  }
  if (!Buffer.from(canonicalJson(value)).equals(raw)) {
    throw new CognitionMarketError("client profile is not strict canonical JSON");
  }
  return value as unknown as CognitionMarketClientProfile;
}

function purchaseRequest(
  findingId: string,
  maxPriceUnits: number,
  currency: string,
  payer: string,
  deadlineSecs: number | undefined,
): Record<string, unknown> {
  requireHex64(findingId, "findingId");
  if (!Number.isSafeInteger(maxPriceUnits) || maxPriceUnits <= 0) {
    throw new CognitionMarketError("maxPriceUnits must be a positive safe integer");
  }
  const identity: Record<string, unknown> = {
    deadlineSecs: deadlineSecs ?? null,
    findingId,
    maxPrice: { currency, units: maxPriceUnits },
    payer,
    schema: PURCHASE_SCHEMA,
  };
  const digest = createHash("sha256")
    .update(PURCHASE_DOMAIN)
    .update(canonicalJson(identity))
    .digest("hex");
  return {
    ...(deadlineSecs === undefined ? {} : { deadlineSecs }),
    findingId,
    maxPrice: { currency, units: maxPriceUnits },
    payer,
    requestId: digest,
    schema: PURCHASE_SCHEMA,
  };
}

function buyerPayer(profile: CognitionMarketClientProfile): string {
  if (typeof profile.payer !== "string") {
    throw new CognitionMarketError("buyer profile omitted its payer identity");
  }
  return profile.payer;
}

function canonicalJson(value: unknown): Uint8Array {
  return Buffer.from(canonicalString(value), "utf8");
}

function canonicalString(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new CognitionMarketError("non-integer JSON number");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalString).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, member]) => member !== undefined)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, member]) => `${JSON.stringify(key)}:${canonicalString(member)}`).join(",")}}`;
  }
  throw new CognitionMarketError("unsupported JSON value");
}

function parseObject(bytes: Uint8Array, label: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch (error) {
    throw new CognitionMarketError(`${label} is not valid JSON: ${String(error)}`);
  }
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new CognitionMarketError(`${label} is not a JSON object`);
  }
  return value as Record<string, unknown>;
}

function runChio(
  binary: string,
  args: string[],
  input?: Uint8Array,
  env?: NodeJS.ProcessEnv,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { env, stdio: ["pipe", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    let settled = false;
    const finish = (action: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      action();
    };
    const capture = (target: Buffer[]) => (chunk: Buffer): void => {
      outputBytes += chunk.length;
      if (outputBytes > 32 * 1024 * 1024) {
        child.kill();
        finish(() => reject(new CognitionMarketError("chio command output exceeded its bound")));
        return;
      }
      target.push(chunk);
    };
    child.stdout.on("data", capture(stdout));
    child.stderr.on("data", capture(stderr));
    child.on("error", (error) => finish(() => reject(
      new CognitionMarketError(`failed to start chio: ${error.message}`),
    )));
    child.on("close", (code) => {
      if (code !== 0) {
        finish(() => reject(new CognitionMarketError(
          `chio command failed: ${Buffer.concat(stderr).toString("utf8").trim()}`,
        )));
      } else {
        finish(() => resolve(Buffer.concat(stdout)));
      }
    });
    const timer = setTimeout(() => {
      child.kill();
      finish(() => reject(new CognitionMarketError("chio command timed out")));
    }, 60_000);
    child.stdin.end(input);
  });
}

function requireHex64(value: string, field: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new CognitionMarketError(`${field} must be canonical lowercase 64-hex`);
  }
}

function purchasedVerifiedFix(
  verified: VerifiedFindingProof,
  purchase: Record<string, unknown>,
): PurchasedVerifiedFix {
  if (purchase.findingId !== verified.findingId) {
    throw new CognitionMarketError("purchase result names a different Finding");
  }
  if (purchase.verdict !== "allow" || purchase.settlement !== "captured") {
    throw new CognitionMarketError("purchase did not return a captured allow terminal");
  }
  const output = asObject(purchase.output, "purchase output");
  if (output.mediaType !== VERIFIED_FIX_MEDIA_TYPE || typeof output.payloadB64 !== "string"
      || output.payloadB64.length === 0) {
    throw new CognitionMarketError("purchase did not return a verified-fix payload");
  }
  verifyRevealCommitment(verified, VERIFIED_FIX_MEDIA_TYPE, output.payloadB64);
  let payload: Record<string, unknown>;
  try {
    const raw = Buffer.from(output.payloadB64, "base64");
    if (raw.toString("base64") !== output.payloadB64) {
      throw new Error("noncanonical base64");
    }
    payload = parseObject(raw, "verified-fix payload");
  } catch (error) {
    throw new CognitionMarketError(`verified-fix payload is invalid: ${String(error)}`);
  }
  if (payload.schema !== VERIFIED_FIX_PAYLOAD_SCHEMA) {
    throw new CognitionMarketError("verified-fix payload schema is unsupported");
  }
  const repository = memberString(payload, "repository");
  const baseRevision = memberString(payload, "baseRevision");
  const candidateRevision = memberString(payload, "candidateRevision");
  const patch = memberString(payload, "patch");
  if (repository.length === 0 || baseRevision.length === 0 || candidateRevision.length === 0
      || patch.length === 0 || baseRevision === candidateRevision) {
    throw new CognitionMarketError("verified-fix payload is incomplete");
  }
  return {
    findingId: verified.findingId,
    repository,
    baseRevision,
    candidateRevision,
    patch,
    purchase,
  };
}

function verifyRevealCommitment(
  verified: VerifiedFindingProof,
  mediaType: string,
  payloadB64: string,
): void {
  const proof = parseObject(verified.proof, "verified proof bundle");
  const finding = memberObject(memberObject(proof, "bundle"), "finding");
  const committed = memberString(finding, "payload_sha256");
  const actual = digestJson({ media_type: mediaType, payload_b64: payloadB64 });
  if (actual !== committed) {
    throw new CognitionMarketError("purchased output does not match the verified Finding");
  }
}

function evidenceInvalidDocument(
  verified: VerifiedFindingProof,
  purchase: Record<string, unknown>,
  filedAt: number,
): Record<string, unknown> {
  const proof = parseObject(verified.proof, "verified proof bundle");
  const bundle = memberObject(proof, "bundle");
  const admissionEnvelope = memberObject(bundle, "admission");
  const admission = memberObject(admissionEnvelope, "body");
  const schedule = memberObject(memberObject(bundle, "feeSchedule"), "body");
  const terms = memberObject(memberObject(bundle, "marketTerms"), "body");
  const receipts = proof.evidenceReceipts;
  if (!Array.isArray(receipts) || receipts.length === 0) {
    throw new CognitionMarketError("proof bundle has no evidence receipts");
  }
  const firstReceipt = memberObject(asObject(receipts[0], "evidence receipt"), "receipt");
  const checkpointBody = memberObject(memberObject(proof, "evidenceCheckpoint"), "body");
  const delivery = memberObject(purchase, "deliveryReceipt");
  const purchaseRecord = memberObject(purchase, "purchaseRecord");
  const purchaseBody = memberObject(purchaseRecord, "body");
  const payerKey = memberString(purchase, "payerKey");
  if (memberString(purchase, "payer") !== payerKey) {
    throw new CognitionMarketError("purchase payer does not match its authenticated key");
  }
  const checkpointSha256 = digestJson(checkpointBody);
  const checkpointRef = memberString(memberObject(bundle, "finding"), "evidence_checkpoint_ref");
  const purchaseDigest = digestJson(purchaseRecord);
  const scheduleDigest = memberString(admission, "fee_schedule_envelope_sha256");
  const challengePool = memberObject(admission, "challenge_administration_pool");
  const limits = terms.challenge_bond_limits;
  if (!Array.isArray(limits)) throw new CognitionMarketError("market terms omit challenge limits");
  const limit = limits
    .map((value) => asObject(value, "challenge bond limit"))
    .find((value) => value.guarantee_class === "deterministic_replay");
  if (limit === undefined) throw new CognitionMarketError("market terms omit replay challenge limits");
  const purchaseKey = memberString(purchaseBody, "purchase_key");
  const lockId = createHash("sha256")
    .update("chio.finding.sdk-dispute-lock.v1\0", "utf8")
    .update(verified.findingId, "ascii")
    .update(purchaseKey, "ascii")
    .digest("hex");
  return {
    affected_deliveries: [{
      checkpoint_ref: checkpointRef,
      checkpoint_sha256: checkpointSha256,
      receipt_id: memberString(delivery, "id"),
      receipt_sha256: digestJson(delivery),
    }],
    authorization: { buyer_submission: {
      challenger: payerKey,
      dispute_fee_terminal: {
        amount: memberObject(schedule, "disputeFee"),
        beneficiary_pool_principal_id: memberString(challengePool, "principal_id"),
        event: "challenge_filing",
        fee_schedule_envelope_sha256: scheduleDigest,
        payer: payerKey,
        rail_destination: memberString(challengePool, "rail_destination"),
      },
      dispute_lock_ref: {
        amount: memberObject(limit, "min_bond"),
        class: "dispute",
        expiry: filedAt + 600,
        fee_schedule_envelope_sha256: scheduleDigest,
        lock_id: lockId,
      },
      standing: { finalized_purchase: {
        purchase_key: purchaseKey,
        purchase_record_envelope_sha256: purchaseDigest,
      } },
    } },
    evidence: { evidence_invalid: {
      challenged_checkpoint_ref: {
        checkpoint_ref: checkpointRef,
        checkpoint_sha256: checkpointSha256,
      },
      challenged_evidence_receipt_refs: [{
        receipt_id: memberString(firstReceipt, "id"),
        receipt_sha256: digestJson(firstReceipt),
      }],
      purchase_record_envelope_sha256: purchaseDigest,
    } },
    filed_at: filedAt,
    listing: {
      backing_envelope_sha256: memberString(admission, "backing_envelope_sha256"),
      listing_id: memberString(admission, "listing_id"),
      profile_envelope_sha256: memberString(admission, "profile_envelope_sha256"),
      terms_envelope_sha256: memberString(admission, "terms_envelope_sha256"),
      venue_admission_envelope_sha256: digestJson(admissionEnvelope),
    },
  };
}

function memberObject(value: unknown, field: string): Record<string, unknown> {
  const object = asObject(value, field);
  return asObject(object[field], field);
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  const member = value;
  if (member === null || Array.isArray(member) || typeof member !== "object") {
    throw new CognitionMarketError(`${label} is not an object`);
  }
  return member as Record<string, unknown>;
}

function memberString(value: Record<string, unknown>, field: string): string {
  const member = value[field];
  if (typeof member !== "string") throw new CognitionMarketError(`${field} is not a string`);
  return member;
}

function memberNumber(value: Record<string, unknown>, field: string): number {
  const member = value[field];
  if (typeof member !== "number" || !Number.isSafeInteger(member)) {
    throw new CognitionMarketError(`${field} is not a safe integer`);
  }
  return member;
}

function digestJson(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function requireTimeout(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new CognitionMarketError("timeoutMs must be a positive safe integer");
  }
  return value;
}
