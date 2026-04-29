/**
 * @chio-protocol/conformance
 *
 * Conformance test utilities for the Chio TypeScript SDK.
 * Verifies that TS SDK behavior matches the Rust kernel.
 *
 * The schema-derived companion types live under `./_generated/index.ts` and
 * are regenerated via `cargo xtask codegen --lang ts`. They are exposed
 * here as the `Schemas` namespace tree so consumers can write
 * `Schemas.JsonRPC_Request.ChioJSONRPC20Request` without importing the
 * generated module directly. The hand-written canonical-JSON encoder and
 * the receipt verifier remain authoritative for behavior; the generated
 * types describe shape only.
 */

export { canonicalJsonString, canonicalJsonBytes } from "./canonical.js";
export {
  validateReceiptStructure,
  verifyContentHash,
  assertVerdictMatch,
} from "./verify.js";
export {
  BROWSER_SUBSET_V1,
  BROWSER_SUBSET_TAG,
  selector,
} from "./browser-subset.js";
export type {
  BrowserSubsetCategory,
  BrowserSubsetSelection,
  CategorySelection,
  ConformanceCase,
  ConformanceCategoryFile,
  ConformanceManifest,
} from "./browser-subset.js";
export * as Schemas from "./_generated/index.js";
