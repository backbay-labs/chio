/**
 * Browser/Edge conformance subset selector (BROWSER_SUBSET_V1).
 *
 * Browser/edge runtimes are verify-only and execute a named, versioned
 * subset of the conformance corpus, not the full corpus. This module
 * defines that subset.
 *
 * The subset (v1) is intentionally narrow:
 *
 *   - canonical/v1.json:  ALL cases (canonical-JSON byte equivalence is
 *                         a verify primitive on every runtime).
 *   - receipt/v1.json:    cases tagged `verify_only: true`.
 *   - capability/v1.json: cases tagged `verify_only: true`.
 *
 * Explicitly excluded:
 *   - Receipt and capability SIGNING cases (verify-only ships first).
 *   - manifest, hashing, signing corpora (server-side concerns).
 *   - Any vector requiring fresh entropy or live time.
 *
 * Bumping to v2 requires a coordinated change in the conformance corpus
 * and this selector.
 */

/**
 * Stable tag identifying this subset version. The conformance manifest
 * pins this string to gate cross-runtime compatibility.
 */
export const BROWSER_SUBSET_TAG = "chio.conformance.browser-subset/v1" as const;

/**
 * Selection rule for a category in the M01 conformance corpus.
 *
 * - `mode: "all"` selects every case in that category.
 * - `mode: "verify_only"` selects cases whose `verify_only` flag is `true`.
 */
export type CategorySelection =
  | { readonly mode: "all" }
  | { readonly mode: "verify_only" };

/**
 * The subset enumeration: which corpus categories belong to the
 * browser/edge runtime gate, and how each is filtered.
 *
 * Iteration order is canonical, receipt, capability; downstream consumers
 * MUST NOT rely on Object.keys ordering for correctness, but stable order
 * is convenient for snapshot tests.
 */
export const BROWSER_SUBSET_V1 = {
  tag: BROWSER_SUBSET_TAG,
  version: 1,
  categories: {
    canonical: { mode: "all" },
    receipt: { mode: "verify_only" },
    capability: { mode: "verify_only" },
  },
} as const satisfies {
  readonly tag: typeof BROWSER_SUBSET_TAG;
  readonly version: 1;
  readonly categories: {
    readonly canonical: CategorySelection;
    readonly receipt: CategorySelection;
    readonly capability: CategorySelection;
  };
};

/** Category names included in BROWSER_SUBSET_V1. */
export type BrowserSubsetCategory = keyof typeof BROWSER_SUBSET_V1.categories;

/**
 * Minimal shape of a conformance case. The selector reads `id` and
 * `verify_only`; additional per-category fields are preserved via the generic.
 */
export interface ConformanceCase {
  readonly id: string;
  readonly verify_only?: boolean;
}

/**
 * Minimal shape of a category file. The selector reads `cases`; callers
 * may pass the full parsed file - other fields are preserved on input.
 */
export interface ConformanceCategoryFile<C extends ConformanceCase = ConformanceCase> {
  readonly cases: ReadonlyArray<C>;
}

/** Record keyed by category name with the parsed JSON for that category. */
export type ConformanceManifest = {
  readonly [K in BrowserSubsetCategory]: ConformanceCategoryFile;
};

/** Versioned, tagged record listing which case IDs are in scope per category. */
export interface BrowserSubsetSelection {
  readonly tag: typeof BROWSER_SUBSET_TAG;
  readonly version: 1;
  readonly categories: {
    readonly [K in BrowserSubsetCategory]: ReadonlyArray<string>;
  };
}

/**
 * Apply BROWSER_SUBSET_V1 to a parsed conformance manifest and return
 * the per-category list of case IDs that runtimes must pass.
 * Pure and total: zero-match categories yield an empty array.
 */
export function selector(manifest: ConformanceManifest): BrowserSubsetSelection {
  const categories: { [K in BrowserSubsetCategory]: ReadonlyArray<string> } = {
    canonical: pickIds(manifest.canonical, BROWSER_SUBSET_V1.categories.canonical),
    receipt: pickIds(manifest.receipt, BROWSER_SUBSET_V1.categories.receipt),
    capability: pickIds(manifest.capability, BROWSER_SUBSET_V1.categories.capability),
  };

  return {
    tag: BROWSER_SUBSET_TAG,
    version: 1,
    categories,
  };
}

function pickIds(
  file: ConformanceCategoryFile,
  rule: CategorySelection,
): ReadonlyArray<string> {
  if (rule.mode === "all") {
    return file.cases.map((c) => c.id);
  }
  return file.cases.filter((c) => c.verify_only === true).map((c) => c.id);
}
