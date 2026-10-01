/**
 * Shared reduced-motion policy (BAC-668 / CV-2).
 *
 * `prefers-reduced-motion` is currently re-derived in 8+ places across the
 * homepage. This module is the single source of truth for later waves to adopt;
 * the existing consumers are intentionally NOT refactored in this ticket.
 *
 * Semantics match today's usage exactly (see LenisProvider.tsx / OsFolio.tsx /
 * LaunchPixels.tsx): a `window.matchMedia('(prefers-reduced-motion: reduce)')`
 * query, SSR-safe (returns false when `window` is undefined), with a
 * `change`-event listener guarded by optional chaining for older engines.
 */

import { useSyncExternalStore } from "react";

export const REDUCE_QUERY = "(prefers-reduced-motion: reduce)";

/**
 * Read the current reduced-motion preference. SSR-safe: returns `false` when
 * `window` (or `matchMedia`) is unavailable.
 */
export function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia(REDUCE_QUERY).matches
  );
}

function subscribe(onChange: () => void) {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return () => {};
  const mq = window.matchMedia(REDUCE_QUERY);
  mq.addEventListener?.("change", onChange);
  return () => mq.removeEventListener?.("change", onChange);
}

/** Use the same initial snapshot for SSR and hydration, then follow the live preference. */
export function useReducedMotion(): boolean {
  return useSyncExternalStore(subscribe, prefersReducedMotion, () => false);
}
