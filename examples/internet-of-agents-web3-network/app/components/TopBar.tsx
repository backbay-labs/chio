"use client";

import type { Manifest, ReviewResult, Summary, Verdict } from "@/lib/types";

export interface Layers {
  graph: boolean;
  explorer: boolean;
  narrative: boolean;
}

interface TopBarProps {
  review: ReviewResult;
  summary: Summary;
  manifest: Manifest;
  layers: Layers;
  onToggleLayer: (k: keyof Layers) => void;
  live: boolean;
  onToggleLive: () => void;
  effectiveVerdict: Verdict;
  bundleDigest: string | null;
  firstMismatchPath: string | null;
}

function formatEpochSeconds(seconds: number): string {
  try {
    return new Date(seconds * 1000).toISOString().replace(/\.\d+Z$/, "Z");
  } catch {
    return "unknown";
  }
}

export function TopBar({
  review,
  summary,
  manifest,
  layers,
  onToggleLayer,
  live,
  onToggleLive,
  effectiveVerdict,
  bundleDigest,
  firstMismatchPath,
}: TopBarProps): JSX.Element {
  const digest = bundleDigest ?? "";
  const digestShort = digest.length > 22 ? `${digest.slice(0, 22)}...` : digest;
  const generatedLabel =
    typeof manifest.generated_at === "number" ? formatEpochSeconds(manifest.generated_at) : "unknown";
  const orderId = typeof summary.order_id === "string" ? summary.order_id : "unknown";
  const agentCount = typeof summary.agent_count === "number" ? summary.agent_count : "?";
  const capCount = typeof summary.capability_count === "number" ? summary.capability_count : "?";
  // review.ok is advisory only: review-result.json sits outside
  // manifest.sha256, so we surface it as a labeled non-blocking note rather
  // than as a fail trigger. Authenticated state (manifest hash matches)
  // drives the verdict pill above.
  const reviewAdvisoryError =
    review.ok === false ? (review.errors?.[0] ?? "review-result reports not ok") : null;

  return (
    <div className="topbar" data-testid="topbar">
      <div className="brand">
        <div className="brand-mark">
          <svg viewBox="0 0 20 20" fill="none">
            <rect x="1" y="1" width="8" height="8" stroke="#2dd4bf" strokeWidth="1.2" />
            <rect x="11" y="1" width="8" height="8" stroke="#2dd4bf" strokeWidth="1.2" />
            <rect x="1" y="11" width="8" height="8" stroke="#2dd4bf" strokeWidth="1.2" />
            <rect x="11" y="11" width="8" height="8" stroke="#2dd4bf" strokeWidth="1.2" />
            <circle cx="10" cy="10" r="2" fill="#2dd4bf" />
          </svg>
        </div>
        <span className="brand-title">Chio - Evidence Console</span>
        <span className="brand-sep" />
        <span className="brand-sub">v0.1 - bundle-review</span>
      </div>

      <div className="meta">
        <VerdictPill verdict={effectiveVerdict} />
        <div className="meta-item">
          <span className="meta-k">order</span>
          <span className="meta-v">{orderId}</span>
        </div>
        <div className="meta-item">
          <span className="meta-k">generated</span>
          <span className="meta-v">{generatedLabel}</span>
        </div>
        <div className="meta-item">
          <span className="meta-k">bundle</span>
          <span className="meta-v" title={digest || "digest pending"}>
            {digestShort || "pending"}
          </span>
        </div>
        <div className="meta-item">
          <span className="meta-k">files</span>
          <span className="meta-v">{manifest.files.length}</span>
        </div>
        <div className="meta-item">
          <span className="meta-k">agents</span>
          <span className="meta-v">{agentCount}</span>
        </div>
        <div className="meta-item">
          <span className="meta-k">capabilities</span>
          <span className="meta-v">{capCount}</span>
        </div>
        {firstMismatchPath ? (
          <div className="meta-item" data-testid="fail-reason">
            <span className="meta-k">fail</span>
            <span className="meta-v" style={{ color: "#f43f5e" }}>
              hash-mismatch: {firstMismatchPath}
            </span>
          </div>
        ) : null}
        {!firstMismatchPath && reviewAdvisoryError ? (
          <div className="meta-item" data-testid="review-advisory">
            <span className="meta-k">advisory</span>
            <span className="meta-v" style={{ color: "#f59e0b" }} title="review.ok=false; review-result.json is unauthenticated and shown as a non-blocking note">
              {reviewAdvisoryError}
            </span>
          </div>
        ) : null}
      </div>

      <div className="layer-toggles">
        <button aria-pressed={layers.graph} onClick={() => onToggleLayer("graph")}>
          Graph
        </button>
        <button aria-pressed={layers.explorer} onClick={() => onToggleLayer("explorer")}>
          Explorer
        </button>
        <button aria-pressed={layers.narrative} onClick={() => onToggleLayer("narrative")}>
          Narrative
        </button>
      </div>

      <div className="topbar-actions">
        <button className={`btn-ghost${live ? " live" : ""}`} onClick={onToggleLive}>
          {live ? "Live" : "Review"}
        </button>
      </div>
    </div>
  );
}

export function VerdictPill({ verdict }: { verdict: Verdict }): JSX.Element {
  const fail = verdict !== "PASS";
  return (
    <div className={`verdict-pill${fail ? " fail" : ""}`} data-testid="verdict-pill" data-verdict={verdict}>
      <span className="dot" />
      <span>{verdict}</span>
    </div>
  );
}
