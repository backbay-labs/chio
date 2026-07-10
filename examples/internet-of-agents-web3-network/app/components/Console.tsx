"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { Chrome } from "@/components/Chrome";
import { Explorer } from "@/components/Explorer";
import { Graph } from "@/components/Graph";
import { Narrative } from "@/components/Narrative";
import { TopBar, type Layers } from "@/components/TopBar";
import { TweaksPanel, type TweaksState } from "@/components/TweaksPanel";
import { ErrorBanner } from "@/components/ErrorBanner";
import { useBundle } from "@/components/BundleProvider";
import type { Beat, Edge, PulseSpec } from "@/lib/types";

const DEV_FLAG = process.env.NEXT_PUBLIC_CHIO_DEV === "1";

const TWEAK_DEFAULTS: TweaksState = {
  showNarrative: false,
  liveMode: false,
};

export function Console(): JSX.Element {
  const ctx = useBundle();
  const { status, error, bundle } = ctx;

  if (status === "loading" || status === "idle") {
    return (
      <div className="error-banner">
        <div className="card" style={{ borderColor: "var(--line-2)" }}>
          <h1 style={{ color: "var(--ink-0)" }}>loading</h1>
          <p className="muted">Fetching bundle manifest...</p>
        </div>
      </div>
    );
  }

  if (status === "error" || !bundle) {
    const msg = error?.message ?? "Bundle could not be loaded.";
    const detail = error ? `path: ${error.path} (HTTP ${error.status})` : undefined;
    return <ErrorBanner message={msg} detail={detail} />;
  }

  return (
    <ConsoleInner
      bundle={bundle}
      effectiveVerdict={ctx.effectiveVerdict}
      bundleDigest={ctx.bundleDigest}
      firstMismatchPath={ctx.firstMismatchPath}
    />
  );
}

interface InnerProps {
  bundle: NonNullable<ReturnType<typeof useBundle>["bundle"]>;
  effectiveVerdict: string;
  bundleDigest: string | null;
  firstMismatchPath: string | null;
}

function ConsoleInner({ bundle, effectiveVerdict, bundleDigest, firstMismatchPath }: InnerProps): JSX.Element {
  const beats: Beat[] = bundle.beats;
  const [tweaks, setTweaks] = useState<TweaksState>(TWEAK_DEFAULTS);
  const [layers, setLayers] = useState<Layers>({
    graph: true,
    explorer: true,
    narrative: tweaks.showNarrative,
  });
  const [live, setLive] = useState<boolean>(tweaks.liveMode);

  useEffect(() => {
    setLayers((L) => ({ ...L, narrative: tweaks.showNarrative }));
  }, [tweaks.showNarrative]);

  useEffect(() => {
    setLive(tweaks.liveMode);
  }, [tweaks.liveMode]);

  const [selectedPath, setSelectedPath] = useState<string>("summary.json");
  const [filter, setFilter] = useState<string>("");
  const [activeBeat, setActiveBeat] = useState<number>(0);
  const [playing, setPlaying] = useState<boolean>(false);
  const [highlightEdges, setHighlightEdges] = useState<string[]>([]);
  const [pulseBatch, setPulseBatch] = useState<PulseSpec[]>([]);
  const [denialFlash, setDenialFlash] = useState<string[]>([]);
  const [degraded, setDegraded] = useState<string[]>([]);

  const pulseIdRef = useRef<number>(0);
  const addPulse = useCallback((edgeId: string, kind: string, label: string, duration = 2000) => {
    pulseIdRef.current += 1;
    const id = pulseIdRef.current;
    setPulseBatch((b) => [
      ...b,
      {
        key: id,
        edgeId,
        kind,
        label,
        duration,
        onDone: () => setPulseBatch((bb) => bb.filter((x) => x.key !== id)),
      },
    ]);
  }, []);

  useEffect(() => {
    if (!layers.graph) return;
    const ambientEdges: readonly string[] = ["e5", "e2", "e7", "e8"];
    const id = setInterval(() => {
      const pick = ambientEdges[Math.floor(Math.random() * ambientEdges.length)] ?? "e5";
      addPulse(pick, "", "cap", 2600);
    }, 1700);
    return () => clearInterval(id);
  }, [layers.graph, addPulse]);

  const applyBeatEffects = useCallback(
    (beat: Beat | undefined) => {
      if (!beat) return;
      if (beat.pause && beat.edges && beat.edges.length) {
        setDenialFlash(beat.edges);
        beat.edges.forEach((eid) => addPulse(eid, "denial", "deny", 1000));
        setTimeout(() => setDenialFlash([]), 2200);
      }
      if (beat.n === 7) {
        setDegraded(["proofworks.provider", "proofworks.subcontract-desk"]);
        setTimeout(() => setDegraded([]), 2800);
      }
      if (beat.n === 9) addPulse("e7", "x402", "x402", 2200);
      if (beat.n === 8) addPulse("e7", "passport", "approve", 2200);
      if (beat.n === 6) addPulse("e6", "", "scope", 2400);
      if (beat.n === 5) addPulse("e5", "", "award", 2400);
      if (beat.n === 2) addPulse("e5", "", "rfq", 2400);
      if (beat.n === 11) {
        addPulse("e8", "", "read", 1800);
        addPulse("e9", "", "attest", 2200);
      }
    },
    [addPulse],
  );

  useEffect(() => {
    if (!playing) return;
    const beat = beats[activeBeat];
    applyBeatEffects(beat);
    if (beat?.pause) {
      setPlaying(false);
      return;
    }
    const id = setTimeout(() => {
      setActiveBeat((i) => Math.min(beats.length - 1, i + 1));
    }, 3200);
    return () => clearTimeout(id);
  }, [playing, activeBeat, beats, applyBeatEffects]);

  useEffect(() => {
    const beat = beats[activeBeat];
    if (!beat) return;
    setHighlightEdges(beat.edges ?? []);
    if (beat.artifacts && beat.artifacts[0]) {
      setSelectedPath(beat.artifacts[0]);
    }
    applyBeatEffects(beat);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeBeat]);

  const onPickEdge = useCallback((e: Edge) => {
    setHighlightEdges([e.id]);
    const files = bundle.manifest.files;
    const pick = (prefix: string): string | null => files.find((p) => p.startsWith(prefix)) ?? null;
    let target: string;
    if (e.kind === "mediated") {
      target =
        pick("chio/receipts/market-api-sidecar") ??
        pick("chio/receipts/settlement-api-sidecar") ??
        pick("chio/receipts/") ??
        "bundle-manifest.json";
    } else if (e.kind === "delegation") {
      target = pick("chio/capabilities/") ?? pick("capabilities/") ?? "bundle-manifest.json";
    } else if (e.kind === "denial") {
      target = pick("adversarial/") ?? pick("guardrails/") ?? "bundle-manifest.json";
    } else {
      target = "chio/topology.json";
    }
    setSelectedPath(target);
  }, [bundle.manifest.files]);

  const toggleLayer = useCallback(
    (k: keyof Layers) => {
      setLayers((L) => {
        const next = { ...L, [k]: !L[k] };
        if (!next.graph && !next.explorer) return L;
        if (k === "narrative") {
          setTweaks((t) => ({ ...t, showNarrative: next.narrative }));
        }
        return next;
      });
    },
    [],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (target && target.tagName === "INPUT") return;
      if (e.key === "[") setActiveBeat((i) => Math.max(0, i - 1));
      else if (e.key === "]") setActiveBeat((i) => Math.min(beats.length - 1, i + 1));
      else if (e.key === "g") toggleLayer("graph");
      else if (e.key === "x") toggleLayer("explorer");
      else if (e.key === "n") toggleLayer("narrative");
      else if (e.key === "/") {
        e.preventDefault();
        document.querySelector<HTMLInputElement>(".tree-filter input")?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [beats.length, toggleLayer]);

  const mainClass =
    "main" + (!layers.graph ? " explorer-only" : "") + (!layers.explorer ? " graph-only" : "");

  return (
    <div className="app">
      <TopBar
        review={bundle.review}
        summary={bundle.summary}
        manifest={bundle.manifest}
        layers={layers}
        onToggleLayer={toggleLayer}
        live={live}
        onToggleLive={() => {
          const next = !live;
          setLive(next);
          setTweaks((t) => ({ ...t, liveMode: next }));
        }}
        effectiveVerdict={effectiveVerdict}
        bundleDigest={bundleDigest}
        firstMismatchPath={firstMismatchPath}
      />

      <div className={mainClass}>
        {layers.graph ? (
          <div className="pane">
            <div className="pane-header">
              <span>graph - anchored four-quadrant topology</span>
              <span className="muted">chio/topology.json</span>
            </div>
            <div style={{ height: "calc(100% - 28px)" }}>
              <Graph
                topology={bundle.topology}
                onPickEdge={onPickEdge}
                highlightEdges={highlightEdges}
                pulseBatch={pulseBatch}
                denialFlash={denialFlash}
                degraded={degraded}
              />
            </div>
            <Chrome summary={bundle.summary} />
            <div className="hint">[ / ] narrative beat - g graph - x explorer - / filter</div>
          </div>
        ) : null}
        {layers.explorer ? (
          <div className="pane">
            <div className="pane-header">
              <span>explorer - verify any claim against raw artifact</span>
              <span className="muted">offline - in-browser hash check</span>
            </div>
            <div style={{ height: "calc(100% - 28px)" }}>
              <Explorer
                selectedPath={selectedPath}
                onSelectPath={setSelectedPath}
                filter={filter}
                onFilter={setFilter}
              />
            </div>
          </div>
        ) : null}
      </div>

      {layers.narrative ? (
        <Narrative
          beats={beats}
          activeIdx={activeBeat}
          onPick={(i) => setActiveBeat(i)}
          playing={playing}
          onTogglePlay={() => setPlaying((p) => !p)}
        />
      ) : null}

      {DEV_FLAG ? (
        <TweaksPanel
          state={tweaks}
          onChange={(patch) => setTweaks((t) => ({ ...t, ...patch }))}
          onTriggerDenial={() => {
            setDenialFlash(["d1", "d2"]);
            addPulse("d1", "denial", "forged-passport", 1000);
            addPulse("d2", "denial", "over-budget", 1000);
            setTimeout(() => setDenialFlash([]), 2200);
            setSelectedPath("adversarial/forged_passport-denial.json");
          }}
          onSimulateWobble={() => {
            setDegraded(["proofworks.provider", "proofworks.subcontract-desk"]);
            setTimeout(() => setDegraded([]), 3000);
            setSelectedPath("identity/runtime-degradation/provider-quarantine.json");
          }}
          onJumpManifest={() => setSelectedPath("bundle-manifest.json")}
        />
      ) : null}
    </div>
  );
}
