import { prefersReducedMotion } from "@/lib/motion-policy";

export const BUILD_SEEN_KEY = "chio:build:workshop-seen:v1";
export const BUILD_REPLAY_EVENT = "chio:build:replay";

export function hasSeenWorkshop(): boolean {
  try { return sessionStorage.getItem(BUILD_SEEN_KEY) === "1"; } catch { return false; }
}

export function rememberWorkshop(): void {
  try { sessionStorage.setItem(BUILD_SEEN_KEY, "1"); } catch { /* Storage is optional. */ }
}

let departure: { started: number; release: () => void } | null = null;

/** Claim the existing home canvas so there is no flash of the destination. */
export function claimBuildDeparture() {
  const current = departure;
  departure = null;
  return current;
}

/** Navigate immediately; the destination loads under the departing pixel field. */
export function runBuildTransition(navigate: () => void): void {
  if (departure) return;
  if (prefersReducedMotion() || hasSeenWorkshop()) { navigate(); return; }
  const source = document.querySelector<HTMLCanvasElement>(".swarm-canvas");
  if (!source?.width || !source.height) { navigate(); return; }
  const veil = document.createElement("canvas");
  const context = veil.getContext("2d");
  if (!context) { navigate(); return; }
  veil.width = source.width; veil.height = source.height;
  veil.setAttribute("aria-hidden", "true");
  veil.dataset.buildDeparture = "";
  Object.assign(veil.style, { position: "fixed", inset: "0", width: "100%", height: "100%", zIndex: "400", pointerEvents: "none", background: "#09080d" });
  context.drawImage(source, 0, 0);
  document.body.appendChild(veil);
  const started = performance.now();
  let frame = 0;
  const release = () => {
    cancelAnimationFrame(frame); clearTimeout(fuse); veil.remove();
    window.removeEventListener("popstate", release);
    document.removeEventListener("visibilitychange", onVisibility);
    if (departure?.release === release) departure = null;
  };
  const onVisibility = () => { if (document.hidden) release(); };
  const fuse = window.setTimeout(release, 6500);
  const draw = (now: number) => {
    const p = Math.min(1, (now - started) / 380);
    const cell = Math.max(8, Math.round(veil.width / 120));
    context.fillStyle = "#09080d";
    for (let y = 0; y < veil.height / cell; y++) for (let x = 0; x < veil.width / cell; x++) {
      // A stable diagonal dissolution; no random flicker between frames.
      const threshold = ((x * 17 + y * 31) % 101) / 101 * .65 + x * cell / veil.width * .35;
      if (threshold <= p) context.fillRect(x * cell, y * cell, cell + 1, cell + 1);
    }
    if (p < 1) frame = requestAnimationFrame(draw);
  };
  departure = { started, release };
  window.addEventListener("popstate", release, { once: true });
  document.addEventListener("visibilitychange", onVisibility);
  frame = requestAnimationFrame(draw);
  try { navigate(); } catch (error) { release(); throw error; }
}
