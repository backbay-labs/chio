"use client";
import { useEffect, useState, useSyncExternalStore } from "react";
import { createRoot } from "react-dom/client";
import Workshop from "./Workshop";
import Machine from "@/components/chio/build/Machine";
import { LocalClient } from "@/lib/workshop/local-client";
import { fromLocal } from "@/lib/workshop/view-model";
import { OVERVIEW, type WorkshopNavigation } from "@/lib/workshop/navigation";
import { documentFor } from "@/lib/workshop/presentation";
import { IdSchema } from "@/lib/workshop/schema";
import s from "./workshop.module.css";
import "./local.css";
declare const __WORKSHOP_UI_BUILD__: string;

function Header() {
  return (
    <header className={s.header}>
      <a
        href="https://chio.computer"
        className={s.brand}
        aria-label="Chio website"
      >
        <svg viewBox="0 0 36 36" aria-hidden="true">
          <g fill="none" stroke="currentColor" strokeWidth="1.25">
            <ellipse
              cx="18"
              cy="18"
              rx="6"
              ry="16"
              transform="rotate(40 18 18)"
            />
            <ellipse
              cx="18"
              cy="18"
              rx="6"
              ry="16"
              transform="rotate(-40 18 18)"
            />
            <ellipse
              cx="18"
              cy="18"
              rx="6"
              ry="16"
              transform="rotate(90 18 18)"
            />
          </g>
        </svg>
        Chio
      </a>
      <nav aria-label="Workshop links">
        <a href="https://chio.computer/docs/megastart">Guide ↗</a>
      </nav>
      <span className={s.studyLabel}>LOCAL WORKSHOP</span>
    </header>
  );
}
function Connected({ token }: { token: string }) {
  const [client] = useState(
    () => new LocalClient(token, __WORKSHOP_UI_BUILD__),
  );
  const observation = useSyncExternalStore(
    client.subscribe,
    client.snapshot,
    client.snapshot,
  );
  const [nav, setNav] = useState<WorkshopNavigation>({
    ...OVERVIEW,
    open: true,
    document: "source",
    selection: { kind: "project" },
  });
  const [paused, setPaused] = useState(false);
  useEffect(() => {
    client.start();
    const requested = IdSchema.safeParse(
      new URL(location.href).searchParams.get("mission"),
    );
    if (requested.success) client.select(requested.data);
    return () => client.stop();
  }, [client]);
  const state = observation.state;
  if (!state)
    return (
      <main className={s.main}>
        <section className={s.localLoading}>
          <span className={s.eyebrow}>SOFTWARE FACTORY</span>
          <h1>Opening your workshop.</h1>
          <p role="status">
            {observation.error ??
              "Reading the setup and retained work from your local host."}
          </p>
          {observation.error && (
            <button
              className={s.secondary}
              onClick={() => void client.refresh()}
            >
              Refresh state
            </button>
          )}
        </section>
      </main>
    );
  const model = fromLocal(
    state,
    observation.artifacts,
    observation.freshness,
    observation.observedAt,
  );
  const role =
    nav.selection.kind === "role" ? nav.selection.role : "implementation";
  return (
    <main className={s.main}>
      <Workshop
        model={model}
        navigation={nav}
        onNavigate={setNav}
        setup={state.workspace.setup}
        onSetup={() => {}}
        local={{
          observation,
          onCommand: (command) => {
            void client.send(command);
            if (command.type === "create_revision")
              setNav((current) => ({
                ...current,
                panel: "inspect",
                document: "tests",
              }));
          },
          onMission: (id) => {
            client.select(id);
            const url = new URL(location.href);
            url.searchParams.set("mission", id);
            history.replaceState(history.state, "", url);
          },
          onRefresh: () => void client.refresh(),
        }}
        scene={
          <>
            <div className={s.sceneTop}>
              <span>SOFTWARE FACTORY</span>
              <button
                className={s.replay}
                onClick={() => setPaused((value) => !value)}
              >
                {paused ? "Play" : "Pause"} illustration
              </button>
            </div>
            <Machine
              selected={role}
              engaged={model.activeRole}
              wide={false}
              paused={paused}
              illustration={false}
              showSelection={nav.selection.kind === "role"}
              onFocusFactory={() => {}}
              onSelect={(role) => {
                const selection = { kind: "role", role } as const;
                setNav((current) => ({
                  ...current,
                  selection,
                  document: documentFor(selection),
                  panel: "inspect",
                }));
              }}
            />
            <p className={s.sceneMode}>
              Architectural illustration · current activity is reported by the
              host.
            </p>
          </>
        }
      />
      <footer className={s.footer}>
        <span>CHIO / LOCAL WORKSHOP</span>
        <span>Keep the host terminal open.</span>
      </footer>
    </main>
  );
}
function sessionToken(): string | null {
  const key = "chio:workshop:session:v1";
  const fragment = location.hash.slice(1);
  // Consume the fragment before mounting any navigation or fetching data.
  if (fragment)
    history.replaceState(
      history.state,
      "",
      location.pathname + location.search,
    );
  if (/^[a-f0-9]{64}$/.test(fragment)) {
    try {
      sessionStorage.setItem(key, fragment);
    } catch {
      /* In-memory use still works. */
    }
    return fragment;
  }
  try {
    const retained = sessionStorage.getItem(key);
    return retained && /^[a-f0-9]{64}$/.test(retained) ? retained : null;
  } catch {
    return null;
  }
}
const token = sessionToken();
createRoot(document.getElementById("root")!).render(
  <div className={`${s.page} ${s.localPage}`}>
    <a className={s.skip} href="#workshop-heading">
      Skip to the inspector
    </a>
    <Header />
    {token ? (
      <Connected token={token} />
    ) : (
      <main className={s.main}>
        <section className={s.localLoading}>
          <h1>Reopen your workshop.</h1>
          <p>
            Use the local URL printed in your Chio terminal. It connects this
            browser to the current host session.
          </p>
        </section>
      </main>
    )}
  </div>,
);
