"use client";
import {
  useEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import type {
  CommandRequest,
  Document,
  Selection,
  State,
} from "@/lib/workshop/schema";
import type { WorkshopModel } from "@/lib/workshop/view-model";
import type { Observation } from "@/lib/workshop/local-client";
import {
  AGENT_NAMES,
  ROLE_IDS,
  setupLabel,
  type Setup,
} from "@/lib/workshop/setup-code";
import { actionAvailability, documentFor } from "@/lib/workshop/presentation";
import { FIRST_CHANGE } from "@/lib/workshop/first-change";
import { sourceDiff } from "@/lib/workshop/diff";
import type { WorkshopNavigation } from "@/lib/workshop/navigation";
import s from "./workshop.module.css";

const roleNames = {
  research: "Research",
  implementation: "Implementation",
  review: "Review",
};
const documents: { id: Document; label: string }[] = [
  { id: "changes", label: "Changes" },
  { id: "tests", label: "Tests" },
  { id: "source", label: "Source" },
];
export function Arrow() {
  return <span aria-hidden="true">→</span>;
}
export function Source({
  source,
  label = "Source code",
}: {
  source: string;
  label?: string;
}) {
  return (
    <div
      className={s.codeScroll}
      tabIndex={0}
      role="region"
      aria-label={`${label}; scroll to read long lines`}
    >
      <pre>
        {source
          .trimEnd()
          .split("\n")
          .map((line, index) => (
            <span className={s.codeLine} key={index}>
              <span className={s.lineNumber} aria-hidden="true">
                {index + 1}
              </span>
              <code>{line}</code>
            </span>
          ))}
      </pre>
    </div>
  );
}
function Diff({
  original,
  candidate,
}: {
  original: string;
  candidate: string;
}) {
  const lines = sourceDiff(original, candidate);
  if (!lines)
    return (
      <p className={s.diffNote}>Open Source to compare these complete files.</p>
    );
  if (!lines.length)
    return (
      <p className={s.diffNote}>
        The candidate matches the original source. Inspect the harness and
        results for this mission.
      </p>
    );
  return (
    <div
      className={s.diffScroll}
      tabIndex={0}
      role="region"
      aria-label="Exact changed source lines"
    >
      <div className={s.diff}>
        <p className={s.diffContext}>lib.rs · changed lines</p>
        {lines.map((line, index) =>
          line.kind === "gap" ? (
            <p className={s.diffContext} key={index}>
              ···
            </p>
          ) : (
            <div
              className={
                line.kind === "added"
                  ? s.added
                  : line.kind === "removed"
                    ? s.removed
                    : s.unchanged
              }
              key={index}
            >
              <span aria-label={line.kind === "same" ? undefined : line.kind}>
                {line.kind === "added"
                  ? "+"
                  : line.kind === "removed"
                    ? "−"
                    : " "}
              </span>
              <code>{line.text}</code>
            </div>
          ),
        )}
      </div>
    </div>
  );
}
function Empty({ children }: { children: ReactNode }) {
  return <div className={s.empty}>{children}</div>;
}
function Evidence({
  model,
  document,
  onDocument,
  expanded,
  onExpand,
}: {
  model: WorkshopModel;
  document: Document;
  onDocument: (doc: Document) => void;
  expanded: boolean;
  onExpand: () => void;
}) {
  const [source, setSource] = useState<"original" | "candidate" | "harness">(
    "original",
  );
  const scroll = useRef<HTMLDivElement>(null);
  const positions = useRef<Record<string, [number, number]>>({});
  function changeDocument(next: Document) {
    const element = scroll.current?.querySelector(
      `.${s.codeScroll},.${s.diffScroll}`,
    );
    if (element)
      positions.current[`${document}/${source}`] = [
        element.scrollLeft,
        element.scrollTop,
      ];
    onDocument(next);
  }
  useEffect(() => {
    const element = scroll.current?.querySelector(
      `.${s.codeScroll},.${s.diffScroll}`,
    );
    const position = positions.current[`${document}/${source}`];
    if (element && position) {
      element.scrollLeft = position[0];
      element.scrollTop = position[1];
    }
  }, [document, source]);
  function navigate(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const next =
      event.key === "ArrowRight"
        ? (index + 1) % 3
        : event.key === "ArrowLeft"
          ? (index + 2) % 3
          : event.key === "Home"
            ? 0
            : event.key === "End"
              ? 2
              : null;
    if (next === null) return;
    event.preventDefault();
    changeDocument(documents[next].id);
    window.document
      .getElementById(`workshop-tab-${documents[next].id}`)
      ?.focus();
  }
  const tests = model.tests;
  const passed =
    tests?.checks.filter((test) => test.status === "passed").length ?? 0;
  return (
    <>
      <div className={s.artifactNavigation}>
        <div className={s.tabs} role="tablist" aria-label="Project artifacts">
          {documents.map((doc, i) => (
            <button
              key={doc.id}
              role="tab"
              id={`workshop-tab-${doc.id}`}
              aria-selected={document === doc.id}
              aria-controls="workshop-document"
              tabIndex={document === doc.id ? 0 : -1}
              onClick={() => changeDocument(doc.id)}
              onKeyDown={(event) => navigate(event, i)}
            >
              {doc.label}
              {doc.id === "tests" && !!tests?.checks.length && (
                <span>{tests.checks.length}</span>
              )}
            </button>
          ))}
        </div>
        <button
          className={s.expandWork}
          onClick={onExpand}
          aria-label={expanded ? "Show workshop" : "Expand work"}
          title={expanded ? "Show workshop" : "Expand work"}
        >
          {expanded ? "⊟" : "⤢"}
        </button>
      </div>
      <div
        ref={scroll}
        className={s.evidence}
        id="workshop-document"
        role="tabpanel"
        aria-labelledby={`workshop-tab-${document}`}
        tabIndex={0}
      >
        {document === "changes" && (
          <>
            {model.original !== null && model.candidate !== null ? (
              <Diff original={model.original} candidate={model.candidate} />
            ) : (
              <Empty>
                <strong>No candidate yet.</strong>
                <p>
                  The source remains available while the mission prepares a
                  repair.
                </p>
                <button
                  className={s.textButton}
                  onClick={() => changeDocument("source")}
                >
                  Read the input files <Arrow />
                </button>
              </Empty>
            )}
            {tests && (
              <button
                className={s.resultLine}
                onClick={() => changeDocument("tests")}
              >
                <span
                  className={tests.status === "passed" ? s.pass : undefined}
                >
                  {tests.status === "passed" ? "✓" : "◇"}{" "}
                  <strong>
                    {tests.status === "passed"
                      ? `${passed} checks passed`
                      : tests.status === "pending"
                        ? "Tests pending"
                        : tests.status.replaceAll("_", " ")}
                  </strong>
                </span>
                <span>
                  View results <Arrow />
                </span>
              </button>
            )}
            {model.proposal && (
              <div className={s.reviewNote}>
                <span aria-hidden="true">◇</span>
                <p>
                  {model.publication
                    ? "Published locally"
                    : "Awaiting owner review"}
                  <small>
                    {model.publication
                      ? "The retained release matches this candidate."
                      : "Passing tests do not publish the candidate."}
                  </small>
                </p>
              </div>
            )}
          </>
        )}
        {document === "tests" &&
          (tests && tests.status !== "pending" ? (
            <div className={s.testResults}>
              <div
                className={s.testCount}
                data-passing={tests.status === "passed"}
              >
                <strong>
                  {passed}
                  <span>/{tests.checks.length || "?"}</span>
                </strong>
                <div>
                  {tests.status === "passed"
                    ? "Checks passed"
                    : tests.status.replaceAll("_", " ")}
                  <small>
                    {tests.complete
                      ? "Retained test output"
                      : "Complete named results are unavailable"}
                  </small>
                </div>
              </div>
              <ul>
                {tests.checks.map((check) => (
                  <li key={check.name}>
                    <span
                      className={check.status === "passed" ? s.pass : undefined}
                      aria-label={check.status}
                    >
                      {check.status === "passed"
                        ? "✓"
                        : check.status === "failed"
                          ? "×"
                          : "–"}
                    </span>
                    <div>
                      {check.name.replaceAll("_", " ")}
                      <code>{check.name}</code>
                    </div>
                  </li>
                ))}
              </ul>
              {tests.output && (
                <details>
                  <summary>Read the test output</summary>
                  <pre tabIndex={0}>{tests.output}</pre>
                </details>
              )}
              {tests.compiler_output && (
                <details open>
                  <summary>Compiler output</summary>
                  <pre tabIndex={0}>{tests.compiler_output}</pre>
                </details>
              )}
            </div>
          ) : (
            <Empty>
              <strong>Results will appear here.</strong>
              <p>
                Checks are shown only after the host reports their actual
                outcomes.
              </p>
            </Empty>
          ))}
        {document === "source" && (
          <>
            <div className={s.sourceChoice}>
              <label htmlFor="workshop-file">File</label>
              <select
                id="workshop-file"
                value={source}
                onChange={(event) =>
                  setSource(event.target.value as typeof source)
                }
              >
                <option value="original">lib.rs · Original</option>
                <option value="candidate">lib.rs · Candidate</option>
                <option value="harness">tests.rs · Harness</option>
              </select>
            </div>
            {model[source] !== null ? (
              <Source
                source={model[source]}
                label={
                  source === "harness" ? "Test harness" : `${source} source`
                }
              />
            ) : (
              <Empty>This file is not available yet.</Empty>
            )}
          </>
        )}
      </div>
      <details className={s.provenance}>
        <summary>
          {model.source.kind === "recorded"
            ? "About this record"
            : "Work and identity"}
          <span>
            {model.source.kind === "recorded"
              ? "Reference · saved"
              : "Local · retained"}
          </span>
        </summary>
        <p>
          {model.source.kind === "recorded"
            ? `${model.source.qualification} The scene illustrates the roles; it is not a captured replay.`
            : "This view reads the selected mission on your computer. Selecting a role changes what you inspect; it does not start or redirect work."}
        </p>
        <dl>
          <dt>Candidate digest</dt>
          <dd>{model.proposal?.candidate_digest ?? "Not available yet"}</dd>
          <dt>Harness digest</dt>
          <dd>{model.tests?.harness_digest ?? "Not initialized"}</dd>
          {model.source.kind === "local" && (
            <>
              <dt>Mission</dt>
              <dd>{model.source.missionId ?? "Setup draft"}</dd>
            </>
          )}
          {model.publication && (
            <>
              <dt>Publication</dt>
              <dd>{model.publication.destination}</dd>
            </>
          )}
        </dl>
      </details>
    </>
  );
}

export type LocalControls = {
  observation: Observation;
  onCommand: (command: CommandRequest["command"]) => void;
  onMission: (id: string) => void;
  onRefresh: () => void;
};
type Props = {
  model: WorkshopModel;
  navigation: WorkshopNavigation;
  onNavigate: (next: WorkshopNavigation, push?: boolean) => void;
  setup: Setup;
  onSetup: (setup: Setup) => void;
  scene: ReactNode;
  landing?: ReactNode;
  local?: LocalControls;
  installation?: ReactNode;
};

function copy(text: string, setStatus: (status: string) => void) {
  void navigator.clipboard?.writeText(text).then(
    () => setStatus("Copied."),
    () => setStatus("Select and copy the complete command below."),
  );
  if (!navigator.clipboard)
    setStatus("Select and copy the complete command below.");
}
export function CopyCommand({
  command,
  label,
}: {
  command: string;
  label: string;
}) {
  const [status, setStatus] = useState("");
  return (
    <div className={s.commandBlock}>
      <div>
        <span>{label}</span>
        <button onClick={() => copy(command, setStatus)}>Copy</button>
      </div>
      <pre tabIndex={0} aria-label={label}>
        <code>{command}</code>
      </pre>
      <span role="status">{status}</span>
    </div>
  );
}
function SetupPanel({
  setup,
  onSetup,
  onContinue,
}: {
  setup: Setup;
  onSetup: (setup: Setup) => void;
  onContinue: () => void;
}) {
  const native = setup.workers.mode === "native";
  return (
    <div className={s.setup}>
      <div className={s.setupProject}>
        <span className={s.projectGlyph} aria-hidden="true">
          ▤
        </span>
        <div>
          <strong>Example project</strong>
          <small>Moving average · Rust module + tests</small>
        </div>
        <span className={s.fixedLabel}>INCLUDED</span>
      </div>
      <fieldset className={s.runMode}>
        <legend>Run with</legend>
        <label className={!native ? s.choiceSelected : undefined}>
          <input
            type="radio"
            name="workshop-mode"
            checked={!native}
            onChange={() =>
              onSetup({ ...setup, workers: { mode: "reference" } })
            }
          />
          <span>
            Reference workers
            <small>A reproducible first run. No model account.</small>
          </span>
        </label>
        <label className={native ? s.choiceSelected : undefined}>
          <input
            type="radio"
            name="workshop-mode"
            checked={native}
            onChange={() =>
              onSetup({
                ...setup,
                workers: {
                  mode: "native",
                  roles: {
                    research: "codex",
                    implementation: "codex",
                    review: "codex",
                  },
                },
              })
            }
          />
          <span>
            My native agents
            <small>Use existing agents and their local sign-ins.</small>
          </span>
        </label>
      </fieldset>
      {native && (
        <div className={s.agentSetup}>
          <label htmlFor="workshop-team">Agents by role</label>
          <select
            id="workshop-team"
            value={
              setup.workers.mode === "native" &&
              setup.workers.roles.research === "hermes"
                ? "mixed"
                : "codex"
            }
            onChange={(event) =>
              onSetup({
                ...setup,
                workers: {
                  mode: "native",
                  roles:
                    event.target.value === "mixed"
                      ? {
                          research: "hermes",
                          implementation: "codex",
                          review: "pi",
                        }
                      : {
                          research: "codex",
                          implementation: "codex",
                          review: "codex",
                        },
                },
              })
            }
          >
            <option value="codex">Codex · all roles</option>
            <option value="mixed">Hermes / Codex / Pi</option>
          </select>
          <dl className={s.configuration}>
            {ROLE_IDS.map((role) => (
              <div key={role}>
                <dt>{roleNames[role]}</dt>
                <dd>
                  {setup.workers.mode === "native" &&
                    AGENT_NAMES[setup.workers.roles[role]]}
                </dd>
              </div>
            ))}
          </dl>
          <p className={s.supporting}>
            Availability depends on your computer and the installed release.
            Native runs use your existing account and its usage limits.
          </p>
        </div>
      )}
      <button className={s.primary} onClick={onContinue}>
        Continue locally <Arrow />
      </button>
      <p className={s.supporting}>
        Your project and credentials stay on your computer.
      </p>
    </div>
  );
}
function LocalAction({
  controls,
  type,
  children,
  command,
  secondary = false,
}: {
  controls: LocalControls;
  type: CommandRequest["command"]["type"];
  command: CommandRequest["command"];
  children: ReactNode;
  secondary?: boolean;
}) {
  const { state, freshness, pending } = controls.observation;
  const availability = state
    ? actionAvailability(state, type, freshness)
    : { enabled: false, reason: "Waiting for the local host." };
  const pendingIntent =
    !!pending && ["accepted", "running", "unknown"].includes(pending.status);
  return (
    <div className={s.actionBlock}>
      <button
        className={secondary ? s.secondary : s.primary}
        disabled={!availability.enabled || pendingIntent}
        onClick={() => controls.onCommand(command)}
      >
        {children}
        <Arrow />
      </button>
      {!availability.enabled && (
        <p className={s.supporting}>{availability.reason}</p>
      )}
    </div>
  );
}
function Readiness({ controls }: { controls: LocalControls }) {
  return (
    <ul className={s.readiness}>
      {controls.observation.state?.readiness.map((check) => (
        <li key={check.id}>
          <span aria-label={check.status}>
            {check.status === "ready" ? "✓" : check.blocking ? "◇" : "·"}
          </span>
          <div>
            <strong>{check.label}</strong>
            <p>{check.message}</p>
            {check.agent && check.status === "missing" && (
              <LocalAction
                controls={controls}
                type="prepare_agent"
                command={{ type: "prepare_agent", agent: check.agent }}
                secondary
              >
                Prepare {AGENT_NAMES[check.agent]}
              </LocalAction>
            )}
          </div>
        </li>
      ))}
    </ul>
  );
}

export default function Workshop({
  model,
  navigation: nav,
  onNavigate,
  setup,
  onSetup,
  scene,
  landing,
  local,
  installation,
}: Props) {
  const [expanded, setExpanded] = useState(false);
  const [approvalDigest, setApprovalDigest] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const state = local?.observation.state;
  const selectedRole =
    nav.selection.kind === "role" ? nav.selection.role : null;
  const change = (update: Partial<WorkshopNavigation>, push = false) => {
    onNavigate({ ...nav, ...update }, push);
    if (update.panel || update.open) setExpanded(false);
  };
  function panel(next: WorkshopNavigation["panel"]) {
    change({ panel: next });
    requestAnimationFrame(() => {
      heading.current?.focus({ preventScroll: true });
      if (matchMedia("(max-width:820px)").matches)
        heading.current?.scrollIntoView({ block: "start" });
    });
  }
  function select(selection: Selection) {
    change(
      {
        open: true,
        selection,
        document: documentFor(selection),
        panel: "inspect",
      },
      !nav.open,
    );
    if (matchMedia("(max-width:820px)").matches)
      requestAnimationFrame(() =>
        heading.current?.scrollIntoView({ block: "start" }),
      );
  }
  useEffect(() => {
    setApprovalDigest(null);
    setConfirmed(false);
  }, [
    model.source.kind === "local"
      ? model.source.missionId
      : model.source.recordId,
  ]);
  const title =
    nav.panel === "setup"
      ? "Run this workshop."
      : nav.panel === "install"
        ? "Continue on your computer."
        : nav.panel === "revise"
          ? "Give it one more test."
          : model.phase === "setup"
            ? "Ready to make it yours."
            : selectedRole === "research"
              ? "Understand the failure."
              : selectedRole === "review"
                ? "Check the result."
                : selectedRole === "implementation"
                  ? "Inspect the repair."
                  : "One shared project.";
  const copy =
    nav.panel === "setup"
      ? "Start with the example project. Choose how the work runs on your computer."
      : nav.panel === "install"
        ? "Install Chio, open the local workshop, and continue with the same setup."
        : nav.panel === "revise"
          ? "Add a singleton-window regression in a fresh mission. The original run remains available."
          : model.phase === "setup"
            ? "Review the setup and local prerequisites. Initialize when you are ready; starting work is a separate action."
            : selectedRole === "research"
              ? "The original module can divide by zero and overflow its accumulator. Inspect the source and its test harness."
              : selectedRole === "review"
                ? "Inspect the actual checks and candidate identity before deciding whether to publish."
                : selectedRole === "implementation"
                  ? "Compare the original module with the candidate produced by this mission."
                  : "The source, test harness, and candidate belong to this selected mission.";
  const phaseLabel =
    model.phase === "awaiting_review"
      ? "Awaiting owner review"
      : model.phase.replaceAll("_", " ");
  const currentApproval =
    approvalDigest !== null &&
    approvalDigest === model.proposal?.candidate_digest &&
    model.candidate !== null;
  return (
    <div
      className={`${s.workspace} ${nav.open ? s.open : ""} ${expanded ? s.focusWork : ""}`}
    >
      <div className={s.workshopBar} hidden={!nav.open}>
        {!local && (
          <button
            className={s.textButton}
            onClick={() => {
              setExpanded(false);
              change({ open: false, panel: "inspect" }, true);
            }}
          >
            ← <span>Build overview</span>
          </button>
        )}
        <div>
          <span className={s.tinyCross} aria-hidden="true">
            ✦
          </span>
          Software factory<span className={s.barSlash}>/</span>
          <span className={s.barProject}>Moving average</span>
        </div>
        <span className={local ? s.localStatus : s.recordStatus}>
          <i aria-hidden="true" />
          {local
            ? local.observation.freshness === "current"
              ? "RUNNING ON YOUR COMPUTER"
              : "LAST OBSERVED WORK"
            : "RECORDED REFERENCE"}
        </span>
      </div>
      {local && (
        <div className={s.localStrip}>
          <label htmlFor="workshop-mission">Mission</label>
          <select
            id="workshop-mission"
            disabled={!state?.workspace.missions.length}
            value={state?.mission?.id ?? ""}
            onChange={(event) => local.onMission(event.target.value)}
          >
            {!state?.workspace.missions.length && (
              <option value="">Setup draft</option>
            )}
            {state?.workspace.missions.map((mission) => (
              <option key={mission.id} value={mission.id}>
                {mission.label}
              </option>
            ))}
          </select>
          <span role="status">{phaseLabel}</span>
        </div>
      )}
      {local?.observation.error && (
        <div className={s.connectionNotice} role="status">
          <p>{local.observation.error}</p>
          <button className={s.textButton} onClick={local.onRefresh}>
            Refresh state <Arrow />
          </button>
        </div>
      )}
      <section
        className={s.stage}
        aria-label={nav.open ? "Software factory workshop" : "Build with Chio"}
      >
        <div className={s.heroCopy} hidden={nav.open}>
          {landing}
        </div>
        <div className={s.machineStage}>
          {scene}
          {nav.open ? (
            <>
              <div
                className={s.roleRail}
                role="group"
                aria-label="Inspect a role"
              >
                {ROLE_IDS.map((role, index) => (
                  <button
                    key={role}
                    data-role={role}
                    aria-pressed={
                      selectedRole === role && nav.panel === "inspect"
                    }
                    onClick={() => select({ kind: "role", role })}
                  >
                    <span className={s.roleNumber}>0{index + 1}</span>
                    <span>
                      {roleNames[role]}
                      <small>
                        {model.agents
                          ? AGENT_NAMES[model.agents[role]]
                          : role === "research"
                            ? "Source & assignment"
                            : role === "implementation"
                              ? "Candidate & changes"
                              : "Checks & decision"}
                      </small>
                    </span>
                    {model.activeRole === role && (
                      <i
                        className={s.activeRole}
                        aria-label="Currently running"
                      />
                    )}
                  </button>
                ))}
              </div>
              <button
                className={s.projectLine}
                aria-pressed={nav.selection.kind === "project"}
                onClick={() => select({ kind: "project" })}
              >
                <span className={s.projectGlyph} aria-hidden="true">
                  ▤
                </span>
                <span>
                  Project<small>moving-average / lib.rs + tests.rs</small>
                </span>
                <Arrow />
              </button>
              <p className={s.sceneCaption}>
                Three roles. One shared project.
                <span>
                  {local
                    ? `Selected setup: ${setupLabel(setup)}`
                    : "Inspect this example, then run it locally."}
                </span>
              </p>
              {local?.observation.pending && (
                <div className={s.commandStatus} role="status">
                  <span>{local.observation.pending.status}</span>
                  <p>{local.observation.pending.message}</p>
                </div>
              )}
            </>
          ) : (
            <div className={s.sceneInvitation}>
              <span className={s.sceneLine} />
              <button
                className={s.textButton}
                onClick={() => change({ open: true }, true)}
              >
                Look inside <span aria-hidden="true">⌁</span>
              </button>
              <span className={s.sceneLine} />
            </div>
          )}
        </div>
        {nav.open && (
          <section className={s.inspector} aria-labelledby="workshop-heading">
            <div className={s.inspectorTop}>
              <span>
                {nav.panel === "inspect"
                  ? selectedRole
                    ? `${String(ROLE_IDS.indexOf(selectedRole) + 1).padStart(2, "0")} / ${roleNames[selectedRole].toUpperCase()}`
                    : "PROJECT"
                  : nav.panel === "revise"
                    ? "YOUR FIRST CHANGE"
                    : "LOCAL SETUP"}
              </span>
              {!local && nav.panel === "inspect" ? (
                <button
                  className={s.smallAction}
                  onClick={() => panel("setup")}
                >
                  Run locally <Arrow />
                </button>
              ) : nav.panel !== "inspect" ? (
                <button
                  className={s.smallAction}
                  onClick={() =>
                    panel(nav.panel === "install" ? "setup" : "inspect")
                  }
                >
                  ← {nav.panel === "install" ? "Setup" : "Inspect"}
                </button>
              ) : (
                <span>{phaseLabel}</span>
              )}
            </div>
            <div className={s.panelIntro}>
              <h2 id="workshop-heading" ref={heading} tabIndex={-1}>
                {title}
              </h2>
              <p>{copy}</p>
            </div>
            {nav.panel === "inspect" && (
              <>
                {model.phase === "setup" && local ? (
                  <div className={s.localBody}>
                    <div className={s.setupProject}>
                      <span className={s.projectGlyph} aria-hidden="true">
                        ▤
                      </span>
                      <div>
                        <strong>Moving average</strong>
                        <small>{setupLabel(setup)}</small>
                      </div>
                    </div>
                    <Readiness controls={local} />
                    <LocalAction
                      controls={local}
                      type="initialize"
                      command={{ type: "initialize", setup }}
                    >
                      Initialize workshop
                    </LocalAction>
                  </div>
                ) : (
                  <Evidence
                    model={model}
                    document={nav.document}
                    onDocument={(document) => change({ document })}
                    expanded={expanded}
                    onExpand={() => setExpanded((value) => !value)}
                  />
                )}
                {local && model.phase !== "setup" && (
                  <div className={s.localBody}>
                    {model.phase === "ready" && (
                      <>
                        <Readiness controls={local} />
                        <LocalAction
                          controls={local}
                          type="run"
                          command={{ type: "run" }}
                        >
                          Start example
                        </LocalAction>
                      </>
                    )}
                    {["blocked", "interrupted"].includes(model.phase) && (
                      <>
                        <p className={s.supporting}>
                          Review retained results before continuing. Resume
                          keeps the original operation identities and allowance.
                        </p>
                        <LocalAction
                          controls={local}
                          type="resume"
                          command={{ type: "resume" }}
                        >
                          Resume mission
                        </LocalAction>
                      </>
                    )}
                    {model.proposal && !model.publication && (
                      <div className={s.approval}>
                        <button
                          className={s.secondary}
                          onClick={() => {
                            setApprovalDigest(model.proposal!.candidate_digest);
                            setConfirmed(false);
                          }}
                        >
                          Review publication
                        </button>
                        {approvalDigest && (
                          <div>
                            <p>
                              Publish this candidate to this mission’s local
                              release folder.
                            </p>
                            <code className={s.digest}>{approvalDigest}</code>
                            {currentApproval ? (
                              <Source
                                source={model.candidate!}
                                label="Candidate to publish"
                              />
                            ) : (
                              <p role="alert">
                                The candidate changed or is unavailable. Review
                                publication again.
                              </p>
                            )}
                            <label className={s.confirmation}>
                              <input
                                type="checkbox"
                                checked={confirmed}
                                onChange={(event) =>
                                  setConfirmed(event.target.checked)
                                }
                              />
                              I reviewed this candidate and its test results.
                            </label>
                            {currentApproval && confirmed && (
                              <LocalAction
                                controls={local}
                                type="approve"
                                command={{
                                  type: "approve",
                                  candidate_digest: approvalDigest,
                                }}
                              >
                                Publish locally
                              </LocalAction>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                    {model.tests?.status === "passed" &&
                      !state?.workspace.missions.find(
                        (mission) => mission.id === state.mission?.id,
                      )?.recipe && (
                        <button
                          className={s.textButton}
                          onClick={() => panel("revise")}
                        >
                          Add one more test <Arrow />
                        </button>
                      )}
                  </div>
                )}
                {!local && (
                  <div className={s.inspectorFooter}>
                    <span>Use this system on your computer.</span>
                    <button
                      className={s.textButton}
                      onClick={() => panel("setup")}
                    >
                      Run locally <Arrow />
                    </button>
                  </div>
                )}
              </>
            )}
            {nav.panel === "setup" && !local && (
              <SetupPanel
                setup={setup}
                onSetup={onSetup}
                onContinue={() => panel("install")}
              />
            )}
            {nav.panel === "install" && (
              <div className={s.install}>
                <dl className={s.configuration}>
                  <div>
                    <dt>Project</dt>
                    <dd>Moving average</dd>
                  </div>
                  <div>
                    <dt>Workers</dt>
                    <dd>{setupLabel(setup)}</dd>
                  </div>
                </dl>
                {installation ?? (
                  <a
                    className={s.primary}
                    href="https://chio.computer/docs/megastart"
                  >
                    Software factory guide <Arrow />
                  </a>
                )}
              </div>
            )}
            {nav.panel === "revise" && (
              <div className={s.localBody}>
                <div className={s.fileBar}>
                  <span>tests.rs</span>
                  <span>One additional regression</span>
                </div>
                <Source
                  source={FIRST_CHANGE}
                  label="Proposed additional test"
                />
                <p className={s.supporting}>
                  The source input stays the same. A fresh harness checks that a
                  one-element window preserves the largest u64 value. The
                  candidate may stay unchanged if it already satisfies the new
                  test.
                </p>
                {local ? (
                  <LocalAction
                    controls={local}
                    type="create_revision"
                    command={{
                      type: "create_revision",
                      recipe: "singleton-window-v1",
                    }}
                  >
                    Create this mission
                  </LocalAction>
                ) : (
                  <button className={s.primary} onClick={() => panel("setup")}>
                    Try it locally <Arrow />
                  </button>
                )}
              </div>
            )}
          </section>
        )}
      </section>
    </div>
  );
}
