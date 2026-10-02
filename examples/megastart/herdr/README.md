# Chio for Herdr

**Your agents. A system built on Chio.**

Chio is the modern Rust kernel for agentic operating systems. This terminal
workspace operates Megastart's existing mission host: native agents research,
repair, and review; Chio supplies shared authority, execution rules, and signed
decisions; Herdr supplies the operator workspace.

## Open your mission

Install Megastart with its native-agent feature from the parent application,
then build and register the included plugin once:

```bash
cargo build --release --locked
herdr plugin link .
```

In your Herdr project workspace, choose **Open Chio mission** from plugin actions,
or run:

```bash
herdr plugin action invoke chio.megastart.open
```

The plugin starts a private detached host and opens a mission tab. Choose all
Hermes or a Hermes → Codex → Pi mission. Press **c** to prepare a selected missing
integration using the existing supported login, then **i** to create the mission.
Each action shows a confirmation before execution. Press **r** to start work.
Native launchers currently require Apple Silicon macOS; the terminal client can
also build on Linux. During setup, press **1**, **2**, or **3** to cycle a role
through Hermes, Codex, Pi, and Claude Code. Claude uses your existing Claude login;
the other three integrations use the existing ChatGPT login.

The three swarm panels are **native activity views**. They show retained work
from the headless restricted sessions, not interactive native agent terminals.
They do not register native resume references with Herdr or launch bare agents.

## Operate the system

| Key | Result |
| --- | --- |
| 1 | Mission board, swarm activity, authoritative capacity observation |
| 2 | Original native-operation records and mission outcomes |
| 3 | Original source, exact candidate, proposal, and independent review evidence |
| 4 | Retained host events, readiness, and isolated exercise outcomes |
| ↑ / ↓ | Select an operation in the inspector |
| Page Up / Page Down | Scroll the complete record or candidate review |
| r | Run/reconcile the existing mission through its host |
| a | From candidate review, confirm publication of that exact digest locally |
| x | Confirm the isolated boundary-and-recovery exercise |
| b | Open the same mission in the browser |
| q | Close this view; the host and retained mission survive |

In setup, 1/2/3 cycle each role, **h** chooses all Hermes, and **m** chooses the
mixed mission. No new account or API billing route is selected silently.

## Attach an existing mission

Use an explicit connection file in a private directory to select an existing
mission and keep its identity across host restarts:

```bash
mkdir -p ~/.local/share/chio/my-mission
chmod 700 ~/.local/share/chio/my-mission
chio-herdr --connection ~/.local/share/chio/my-mission/connection.json open \
  --mission /absolute/path/to/mission
```

Install the helper with `cargo install --locked --path .` to use it by name.
The `--megastart` option can select a specific Megastart executable. The board
also runs in an ordinary terminal. `chio-herdr ... status` emits authenticated
state for operator automation without the connection credential.

## Connection and recovery contract

The versioned protocol, process ownership, supported interaction mode, and removal
instructions are specified in [CONTRACT.md](CONTRACT.md).

The host writes an owner-only versioned descriptor containing a loopback endpoint,
operator credential, mission root, and host PID. Treat that descriptor as a secret.
Clients reject remote endpoints and redirects, bypass proxies for loopback calls,
bound response sizes, and never automatically retry a mutating action. Native
text is stripped of terminal control characters before rendering.

Opening a view performs no mission work. Reopening uses the existing host or
restarts a host for the retained mission. A disconnected board labels its last
snapshot and disables actions. Event gaps cause a new snapshot/cursor reconciliation;
they never trigger operation replay. Resume follows the existing kernel receipt
and effect reconciliation contract. An unresolved operation stays unresolved until
that contract permits progress.

The mission host runs in its own Unix session, outside inspection panes. It
receives no Herdr control variables. The plugin has no startup hook and registers
no generic native-session restore command. After Herdr restarts, explicitly open
the mission action to reconstruct the view. Closing or uninstalling the plugin
preserves mission storage. The host remains running until explicitly stopped;
the descriptor identifies its PID for deliberate operator administration.

Plugin registration is per user; mission selection is scoped to Herdr's socket
and workspace. Interface state and mission state live outside the replaceable
plugin source directory. Installing over a working source checkout never bundles
mission credentials, logs, or generated candidates.

## Development checks

```bash
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

The typed operator client, terminal views, and Herdr integration are separate Rust
modules. Chio remains the authority; this plugin contains no allowance counter,
receipt signer, or agent scheduler. Public release and interactive PTY qualification
are tracked in the accompanying acceptance report; a local build does not establish
those results.
