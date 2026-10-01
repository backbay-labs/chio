# Chio for Herdr: operator contract v1

This client operates the Megastart host included in the same source archive.
It requires `megastart console --connection-file`; an older Megastart binary
without that option is not compatible. Build both from this archive and preserve
both Cargo lockfiles. Herdr 0.9.0 and Apple Silicon macOS were exercised; building
the terminal client on another Unix host does not qualify its native launchers.

## Discovery and authentication

The host creates the descriptor in a private directory (0700), as a regular file
(0600). Its fields are `protocol_version`, `endpoint`, `token`, `mission_root`,
and `pid`. Version 1 requires an explicit loopback HTTP address and port, a
64-character hexadecimal bearer token, and an absolute mission path. Descriptor
reads are limited to 8 KiB. The token is never copied into pane metadata or
terminal output. The browser receives it in the fragment and immediately removes
it from the address bar; terminal clients send it only in the Authorization header.

The host checks the exact Host header, bearer authorization, and any supplied
Origin. The client refuses redirects, remote endpoints, and proxy routing. Worker
launchers remain responsible for their existing credential and sandbox boundary.
The plugin does not pass its Herdr control environment to the detached host.

## Read model

`GET /api/state` returns a versioned envelope containing `state`, `busy`, and
`connections` (plus browser-specific readiness fields). The state contains the
retained mission, assignments, native observations, original outcomes, candidate,
proposal, authority projection, and capacity observations. A setup response does
not create a mission. Private signing material is never part of this projection.

`GET /api/events?after=N` returns the version and retained events after sequence
N. Events must be contiguous. The client advances its cursor only after validating
the entire batch. A gap discards the cursor and refreshes state; it never replays
a mission operation. Responses are bounded to 16 MiB. Connection timeout is two
seconds; reads time out after five seconds.

Capacity observations come from the mission process's existing authority runtime.
The client neither opens a competing authority runtime nor calculates an allowance
from the number of rows on screen. The last retained observation remains visible
when disconnected and is labeled accordingly.

## Explicit actions

`POST /api/action` accepts tagged actions: `connect`, `initialize`, `run`, `resume`,
`approve`, and `exercise`. Initialize supplies native roles; approval supplies the
reviewed `candidate` digest. The host serializes actions. Start/resume dispatches
the existing mission runner; approval is checked against the retained exact
candidate; the exercise creates a separate reference mission.

The terminal asks for confirmation before sending a mutation. Any other key
invalidates that pending confirmation. A request is consumed from the queue before
connecting. Network errors never cause automatic retry, including after reconnect.
An accepted request means the host accepted work, not that the operation succeeded;
retained outcomes establish that distinction. Connection preparation may take up
to the action timeout of 15 minutes while keyboard input remains responsive.

## Process and restoration ownership

The plugin launches a host in a separate Unix session with null stdin and private
logs. Launch and connection locks prevent duplicate hosts for the same descriptor.
Closing a pane or stopping Herdr leaves the host running. Opening again reconnects
to it, or starts the host on the same retained mission after a host exit. Explicit
resume reconciles prior outcomes through Megastart's existing recovery contract.

Pane mappings are scoped to the Herdr socket and workspace. Repeated open reuses
a live board. After workspace restoration, the client checks the actual process;
a shell with an old pane label is not a running mission view. It opens a new board
without overwriting that shell. No startup hook dispatches work, and no generic
native resume command is registered. This was exercised with Herdr's native-agent
resume option enabled in an isolated qualification session.

## Interaction boundary

The installed restricted Hermes launcher constructs a one-shot native task and
uses a private parent-liveness channel. Its current public contract does not offer
an interactive PTY session. Allocating a terminal to an unrestricted `hermes` or
`codex` command would change the execution boundary. This release therefore
provides native activity and evidence views. Interactive input, native resize,
and native interruption remain unqualified pending launcher support.

## Install and remove

From this directory, `cargo build --release --locked` and `herdr plugin link .`
register the source package. Run `herdr plugin unlink chio.megastart` to remove
registration. Unlinking does not stop the mission host or delete its files. Mission
state and private connection files remain outside the replaceable plugin directory.
Use the descriptor's PID when deliberately administering the host. Never remove
mission storage as part of a plugin upgrade or uninstall.
