# Example host runtime

Shared implementation for the downloadable Rust reference applications. This
library owns host resources; Chio still performs authority and policy evaluation.

- `TaskGroup` owns jobs through finalization, rejects work after close, and joins
  or aborts outstanding tasks at a shutdown deadline. Forced shutdown is an error.
- `OwnedTask` aborts its child when its supervisor is dropped, preventing a
  cancelled supervisor from detaching active work.
- `BlockingPool` refuses overload immediately and keeps its permit inside the
  blocking closure. Dropping an HTTP request does not release active capacity.
- `files` publishes complete immutable artifacts without overwriting a competing
  writer, replaces snapshots atomically, bounds reads on the opened handle, and
  synchronizes files and containing directories on Unix.
- `credential_matches` uses SHA-256 digest bytes and Subtle's comparison primitive.

Use application-owned directories. These helpers do not secure ancestor paths
against another principal replacing a directory. File publication on non-Unix targets has no directory-durability claim.
Directory publication with no replacement requires Linux, macOS or iOS and
returns an explicit unsupported error on other targets. A file publication error after
rename/link may follow a real effect; reconcile the destination before retrying.
A hard process crash can leave `.chio-write-*` staging files, which are never
considered published artifacts. Remove them only while the application is stopped.

Run `cargo test` and `cargo clippy --all-targets -- -D warnings`.
The docs packager includes an exact copy in each application that uses it; edit
this canonical directory and run the example sync command, rather than editing
its generated copies.
