# Build an Agentic OS with Chio

These applications show a Rust kernel governing useful agent work: delegated document analysis, report production, cited retrieval, adaptive research, repository repair, independent network services, incident response, joint computation, verified repair purchases, and recovery after process failure.

Each application implements the same small `Application` interface. Its no-argument entrypoint opens a local web interface. Input fields, results, events, original kernel receipts, and run downloads all come from that application's execution. Model generation is optional for the first exploration.

## Start an application

From this directory:

```sh
cargo run --locked -p chio-mission-host
```

Open the localhost address printed by the program. Change the document and run the mission. The command has no trust-fixture setup. Each run initializes its own scoped authority and retains keys and accounting in its private run directory.

The chapter downloads select a default application, so their entrypoint is `cargo run --locked`. A prebuilt Linux executable provides the same application without a native source build. The download's README identifies its exact version and prerequisites.

| Application | What it produces |
| --- | --- |
| `mission-host` | Joined document analysis or an answer produced through scoped retrieval |
| `worker-fleet` | Reports submitted by separate workers through one retained authority |
| `knowledge-network` | Permitted source passages and an optional answer with exact citations |
| `research-swarm` | An investigation report, admitted observations, and measured scheduling outcomes |
| `software-factory` | A newly generated or explicitly supplied patch, tests, review, and candidate approval |
| `personal-network` | Governed remote retrieval and computation, plus Iroh observation delivery |
| `incident-response` | A provider-approved repair and an independent service health check |
| `cooperative` | Bilateral computation or a registered 2-of-3 FROST local-credit settlement |
| `cognition-marketplace` | A venue-replayed repair purchased and applied to a separate customer project |
| `operations` | Retained outcomes at named worker, host, cancellation, expiry, and connectivity failures |
| `suite` | A composed research-to-repair mission using the same chapter implementations |

## Native runtime

The complete suite's qualification profile is Linux x86_64 with Rust 1.94.1, Python 3, Git, Bubblewrap, and cgroup v2. A source build also needs a C/C++ toolchain, OpenSSL development headers, Clang, CMake, pkg-config, and protoc. Application dependencies are locked. Native source builds can take several minutes; use the prebuilt download for the first run.

Factory tests run with network access disabled and read-only project and system files. The marketplace additionally requires a writable delegated cgroup subtree and namespace support. Its Linux profile creates those boundaries before accepting seller work. A generic container does not establish this profile by itself.

`personal-network` starts three separate local processes. Its Iroh lane delivers signed observations; passport-authenticated HTTP dispatches the governed tools. The two-machine profile uses HTTPS dispatch and Iroh's relay. Transport connectivity does not grant tool authority.

## Model workers

Set `OPENROUTER_API_KEY` on the application host and select model mode in the interface. `OPENAI_API_KEY` and Vercel AI Gateway credentials are also supported. `CHIO_MODEL` selects a compatible tool-calling model; the qualified profile is `openai/gpt-4.1-mini` through OpenRouter. Credentials stay on the host and are not entered in the docs page.

The model loop has at most six turns, eight proposed calls per turn, a 160 KB context bound, and an 1800-token response bound. Every proposed repository or retrieval operation passes through its worker's Chio capability. Model output still needs application checks: citation validation, immutable tests, candidate review, and approval where applicable.

## Own inputs and retained state

Edit the local form, or put the same object in `input.json` and run the application with `--run input.json`. A completed command prints the retained run. `--capture RUN_ID` reads and checks an existing record without repeating execution. `--describe` returns the application's input example.

`CHIO_RUNS` selects the run directory. Keep that directory to inspect receipts, reconcile effects, or decide a factory candidate. Keys and generated service credentials are local state and must not be included in a shared run bundle. The JSON export contains observations and public evidence, not the private credential files.

For a local knowledge directory, set `CHIO_CORPUS_DIR`. For a Python repository, set `CHIO_FACTORY_WORKSPACE` to a directory containing `chio-factory.json`, top-level editable Python files, and a separate immutable unittest file. The example project includes the same layout.

## Verify and extend

```sh
cargo test --locked --workspace
```

The checks exercise handler effects, receipt association, retained budgets, process death, directory removal, candidate identity, observations, member refusal, private DKG recipient separation, and repeated purchases. Product-level graph admission and federation checks live with the corresponding Chio crates.

Start an extension at the effect owner: add the tool's handler, narrow its grant, define the returned evidence, and test a denied call for the absence of an effect. Keep scheduling and business decisions visible in the application's own source. The shared directory provides host initialization, run records, local HTTP transport, and model requests; it does not supply an invisible agent framework.
