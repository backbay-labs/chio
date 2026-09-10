# Cooperative

Run this chapter application from the Agentic OS workspace:

```sh
cargo run --locked -p chio-cooperative
```

Open the printed localhost address. Change the form input, run the application, and inspect the returned result and original receipt data. The interface also exports a JSON run and can reconnect to unfinished work.

The source in `src/` contains this application's handlers and decisions. Shared initialization and the local interface are in `../shared`. Read the [suite instructions](../README.md) for prerequisites, model configuration, retained state, and extension conventions.

```sh
cargo test --locked -p chio-cooperative
```

Stop the local server with Ctrl-C. Keep `runs/` when you need its operation records or a pending publication decision. A process interruption can leave uncertain work; inspect the recorded effect before scheduling another attempt.
