# Flink Integration Review: Test Quality + Coverage

## Summary

Coverage of `flink.py`'s public surface is broad - config validation, both operators, the verdict splitter, envelope parity, and `register_dependencies` all have at least one test. The suite correctly imports `chio_streaming.flink` unconditionally (proving the "imports without PyFlink" guarantee) and reuses `chio_sdk.testing.allow_all` / `deny_all` like the other broker tests. The real `DLQRouter` is used rather than a mock, which keeps the DLQ code path honest.

However the in-process PyFlink surrogate is too loose in several load-bearing places, and a handful of production code paths are either bypassed or only lightly asserted. Chief risks: (1) the `RuntimeContext` surrogate does not enforce the method set that `_ChioFlinkEvaluator.bind` calls, so a rename in real PyFlink would not fail here; (2) `ChioAsyncEvaluateFunction.close()` is never exercised with the "event loop already running" branch that the source code dedicates multiple lines to; (3) several mandatory spec invariants (SYNTHETIC_RECEIPT_MARKER on the receipt itself, sidecar-error counter, DLQ publish-failure propagation) are not tested; (4) there are no back-pressure tests equivalent to `test_backpressure_blocks_when_max_in_flight_reached` in `test_pulsar.py`, even though the `Slots` integration is identical. The suite is a solid first cut but needs hardening before the "production-ready" claim.

## Coverage matrix

| Invariant | Covered? | Test |
|---|---|---|
| Config: empty `capability_id` | Yes | `test_config_requires_capability_id` |
| Config: empty `tool_server` | Yes | `test_config_requires_tool_server` |
| Config: `max_in_flight < 1` | Yes | `test_config_requires_positive_max_in_flight` |
| Config: invalid `on_sidecar_error` | Yes | `test_config_requires_valid_on_sidecar_error` |
| Config: missing `client_factory` | Yes | `test_config_requires_client_factory` |
| Config: missing `dlq_router_factory` | Yes | `test_config_requires_dlq_router_factory` |
| Config: empty `request_id_prefix` | Yes | `test_config_requires_non_empty_request_id_prefix` |
| Sync allow: main + RECEIPT | Yes | `test_sync_allow_yields_main_and_receipt` |
| Sync allow, no receipt_topic | Yes | `test_sync_allow_without_receipt_topic_skips_receipt` |
| Sync deny: RECEIPT + DLQ, no main | Yes | `test_sync_deny_yields_receipt_and_dlq_no_main` |
| Sync sidecar error `raise` | Yes | `test_sync_sidecar_error_raises_by_default` |
| Sync sidecar error `deny` | Yes | `test_sync_sidecar_error_fails_closed` |
| SYNTHETIC_RECEIPT_MARKER in DLQ payload | Yes (DLQ only) | `test_sync_sidecar_error_fails_closed` |
| SYNTHETIC_RECEIPT_MARKER in the receipt-envelope payload | **No** | - |
| `open`/`close` factory-called-once | Yes | `test_sync_open_and_close_drive_factories_once` |
| Client `close()` actually invoked | **No** | - |
| `process_element` before `open` raises | Yes | `test_sync_process_element_before_open_raises` |
| Default request-id prefix `chio-flink-` | Yes | `test_sync_request_id_prefix_applied` |
| Custom request-id prefix | Yes | `test_sync_custom_request_id_prefix_applied` |
| Custom subject extractor used | Yes | `test_sync_custom_subject_extractor_used` |
| Custom parameters extractor used | Yes (weakly) | `test_sync_custom_parameters_extractor_used` |
| Metrics counters registered | Yes (partial) | `test_sync_metrics_registered` |
| Metrics gracefully degrade on API shape mismatch | **No** | - |
| Async allow returns `EvaluationResult` | Yes | `test_async_allow_returns_evaluation_result` |
| Async deny returns DLQ bytes | Yes | `test_async_deny_returns_dlq_bytes` |
| Async sidecar error `deny` | Yes | `test_async_sidecar_error_fails_closed` |
| Async sidecar error `raise` | Yes | `test_async_sidecar_error_raises_by_default` |
| Async `close()` with running loop branch | **No** | - |
| Split allow: main + receipt | Yes | `test_split_allow_yields_main_and_receipt` |
| Split deny: receipt + DLQ, no main | Yes | `test_split_deny_yields_receipt_and_dlq_no_main` |
| Split allow without receipt bytes | Yes | `test_split_allow_without_receipt_bytes_yields_main_only` |
| Receipt envelope byte-exact (`build_envelope(...).value`) | Yes (sync only) | `test_receipt_bytes_match_build_envelope_exactly` |
| DLQ bytes byte-exact vs `DLQRouter.build_record(...).value` | **No** | - |
| Envelope parity for async path | **No** | - |
| `register_dependencies` no-op | Yes | `test_register_dependencies_no_args_is_noop` |
| `register_dependencies` both args | Yes | `test_register_dependencies_attaches_files_and_requirements` |
| `register_dependencies` single args | Yes | `test_register_dependencies_only_requirements`, `..._only_python_files` |
| Back-pressure / `max_in_flight` bound honored | **No** | - |
| DLQ publish-failure propagation | **No** | - |
| `scope_map` fallback vs explicit mapping | **No** (never asserts resolved tool_name) | - |
| Subtask index / attempt number captured on outcome | **No** | - |
| Shutdown signals (`SystemExit`, `KeyboardInterrupt`, `CancelledError`) propagate | **No** | - |

## Findings

### [P1] SYNTHETIC_RECEIPT_MARKER is asserted on the DLQ envelope but never on the receipt itself

File: `tests/test_flink.py:416-418` and `:591-593`.
Both synthesised-deny tests check the marker inside `dlq_bytes["receipt"]["metadata"]`, but never inside the separate receipt envelope emitted to `RECEIPT_TAG`. The spec calls for the marker to live on the receipt so downstream verifiers can reject structurally. The receipt envelope is built independently (see `flink.py:541-548`) so a regression that produced a signed-looking receipt while still routing to DLQ would not fail any test.
Fix: in `test_sync_sidecar_error_fails_closed`, also decode `receipts[0]` and assert `payload["receipt"]["metadata"]["chio_streaming_synthetic_marker"] == SYNTHETIC_RECEIPT_MARKER`. Same for the async variant.

### [P1] `ChioAsyncEvaluateFunction.close()` "running loop" branch is unreachable from the suite

File: `flink.py:662-668`; no test.
The code dedicates a branch to "PyFlink drives close() from the worker thread when the event loop is already torn down; but if called while a loop is running..." and schedules `create_task(shutdown())`. Under `pytest-asyncio`'s `asyncio_mode = auto`, `async def test_async_*` tests call `fn.close()` from a sync `finally` block which sees no running loop; the running-loop branch is dead in tests.
Fix: add `async def test_async_close_inside_running_loop_schedules_shutdown` that calls `fn.close()` inside a running event loop and asserts shutdown is scheduled without blocking. Also assert `client.close()` is eventually called via a spy `ChioClient`.

### [P1] No DLQ publish-failure test and no back-pressure test

Other broker suites mandate both invariants (see `test_pulsar.py:431-462`, `:470-532`). `ChioEvaluateFunction` uses `Slots(max_in_flight)` just like the Pulsar middleware (`flink.py:495-499`) and the DLQ path runs through the real `DLQRouter`, so these behaviours exist in production but are not exercised.
Fix: add `test_sync_backpressure_respects_max_in_flight` and `test_sync_dlq_router_failure_propagates` (inject a `DLQRouter` subclass whose `build_record` raises and assert the exception surfaces, nothing is emitted, and `Slots.in_flight` returns to 0).

### [P1] Surrogate `RuntimeContext` does not enforce the method set that production calls

File: `tests/test_flink.py:163-176`.
`MockRuntimeContext` implements `get_index_of_this_subtask`, `get_attempt_number`, `get_metrics_group`. Production swallows `Exception` around each call (`flink.py:441-452`), so a rename in PyFlink 2.2 (e.g. `getIndexOfThisSubtask`-style) would silently store `None` and the gauge would silently degrade. No test asserts "on a real RuntimeContext, `subtask_index` is populated" - meaning the fail-forensics contract (`subtask_index` / `attempt_number` present on the outcome) is never verified.
Fix: after `_run_sync` returns, assert the FlinkProcessingOutcome or receipt envelope carries the subtask index. If the outcome is not surfaced (it is currently dropped on the floor by `_run_sync`, see P2 below), fix that first.

### [P1] Sidecar-error counter never verified

File: `tests/test_flink.py:511-523` covers only `evaluations_total`, `allow_total`, `in_flight`. Production also registers `deny_total` and `sidecar_errors_total` (`flink.py:371-372`). The `deny` path and the `on_sidecar_error="deny"` synthesised-deny path both bump counters (`flink.py:528-531`, `:551-552`) but nothing asserts those bumps.
Fix: parametrize the metrics test over `(chio_client, expected_counter)` in `{(allow_all, "allow_total"), (deny_all, "deny_total"), (FailingChio + "deny", "sidecar_errors_total")}`.

### [P1] `_run_sync` discards the outcome, so the outcome-shape assertions are invisible

File: `tests/test_flink.py:346-361`.
`_run_sync` returns `(main, receipts, dlq, None)` - the fourth slot is hard-coded `None`. Production builds a fully populated `FlinkProcessingOutcome` with `element`, `subtask_index`, `attempt_number`, `receipt_bytes`, `dlq_bytes`, `dlq_record` (see `flink.py:561-582`), but the sync operator yields bytes only; the outcome is never surfaced. So spec items "subtask_index captured", "attempt_number captured", and "FlinkProcessingOutcome shape" are untested.
Fix: either expose the last outcome via a hook (`ChioEvaluateFunction._last_outcome`) and assert on it in tests, or add a unit test that drives `_ChioFlinkEvaluator.evaluate` directly (since it is not a PyFlink type it is test-friendly) and verifies the full outcome shape.

### [P2] Parametrization is missing where it would obviously apply

`on_sidecar_error` is tested twice for sync (`..._raises_by_default`, `..._fails_closed`) and twice for async (`..._raises_by_default`, `..._fails_closed`) with near-duplicate bodies. Similarly, the default-prefix and custom-prefix request-id tests share ~10 lines of setup.
Fix: `@pytest.mark.parametrize("on_error,expect_raise", [("raise", True), ("deny", False)])` and run against both sync and async in a single helper. Parametrize `test_sync_request_id_prefix_applied` over the prefix instead of forking.

### [P2] Envelope byte-parity covers only the sync allow path

File: `tests/test_flink.py:665-689`.
The test proves `receipts[0] == build_envelope(...).value` for sync allow. The async path builds its receipt bytes in `_ChioFlinkEvaluator.evaluate` too, so byte parity should hold there; a mismatch would break cross-source receipt consumers. There is also no equivalent check that `dlq_bytes == DLQRouter.build_record(...).value`.
Fix: add `test_async_receipt_bytes_match_build_envelope` and `test_sync_dlq_bytes_match_dlq_router_build_record`.

### [P2] `test_sync_custom_parameters_extractor_used` does not actually verify the override reached the sidecar

File: `tests/test_flink.py:497-508`.
The test only asserts the main element and a receipt emitted. It never spies on the parameters passed to `chio_client.evaluate_tool_call`, so a bug where `_parameters_for` discarded the custom extractor would still pass.
Fix: replace `allow_all()` with a tiny spy client that records `parameters`, and assert `parameters["custom"] is True` and `parameters["request_id"]` / `parameters["subject"]` were added by the operator.

### [P2] `FailingChio` drifts from the pulsar/pubsub convention

File: `tests/test_flink.py:197-199`. The other broker suites raise `ChioConnectionError`, which `evaluate_with_chio` wraps in `ChioStreamingError`. `FailingChio` here also raises `ChioConnectionError`, but each broker suite re-declares the class inside the test body. Lifting it to a shared fixture would remove duplication and ensure all three broker suites fail in lockstep if the error-mapping contract changes. Not strictly a bug - flag as style.

### [P2] `_install_pyflink_surrogate` runs at import time and mutates `sys.modules`

Surrogate installation has no teardown. If a later test file imports `chio_streaming.flink` it will bind to the surrogate, not the real PyFlink (if installed). On CI without PyFlink this is fine; on a dev box with PyFlink installed, test ordering matters. Also the surrogate's `AsyncFunction.async_invoke` returns a coroutine returning `list`, but nothing prevents a subtle bug where the real PyFlink expects a `Collector` / `ResultFuture` shape (per FLINK-38560) - the research doc explicitly calls out `async_invoke(self, value) -> list` for 2.2, so the surrogate is correct for this version, but it would silently pass tests aimed at a pre-2.2 `ResultFuture` API.
Fix: add a `pytest` session-scoped autouse fixture that restores `sys.modules["pyflink"]` on teardown; add a docstring note that the surrogate only models the 2.2+ shape.

### [P2] Shutdown-signal test missing

File: the Pulsar suite has `test_handler_shutdown_signals_propagate` parametrized over `(SystemExit, KeyboardInterrupt, asyncio.CancelledError)`. The Flink operator also wraps sidecar calls in `try/except ChioStreamingError` (which is `Exception`-derived); there is no explicit test that shutdown signals escape intact. Because production only catches `ChioStreamingError` this is probably fine, but an explicit test would lock in the behaviour.

### [P3] Assertion specificity

- `tests/test_flink.py:389-391` decodes the DLQ payload and asserts `verdict == "deny"` and `reason == "missing scope"` - good. But the paired allow test (`:364-369`) only asserts `len(receipts) == 1`; strengthen to `json.loads(receipts[0])["verdict"] == "allow"`.
- `tests/test_flink.py:540-547` asserts `result.receipt_bytes is not None` - should also assert bytes start with `{` and are parseable JSON, mirroring the sync test style.
- `test_sync_metrics_registered` asserts `"in_flight" in rc.metrics.gauges` but never calls the gauge. Call `rc.metrics.gauges["in_flight"]()` and assert it returns `0` post-drain to prove the `Slots` wiring.

### [P3] DRY opportunities

- The `import json as _json` dance is repeated 7 times. Move `json` to the top of the file (it is also standard-library-only; no lint concern).
- `_run_sync` is sync-only; a companion `_run_async` helper would cut 8 lines of open/close boilerplate out of each async test.
- `MockProcessContext.timestamp()` is defined but never asserted on. Remove it or add a test asserting the operator does not rely on it (current production does not call `ctx.timestamp()`, and that absence is actually load-bearing because `AsyncFunction` has no ctx at all).

### [P3] `FakeEnv` lives in the test file but is not reused

`register_dependencies` tests use `FakeEnv` with four methods/attributes. Fine in scope, but if other modules add a helper for PyFlink `StreamExecutionEnvironment` fakes later, keep them colocated.

## Production code paths exercised vs bypassed

- Sync `process_element` -> `_evaluator.evaluate` -> sidecar -> envelope -> generator yield: **exercised** via `_run_sync`.
- Async `async_invoke` -> `_evaluator.evaluate`: **exercised** directly - not a bypass; `async_invoke` is the real public entry.
- `ChioVerdictSplitFunction.process_element`: **exercised** with synthetic `EvaluationResult`s (correct - the split function is pure).
- `_receipt_tag()` / `_dlq_tag()` helpers: **exercised** through `_split_outputs`.
- `_maybe_close` on async clients: **not exercised** (no spy `close`).
- `_register_metrics` exception fallback: **not exercised** - the graceful-degrade branch needs a `MetricsGroup` whose `.counter(name)` raises.
- `ChioAsyncEvaluateFunction.close()` running-loop branch: **not exercised** (see P1).
- `_default_subject_extractor` bytes/None/unusual ctx shapes: only the happy `ctx.topic()` path is tested.

## Recommended additions (priority order)

1. Assert SYNTHETIC_RECEIPT_MARKER on the receipt envelope, not just the DLQ payload.
2. Add a back-pressure test using `max_in_flight=1` and a slow async sidecar, mirroring `test_pulsar.py:431-462`.
3. Add a DLQ-router failure test asserting propagation + no partial emission + `Slots` returns to 0.
4. Add `test_async_close_inside_running_loop_schedules_shutdown` and a client-close spy.
5. Add assertions that `evaluations_total`, `deny_total`, `sidecar_errors_total` counters increment.
6. Surface `FlinkProcessingOutcome` (or drive `_ChioFlinkEvaluator` directly) and assert `subtask_index`, `attempt_number`, and `dlq_record` shape.
7. Add an async envelope-parity test and a DLQ byte-parity test.
8. Parametrize the `on_sidecar_error` pair and the request-id prefix pair.
9. Add a session-scoped teardown that removes the surrogate from `sys.modules`.

Relevant paths:
- `sdks/python/chio-streaming/tests/test_flink.py`
- `sdks/python/chio-streaming/src/chio_streaming/flink.py`
- `sdks/python/chio-streaming/tests/test_pulsar.py` (reference patterns)
- `docs/research/chio-streaming-flink-integration.md` (spec)
