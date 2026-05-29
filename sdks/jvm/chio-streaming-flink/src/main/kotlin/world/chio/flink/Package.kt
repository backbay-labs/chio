/**
 * Apache Flink operators that gate a DataStream through a Chio
 * capability. Mirrors `chio_streaming.flink` in Python.
 *
 * Public entry points:
 *
 * - [world.chio.flink.ChioAsyncEvaluateFunction] - primary async
 *   operator. Driven by `AsyncDataStream.unorderedWait(capacity=...)`.
 * - [world.chio.flink.ChioEvaluateFunction] - synchronous
 *   `ProcessFunction` variant for side-output-on-same-operator use.
 * - [world.chio.flink.ChioVerdictSplitFunction] - fans
 *   `EvaluationResult` into main + `chio-receipt` + `chio-dlq` side
 *   outputs. Tag names are the wire-stable
 *   [world.chio.flink.ChioOutputTags] constants.
 * - [world.chio.flink.ChioFlinkConfig] - serializable,
 *   builder-based configuration. Client and DLQ router are supplied
 *   as [world.chio.flink.SerializableSupplier] factories.
 * - [world.chio.flink.SidecarErrorBehaviour] - RAISE (let Flink
 *   restart on sidecar error) vs DENY (synthesise a deny receipt and
 *   keep flowing).
 *
 * This module does not drive transactions; pair with Flink's 2PC sinks
 * downstream. Flink version requirement: 2.2+.
 */
package world.chio.flink

/** Package summary marker; see KDoc on the [world.chio.flink] package for details. */
@Suppress("unused")
internal const val PACKAGE_DOC_ANCHOR: String = "world.chio.flink"
