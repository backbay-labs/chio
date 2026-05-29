/**
 * Transport-agnostic Chio client SDK for the JVM.
 *
 * Mirrors the Python `chio-sdk` package: typed HTTP client, canonical
 * JSON, signed-receipt primitives, DLQ envelope builders, and the
 * pure-Kotlin error hierarchy used by every JVM middleware.
 *
 * Public entry points:
 *
 * - [world.chio.sdk.ChioClient] - blocking sidecar client
 *   implementing [world.chio.sdk.ChioClientLike] and
 *   [java.lang.AutoCloseable].
 * - [world.chio.sdk.CanonicalJson] - Jackson canonicalizer
 *   byte-compatible with Python's `json.dumps(sort_keys=True,
 *   separators=(",", ":"), ensure_ascii=True)`.
 * - [world.chio.sdk.ChioReceipt] / [world.chio.sdk.Decision] -
 *   the signed-receipt object graph.
 * - [world.chio.sdk.SyntheticDenyReceipt] - fail-closed synthetic
 *   receipt carrying the `chio-streaming/synthetic-deny/v1` marker.
 * - [world.chio.sdk.DlqRouter] /
 *   [world.chio.sdk.ReceiptEnvelope] - canonical wire envelopes.
 * - [world.chio.sdk.errors] - the structured error hierarchy.
 *
 * Wire-level parity with the Python reference is non-negotiable and is
 * asserted by tests tagged `parity`.
 */
package world.chio.sdk

/** Package summary marker; see KDoc on the [world.chio.sdk] package for details. */
@Suppress("unused")
internal const val PACKAGE_DOC_ANCHOR: String = "world.chio.sdk"
