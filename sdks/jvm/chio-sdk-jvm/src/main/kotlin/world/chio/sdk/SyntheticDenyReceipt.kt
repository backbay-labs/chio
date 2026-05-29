/**
 * Synthetic deny receipt builder for the fail-closed path when the
 * sidecar is unreachable. Mirrors chio_streaming.core.synthesize_deny_receipt.
 *
 * Invariants:
 * - Reason is prefixed "[unsigned] " unless already prefixed (idempotent).
 * - kernelKey = "", signature = "".
 * - metadata carries chio_streaming_synthetic: true plus the marker.
 * - parameterHash = SHA-256 hex of canonical JSON of parameters.
 * - contentHash = parameterHash.
 * - policyHash = "".
 * - evidence = [].
 */
package world.chio.sdk

import java.util.UUID

object SyntheticDenyReceipt {
    /** Marker string written into receipt.metadata for synthetic denies. */
    const val MARKER: String = "chio-streaming/synthetic-deny/v1"

    private const val UNSIGNED_PREFIX: String = "[unsigned] "

    @JvmStatic
    @JvmOverloads
    fun synthesize(
        capabilityId: String,
        toolServer: String,
        toolName: String,
        parameters: Map<String, Any?>,
        reason: String,
        guard: String,
        clock: () -> Long = { System.currentTimeMillis() / 1000L },
        idSupplier: () -> String = {
            "chio-streaming-synth-" +
                UUID
                    .randomUUID()
                    .toString()
                    .replace("-", "")
                    .take(10)
        },
    ): ChioReceipt {
        val canonical = CanonicalJson.writeBytes(parameters)
        val paramHash = Hashing.sha256Hex(canonical)
        val annotated = if (reason.startsWith(UNSIGNED_PREFIX)) reason else UNSIGNED_PREFIX + reason
        return ChioReceipt(
            id = idSupplier(),
            timestamp = clock(),
            capabilityId = capabilityId,
            toolServer = toolServer,
            toolName = toolName,
            action =
                ToolCallAction(
                    parameters = LinkedHashMap(parameters),
                    parameterHash = paramHash,
                ),
            decision = Decision.deny(reason = annotated, guard = guard),
            contentHash = paramHash,
            policyHash = "",
            evidence = emptyList(),
            metadata =
                mapOf(
                    "chio_streaming_synthetic" to true,
                    "chio_streaming_synthetic_marker" to MARKER,
                ),
            kernelKey = "",
            signature = "",
        )
    }
}
