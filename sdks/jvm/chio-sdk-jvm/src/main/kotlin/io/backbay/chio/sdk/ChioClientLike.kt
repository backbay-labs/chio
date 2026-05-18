/**
 * The sidecar surface the Flink operator calls. ChioClient implements
 * this; test doubles can too without an HttpServer. Mirrors the Python
 * chio_streaming.core.ChioClientLike Protocol.
 */
package io.backbay.chio.sdk

interface ChioClientLike {
    fun evaluateToolCall(
        capabilityId: String,
        toolServer: String,
        toolName: String,
        parameters: Map<String, Any?>,
    ): ChioReceipt

    fun verifyReceipt(receipt: ChioReceipt): Boolean = false
}
