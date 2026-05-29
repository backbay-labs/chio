/**
 * String constants for sidecar endpoints. Mirrors the bare paths used
 * throughout chio_sdk/client.py.
 */
package world.chio.sdk

object SidecarPaths {
    const val DEFAULT_BASE_URL = "http://127.0.0.1:9090"
    const val HEALTH = "/chio/health"
    const val EVALUATE_HTTP = "/chio/evaluate"
    const val VERIFY_HTTP_RECEIPT = "/chio/verify"
    const val EVALUATE_TOOL_CALL = "/v1/evaluate"
    const val VERIFY_RECEIPT = "/v1/receipts/verify"
}
