/**
 * Signed tool-call receipt. Mirrors chio_sdk.models.ChioReceipt
 * (models.py). Implements Serializable because it travels
 * inside EvaluationResult / FlinkProcessingOutcome which Flink
 * serialises across operator boundaries.
 */
package world.chio.sdk

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import java.io.Serializable

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ChioReceipt(
    @JsonProperty("id") val id: String,
    @JsonProperty("timestamp") val timestamp: Long,
    @JsonProperty("capability_id") val capabilityId: String,
    @JsonProperty("tool_server") val toolServer: String,
    @JsonProperty("tool_name") val toolName: String,
    @JsonProperty("action") val action: ToolCallAction,
    @JsonProperty("decision") val decision: Decision? = null,
    @JsonProperty("receipt_kind") val receiptKind: String? = null,
    @JsonProperty("boundary_class") val boundaryClass: String? = null,
    @JsonProperty("observation_outcome") val observationOutcome: String? = null,
    @JsonProperty("tool_origin") val toolOrigin: String? = null,
    @JsonProperty("redaction_mode") val redactionMode: String? = null,
    @JsonProperty("actor_chain") val actorChain: List<Map<String, Any?>> = emptyList(),
    @JsonProperty("content_hash") val contentHash: String,
    @JsonProperty("policy_hash") val policyHash: String,
    @JsonProperty("evidence") val evidence: List<GuardEvidence> = emptyList(),
    @JsonProperty("metadata") val metadata: Map<String, Any?>? = null,
    @JsonProperty("trust_level") val trustLevel: String? = null,
    @JsonProperty("tenant_id") val tenantId: String? = null,
    @JsonProperty("kernel_key") val kernelKey: String,
    @JsonProperty("signature") val signature: String,
) : Serializable {
    @JsonIgnore
    fun isAllowed(): Boolean =
        receiptKind == "mediated_decision" &&
            boundaryClass == "prevent" &&
            trustLevel == "mediated" &&
            observationOutcome == null &&
            decision?.isAllowed() == true

    @JsonIgnore
    fun isDenied(): Boolean = decision?.isDenied() == true

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
