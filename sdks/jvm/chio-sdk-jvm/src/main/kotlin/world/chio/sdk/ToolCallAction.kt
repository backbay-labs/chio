/**
 * Action block inside a ChioReceipt. Mirrors
 * chio_sdk.models.ToolCallAction (models.py).
 */
package world.chio.sdk

import com.fasterxml.jackson.annotation.JsonProperty
import java.io.Serializable

data class ToolCallAction(
    @JsonProperty("parameters") val parameters: Map<String, Any?> = emptyMap(),
    @JsonProperty("parameter_hash") val parameterHash: String,
) : Serializable {
    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
