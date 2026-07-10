/**
 * Tool-call verdict (allow / deny / cancelled / incomplete). Mirrors
 * chio_sdk.models.Decision (models.py).
 */
package world.chio.sdk

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import java.io.Serializable

@JsonInclude(JsonInclude.Include.NON_NULL)
data class Decision(
    @JsonProperty("verdict") val verdict: String,
    @JsonProperty("reason") val reason: String? = null,
    @JsonProperty("guard") val guard: String? = null,
) : Serializable {
    @JsonIgnore
    fun isAllowed(): Boolean = verdict == "allow"

    @JsonIgnore
    fun isDenied(): Boolean = verdict == "deny"

    companion object {
        private const val serialVersionUID: Long = 1L

        @JvmStatic
        fun allow(): Decision = Decision(verdict = "allow")

        @JvmStatic
        fun deny(
            reason: String,
            guard: String,
        ): Decision = Decision(verdict = "deny", reason = reason, guard = guard)

        @JvmStatic
        fun cancelled(reason: String): Decision = Decision(verdict = "cancelled", reason = reason)

        @JvmStatic
        fun incomplete(reason: String): Decision = Decision(verdict = "incomplete", reason = reason)
    }
}
