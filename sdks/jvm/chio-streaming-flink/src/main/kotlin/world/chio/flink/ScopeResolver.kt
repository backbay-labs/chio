/**
 * Resolve the Chio tool_name for a subject. Mirrors
 * chio_streaming.core.resolve_scope. Explicit map hit wins over the
 * default prefix fallback; empty subject throws ChioValidationError.
 */
package world.chio.flink

import world.chio.sdk.errors.ChioValidationError

object ScopeResolver {
    @JvmOverloads
    @JvmStatic
    fun resolve(
        scopeMap: Map<String, String>,
        subject: String,
        defaultPrefix: String = "events:consume",
    ): String {
        if (subject.isEmpty()) {
            throw ChioValidationError(
                "consumed message has no subject/topic; Chio evaluation requires one",
            )
        }
        val mapped = scopeMap[subject]
        if (!mapped.isNullOrEmpty()) return mapped
        return "$defaultPrefix:$subject"
    }
}
