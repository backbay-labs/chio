/**
 * Structured Chio deny error. Mirrors chio_sdk.errors.ChioDeniedError.
 *
 * Preserves all 11 optional fields plus fromWire/toWire helpers that
 * accept and emit the same payload shape Python emits.
 */
package world.chio.sdk.errors

import com.fasterxml.jackson.databind.JsonNode

class ChioDeniedError
    @JvmOverloads
    constructor(
        message: String,
        val guard: String? = null,
        val reason: String? = null,
        val toolName: String? = null,
        val toolServer: String? = null,
        val requestedAction: String? = null,
        val requiredScope: String? = null,
        val grantedScope: String? = null,
        val reasonCode: String? = null,
        val receiptId: String? = null,
        val hint: String? = null,
        val docsUrl: String? = null,
    ) : ChioError(message, "DENIED") {
        /** Return a JSON-serializable map of all populated fields. */
        fun toWire(): Map<String, Any?> {
            val payload =
                linkedMapOf<String, Any?>(
                    "code" to code,
                    "message" to message,
                )
            val fields =
                linkedMapOf<String, Any?>(
                    "tool_name" to toolName,
                    "tool_server" to toolServer,
                    "requested_action" to requestedAction,
                    "required_scope" to requiredScope,
                    "granted_scope" to grantedScope,
                    "guard" to guard,
                    "reason" to reason,
                    "reason_code" to reasonCode,
                    "receipt_id" to receiptId,
                    "hint" to hint,
                    "docs_url" to docsUrl,
                )
            for ((key, value) in fields) {
                if (value != null) {
                    payload[key] = value
                }
            }
            return payload
        }

        companion object {
            @JvmStatic
            fun fromWire(data: Map<String, Any?>): ChioDeniedError {
                val msg =
                    (data["message"] as? String)
                        ?: (data["reason"] as? String)
                        ?: "denied"
                return ChioDeniedError(
                    msg,
                    guard = data["guard"] as? String,
                    reason = data["reason"] as? String,
                    toolName = data["tool_name"] as? String,
                    toolServer = data["tool_server"] as? String,
                    requestedAction = data["requested_action"] as? String,
                    requiredScope = data["required_scope"] as? String,
                    grantedScope = data["granted_scope"] as? String,
                    reasonCode = data["reason_code"] as? String,
                    receiptId = data["receipt_id"] as? String,
                    hint = (data["hint"] as? String) ?: (data["suggested_fix"] as? String),
                    docsUrl = data["docs_url"] as? String,
                )
            }

            @JvmStatic
            fun fromWire(node: JsonNode): ChioDeniedError {
                fun txt(k: String): String? = node.get(k)?.takeIf { it.isTextual }?.asText()
                val msg = txt("message") ?: txt("reason") ?: "denied"
                return ChioDeniedError(
                    msg,
                    guard = txt("guard"),
                    reason = txt("reason"),
                    toolName = txt("tool_name"),
                    toolServer = txt("tool_server"),
                    requestedAction = txt("requested_action"),
                    requiredScope = txt("required_scope"),
                    grantedScope = txt("granted_scope"),
                    reasonCode = txt("reason_code"),
                    receiptId = txt("receipt_id"),
                    hint = txt("hint") ?: txt("suggested_fix"),
                    docsUrl = txt("docs_url"),
                )
            }
        }
    }
