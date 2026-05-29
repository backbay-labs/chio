/**
 * Default parameters extractor returning
 * {request_id, subject, body_length, body_hash}. Mirrors the Python
 * _default_parameters_extractor.
 */
package world.chio.flink

import world.chio.sdk.Hashing

object DefaultParametersExtractor {
    @JvmStatic
    fun extract(
        element: Any?,
        requestId: String,
        subject: String,
    ): Map<String, Any?> {
        val body = BodyCoercion.canonicalBodyBytes(element)
        return linkedMapOf(
            "request_id" to requestId,
            "subject" to subject,
            "body_length" to body.size.toLong(),
            "body_hash" to Hashing.hashBody(body),
        )
    }
}
