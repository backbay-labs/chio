package example.hello

import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class HelloController {
    @GetMapping("/healthz")
    fun healthz(): Map<String, String> = mapOf("status" to "ok")

    @GetMapping("/hello")
    fun hello(): Map<String, String> = mapOf("message" to "hello from spring-boot")

    @PostMapping("/echo", consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun echo(@RequestBody payload: Any?): EchoResponse = parseEchoPayload(payload)

    @ExceptionHandler(EchoPayloadError::class)
    fun echoPayloadError(error: EchoPayloadError): ResponseEntity<Map<String, String>> =
        ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(mapOf("error" to (error.message ?: "invalid echo payload")))
}

data class EchoResponse(
    val message: String,
    val count: Int,
)

class EchoPayloadError(message: String) : RuntimeException(message)

internal fun parseEchoPayload(payload: Any?): EchoResponse {
    if (payload !is Map<*, *>) {
        throw EchoPayloadError("body must be a JSON object")
    }

    val allowedKeys = setOf("message", "count")
    val extraKeys =
        payload.keys
            .map { it.toString() }
            .filter { it !in allowedKeys }
            .sorted()
    if (extraKeys.isNotEmpty()) {
        throw EchoPayloadError("unexpected fields: ${extraKeys.joinToString(", ")}")
    }

    val message = payload["message"]
    if (message !is String || message.isEmpty()) {
        throw EchoPayloadError("message must be a non-empty string")
    }

    val count = payload["count"] ?: 1
    if (count !is Int || count < 1) {
        throw EchoPayloadError("count must be an integer greater than or equal to 1")
    }

    return EchoResponse(
        message = message,
        count = count,
    )
}
