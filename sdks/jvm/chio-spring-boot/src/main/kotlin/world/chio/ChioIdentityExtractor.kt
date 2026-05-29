/**
 * Default identity extraction from HTTP request headers.
 *
 * Mirrors the Rust extract_caller logic in chio-api-protect.
 * Extracts caller identity from Authorization headers, API keys, and cookies.
 */
package world.chio

import jakarta.servlet.http.HttpServletRequest
import world.chio.sdk.Hashing.sha256Hex

/** Function type for extracting caller identity from a request. */
typealias IdentityExtractorFn = (HttpServletRequest) -> CallerIdentity

/**
 * Default identity extractor. Checks headers in order:
 * 1. Authorization: Bearer <token>
 * 2. X-API-Key header
 * 3. Cookie header
 * 4. Anonymous fallback
 */
fun defaultIdentityExtractor(request: HttpServletRequest): CallerIdentity {
    // 1. Bearer token
    val auth = request.getHeader("Authorization")
    if (auth != null && auth.startsWith("Bearer ", ignoreCase = true)) {
        val token = auth.removePrefix("Bearer ").removePrefix("bearer ")
        val tokenHash = sha256Hex(token)
        return CallerIdentity(
            subject = "bearer:${tokenHash.take(16)}",
            authMethod = AuthMethod.bearer(tokenHash),
        )
    }

    // 2. API key
    for (keyHeader in listOf("X-API-Key", "X-Api-Key", "x-api-key")) {
        val keyValue = request.getHeader(keyHeader)
        if (keyValue != null) {
            val keyHash = sha256Hex(keyValue)
            return CallerIdentity(
                subject = "apikey:${keyHash.take(16)}",
                authMethod = AuthMethod.apiKey(keyHeader, keyHash),
            )
        }
    }

    // 3. Cookie
    val cookies = request.cookies
    if (cookies != null && cookies.isNotEmpty()) {
        val cookie = cookies[0]
        val cookieHash = sha256Hex(cookie.value)
        return CallerIdentity(
            subject = "cookie:${cookieHash.take(16)}",
            authMethod =
                AuthMethod(
                    method = "cookie",
                    cookieName = cookie.name,
                    cookieHash = cookieHash,
                ),
        )
    }

    // 4. Anonymous
    return CallerIdentity.anonymous()
}
