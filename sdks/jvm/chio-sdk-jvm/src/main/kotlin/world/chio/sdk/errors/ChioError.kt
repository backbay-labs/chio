/**
 * Base Chio SDK exception. Mirrors chio_sdk.errors.ChioError.
 */
package world.chio.sdk.errors

/** Base error for all Chio SDK operations. */
open class ChioError
    @JvmOverloads
    constructor(
        message: String,
        val code: String? = null,
        cause: Throwable? = null,
    ) : RuntimeException(message, cause)
