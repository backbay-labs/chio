/**
 * Failed to connect to the Chio sidecar. Mirrors chio_sdk.errors.ChioConnectionError.
 */
package world.chio.sdk.errors

class ChioConnectionError
    @JvmOverloads
    constructor(
        message: String,
        cause: Throwable? = null,
    ) : ChioError(message, "CONNECTION_ERROR", cause)
