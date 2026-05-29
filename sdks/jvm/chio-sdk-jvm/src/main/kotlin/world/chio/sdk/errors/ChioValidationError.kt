/**
 * Local validation failed before contacting the sidecar.
 * Mirrors chio_sdk.errors.ChioValidationError.
 */
package world.chio.sdk.errors

class ChioValidationError(
    message: String,
) : ChioError(message, "VALIDATION_ERROR")
