/**
 * Sidecar failure behaviour for Chio Flink operators. Mirrors the
 * Python Literal["raise", "deny"].
 *
 * RAISE: propagate sidecar unavailability so Flink restarts the task
 *        and the source rewinds.
 * DENY:  synthesise a deny receipt, emit to DLQ, continue processing.
 */
package world.chio.flink

enum class SidecarErrorBehaviour { RAISE, DENY }
