/**
 * Bounded semaphore + in-flight gauge. Mirrors chio_streaming.core.Slots.
 * Uses java.util.concurrent.Semaphore directly; no asyncio loop-binding
 * concern on the JVM.
 */
package world.chio.flink

import world.chio.sdk.errors.ChioValidationError
import java.io.Serializable
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicInteger

class Slots(
    private val limit: Int,
) : Serializable {
    init {
        if (limit < 1) {
            throw ChioValidationError("Slots(limit) must be >= 1")
        }
    }

    @Transient
    private var semRef: Semaphore? = null

    @Transient
    private var inFlightRef: AtomicInteger? = null

    private fun sem(): Semaphore {
        val current = semRef
        if (current != null) return current
        synchronized(this) {
            val again = semRef
            if (again != null) return again
            val created = Semaphore(limit, true)
            semRef = created
            return created
        }
    }

    private fun inFlightAtomic(): AtomicInteger {
        val current = inFlightRef
        if (current != null) return current
        synchronized(this) {
            val again = inFlightRef
            if (again != null) return again
            val created = AtomicInteger(0)
            inFlightRef = created
            return created
        }
    }

    val inFlight: Int
        get() = inFlightRef?.get() ?: 0

    /** Blocking acquire. Throws InterruptedException. */
    @Throws(InterruptedException::class)
    fun acquire() {
        sem().acquire()
        inFlightAtomic().incrementAndGet()
    }

    fun release() {
        // Match Python's "extra releases are ignored so drain paths stay simple" semantic.
        // The check + decrement must be atomic; otherwise two concurrent extra releases
        // can both observe >0, both decrement, and both release the semaphore, growing
        // permits past `limit`.
        val inFlightCounter = inFlightRef ?: return
        val prev = inFlightCounter.getAndUpdate { if (it > 0) it - 1 else it }
        if (prev > 0) {
            semRef?.release()
        }
    }

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
