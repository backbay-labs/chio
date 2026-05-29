package world.chio.flink

import org.junit.jupiter.api.Test
import world.chio.sdk.errors.ChioValidationError
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SlotsTest {
    @Test
    fun limitMustBePositive() {
        assertFailsWith<ChioValidationError> { Slots(0) }
    }

    @Test
    fun extraReleasesDoNotGrowPermits() {
        val slots = Slots(2)
        slots.acquire()
        slots.acquire()
        // Two extra releases beyond what was acquired; permits must stay capped at 2.
        slots.release()
        slots.release()
        slots.release()
        slots.release()
        assertEquals(0, slots.inFlight)

        // Acquiring again must still be bounded by limit=2: a third concurrent
        // acquire should block, not steal a phantom permit produced by the extras above.
        slots.acquire()
        slots.acquire()
        assertEquals(2, slots.inFlight)

        val executor = Executors.newSingleThreadExecutor()
        try {
            val started = CountDownLatch(1)
            val acquired = CountDownLatch(1)
            executor.submit {
                started.countDown()
                slots.acquire()
                acquired.countDown()
            }
            assertTrue(started.await(1, TimeUnit.SECONDS))
            assertFalse(
                acquired.await(200, TimeUnit.MILLISECONDS),
                "third acquire must block while limit=2 is held",
            )
            slots.release()
            assertTrue(acquired.await(1, TimeUnit.SECONDS))
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun concurrentExtraReleasesAreAtomic() {
        // Without atomic check-and-decrement, multiple threads racing release()
        // when inFlight is exactly 1 could both observe >0 and both call
        // sem.release(), leaving permits above limit. Drive that race here.
        val slots = Slots(1)
        slots.acquire()
        val pool = Executors.newFixedThreadPool(8)
        try {
            val start = CountDownLatch(1)
            val done = CountDownLatch(8)
            repeat(8) {
                pool.submit {
                    start.await()
                    slots.release()
                    done.countDown()
                }
            }
            start.countDown()
            assertTrue(done.await(2, TimeUnit.SECONDS))
        } finally {
            pool.shutdownNow()
        }
        assertEquals(0, slots.inFlight)
        // Permits must still be capped: acquire then immediate try-acquire from
        // another thread should block.
        slots.acquire()
        assertEquals(1, slots.inFlight)
    }
}
