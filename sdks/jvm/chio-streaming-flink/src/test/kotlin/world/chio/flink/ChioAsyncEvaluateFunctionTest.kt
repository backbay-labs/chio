package world.chio.flink

import org.apache.flink.api.common.functions.OpenContext
import org.apache.flink.streaming.api.functions.async.CollectionSupplier
import org.apache.flink.streaming.api.functions.async.ResultFuture
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import world.chio.flink.support.FakeChioClient
import world.chio.flink.support.FakeRuntimeContext
import world.chio.sdk.ChioClientLike
import world.chio.sdk.DlqRouter
import world.chio.sdk.errors.ChioConnectionError
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@Tag("parity")
class ChioAsyncEvaluateFunctionTest {
    private fun configFor(client: ChioClientLike): ChioFlinkConfig<Map<String, Any?>> =
        ChioFlinkConfig
            .builder<Map<String, Any?>>()
            .capabilityId("cap")
            .toolServer("srv")
            .subjectExtractor { e -> e["topic"]?.toString() ?: "t" }
            .clientFactory { client }
            .dlqRouterFactory { DlqRouter(defaultTopic = "chio-dlq") }
            .maxInFlight(2)
            .build()

    private fun setRuntimeContext(
        fn: ChioAsyncEvaluateFunction<*>,
        rc: FakeRuntimeContext,
    ) {
        val m =
            fn.javaClass.superclass.superclass
                .getDeclaredMethod("setRuntimeContext", org.apache.flink.api.common.functions.RuntimeContext::class.java)
        m.isAccessible = true
        m.invoke(fn, rc)
    }

    @Test
    fun asyncInvokeCompletesOneResultPerElement() {
        val fn = ChioAsyncEvaluateFunction(configFor(FakeChioClient()))
        setRuntimeContext(fn, FakeRuntimeContext())
        fn.open(EmptyOpenContext())
        val result = runAsync(fn, mapOf("topic" to "t"))
        assertNotNull(result)
        assertEquals(1, result!!.size)
        assertTrue(result.first().allowed)
        fn.close()
    }

    @Test
    fun closeDrainsQueuedTasksBeforeShuttingDown() {
        // close() must let the queued task complete its ResultFuture; an
        // immediate shutdownNow() would interrupt the worker and orphan the
        // future, breaking AsyncDataStream's checkpoint barriers on
        // rebalance/stop.
        val gate = CountDownLatch(1)
        val client =
            FakeChioClient(
                behaviour = FakeChioClient.Behaviour.AllowAfterGate(gate),
            )
        val fn = ChioAsyncEvaluateFunction(configFor(client))
        setRuntimeContext(fn, FakeRuntimeContext())
        fn.open(EmptyOpenContext())

        val done = CountDownLatch(1)
        val received = AtomicReference<List<EvaluationResult<Map<String, Any?>>>?>()
        val err = AtomicReference<Throwable?>()
        fn.asyncInvoke(
            mapOf("topic" to "t"),
            CollectingFuture(
                onComplete = {
                    received.set(it)
                    done.countDown()
                },
                onException = {
                    err.set(it)
                    done.countDown()
                },
            ),
        )

        // Trigger close() concurrently with the in-flight task and let it
        // proceed; orderly shutdown must wait for the worker to call
        // complete() before tearing down.
        val closer =
            Thread {
                Thread.sleep(50)
                gate.countDown()
            }
        closer.start()
        fn.close()
        closer.join()

        assertTrue(done.await(5, TimeUnit.SECONDS), "ResultFuture must be completed before close returns")
        assertNotNull(received.get(), "task should have been allowed to finish, not interrupted: err=${err.get()}")
        assertEquals(1, received.get()!!.size)
    }

    @Test
    fun asyncRaiseSidecarErrorReachesCompleteExceptionally() {
        val client =
            FakeChioClient(
                behaviour = FakeChioClient.Behaviour.Throw(ChioConnectionError("boom")),
            )
        val fn =
            ChioAsyncEvaluateFunction(
                configFor(client).let { cfg ->
                    // Override to RAISE.
                    ChioFlinkConfig
                        .builder<Map<String, Any?>>()
                        .capabilityId(cfg.capabilityId)
                        .toolServer(cfg.toolServer)
                        .subjectExtractor(cfg.subjectExtractor)
                        .clientFactory(cfg.clientFactory)
                        .dlqRouterFactory(cfg.dlqRouterFactory)
                        .onSidecarError(SidecarErrorBehaviour.RAISE)
                        .maxInFlight(cfg.maxInFlight)
                        .build()
                },
            )
        setRuntimeContext(fn, FakeRuntimeContext())
        fn.open(EmptyOpenContext())
        val done = CountDownLatch(1)
        val err = AtomicReference<Throwable?>()
        fn.asyncInvoke(
            mapOf("topic" to "t"),
            CollectingFuture(
                onComplete = { done.countDown() },
                onException = {
                    err.set(it)
                    done.countDown()
                },
            ),
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertNotNull(err.get())
        fn.close()
    }

    private fun runAsync(
        fn: ChioAsyncEvaluateFunction<Map<String, Any?>>,
        element: Map<String, Any?>,
    ): List<EvaluationResult<Map<String, Any?>>>? {
        val done = CountDownLatch(1)
        val received = AtomicReference<List<EvaluationResult<Map<String, Any?>>>?>()
        fn.asyncInvoke(
            element,
            CollectingFuture(
                onComplete = {
                    received.set(it)
                    done.countDown()
                },
                onException = { done.countDown() },
            ),
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))
        return received.get()
    }

    private class CollectingFuture<T>(
        private val onComplete: (List<T>) -> Unit,
        private val onException: (Throwable) -> Unit,
    ) : ResultFuture<T> {
        override fun complete(results: MutableCollection<T>) {
            onComplete(results.toList())
        }

        override fun completeExceptionally(error: Throwable) {
            onException(error)
        }

        override fun complete(supplier: CollectionSupplier<T>) {
            onComplete(supplier.get().toList())
        }
    }

    private class EmptyOpenContext : OpenContext
}
