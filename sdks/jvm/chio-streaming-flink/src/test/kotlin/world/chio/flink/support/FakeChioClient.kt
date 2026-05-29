package world.chio.flink.support

import world.chio.sdk.CanonicalJson
import world.chio.sdk.ChioClientLike
import world.chio.sdk.ChioReceipt
import world.chio.sdk.Decision
import world.chio.sdk.Hashing
import world.chio.sdk.ToolCallAction
import world.chio.sdk.errors.ChioError
import java.io.Serializable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * In-memory ChioClientLike for Flink operator unit tests.
 *
 * Lets callers pre-seed a sequence of responses: allow (default),
 * deny, or throw. Also records every invocation for assertions.
 */
class FakeChioClient(
    private val behaviour: Behaviour = Behaviour.Allow,
    val fixedReceiptId: String = DEFAULT_RECEIPT_ID,
    private val verifyResult: Boolean = true,
) : ChioClientLike,
    Serializable {
    sealed class Behaviour : Serializable {
        object Allow : Behaviour() {
            private fun readResolve(): Any = Allow
        }

        data class Deny(
            val reason: String = "nope",
            val guard: String = "test-guard",
        ) : Behaviour()

        data class Throw(
            val error: ChioError,
        ) : Behaviour()

        /** Allow only after the supplied gate counts down (used to test orderly shutdown). */
        data class AllowAfterGate(
            val gate: CountDownLatch,
        ) : Behaviour()
    }

    @Transient
    var calls: AtomicInteger? = null
        private set

    fun callCount(): Int = (calls ?: synchronized(this) { calls ?: AtomicInteger(0).also { calls = it } }).get()

    override fun evaluateToolCall(
        capabilityId: String,
        toolServer: String,
        toolName: String,
        parameters: Map<String, Any?>,
    ): ChioReceipt {
        val counter =
            calls ?: synchronized(this) {
                val c = calls ?: AtomicInteger(0)
                calls = c
                c
            }
        counter.incrementAndGet()
        return when (val b = behaviour) {
            is Behaviour.Allow -> buildAllow(capabilityId, toolServer, toolName, parameters)
            is Behaviour.Deny -> buildDeny(capabilityId, toolServer, toolName, parameters, b)
            is Behaviour.Throw -> throw b.error
            is Behaviour.AllowAfterGate -> {
                if (!b.gate.await(GATE_WAIT_SECONDS, TimeUnit.SECONDS)) {
                    throw IllegalStateException("FakeChioClient gate timed out")
                }
                buildAllow(capabilityId, toolServer, toolName, parameters)
            }
        }
    }

    override fun verifyReceipt(receipt: ChioReceipt): Boolean = verifyResult

    private fun canonicalHash(parameters: Map<String, Any?>): String = Hashing.sha256Hex(CanonicalJson.writeBytes(parameters))

    private fun buildAllow(
        capabilityId: String,
        toolServer: String,
        toolName: String,
        parameters: Map<String, Any?>,
    ): ChioReceipt {
        val hash = canonicalHash(parameters)
        return ChioReceipt(
            id = fixedReceiptId,
            timestamp = 1_700_000_000L,
            capabilityId = capabilityId,
            toolServer = toolServer,
            toolName = toolName,
            action = ToolCallAction(parameters = parameters, parameterHash = hash),
            decision = Decision.allow(),
            receiptKind = "mediated_decision",
            boundaryClass = "prevent",
            toolOrigin = "caller_executed",
            redactionMode = "none",
            trustLevel = "mediated",
            contentHash = hash,
            policyHash = "fake-policy",
            evidence = emptyList(),
            kernelKey = "fake-key",
            signature = "fake-sig",
        )
    }

    private fun buildDeny(
        capabilityId: String,
        toolServer: String,
        toolName: String,
        parameters: Map<String, Any?>,
        deny: Behaviour.Deny,
    ): ChioReceipt {
        val hash = canonicalHash(parameters)
        return ChioReceipt(
            id = fixedReceiptId,
            timestamp = 1_700_000_000L,
            capabilityId = capabilityId,
            toolServer = toolServer,
            toolName = toolName,
            action = ToolCallAction(parameters = parameters, parameterHash = hash),
            decision = Decision.deny(deny.reason, deny.guard),
            receiptKind = "mediated_decision",
            boundaryClass = "prevent",
            toolOrigin = "caller_executed",
            redactionMode = "none",
            trustLevel = "mediated",
            contentHash = hash,
            policyHash = "fake-policy",
            evidence = emptyList(),
            kernelKey = "fake-key",
            signature = "fake-sig",
        )
    }

    companion object {
        const val DEFAULT_RECEIPT_ID: String = "fake-receipt"
        private const val serialVersionUID: Long = 1L
        private const val GATE_WAIT_SECONDS: Long = 5
    }
}
