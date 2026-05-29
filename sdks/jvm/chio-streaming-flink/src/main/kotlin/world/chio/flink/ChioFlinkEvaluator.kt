/**
 * Shared sync/async core for the Chio Flink operators. Mirrors the
 * Python _ChioFlinkEvaluator. One instance per operator subtask;
 * bound by the operator's open(). Not part of the public API.
 */
package world.chio.flink

import org.apache.flink.api.common.functions.RuntimeContext
import org.apache.flink.metrics.Counter
import org.apache.flink.metrics.Gauge
import world.chio.sdk.ChioClientLike
import world.chio.sdk.ChioReceipt
import world.chio.sdk.DlqRouter
import world.chio.sdk.ReceiptEnvelope
import world.chio.sdk.SyntheticDenyReceipt
import world.chio.sdk.errors.ChioDeniedError
import world.chio.sdk.errors.ChioError
import world.chio.sdk.errors.ChioStreamingError
import java.util.UUID

internal class ChioFlinkEvaluator<IN>(
    private val config: ChioFlinkConfig<IN>,
) {
    val slots: Slots = Slots(config.maxInFlight)

    var subtaskIndex: Int? = null
        private set

    var attemptNumber: Int? = null
        private set

    private var client: ChioClientLike? = null
    private var dlqRouter: DlqRouter? = null
    private var metrics: MetricGroup? = null

    fun bind(runtimeContext: RuntimeContext) {
        client = config.clientFactory.get()
        dlqRouter = config.dlqRouterFactory.get()
        subtaskIndex = runCatching<Int> { runtimeContext.taskInfo.indexOfThisSubtask }.getOrNull()
        attemptNumber = runCatching<Int> { runtimeContext.taskInfo.attemptNumber }.getOrNull()
        metrics =
            runCatching<MetricGroup> {
                // Flat on the operator's metric group, matching the Python
                // _register_metrics layout so cross-platform dashboards and
                // alert rules stay interchangeable.
                val group = runtimeContext.metricGroup
                MetricGroup(
                    evaluationsTotal = group.counter("evaluations_total"),
                    allowTotal = group.counter("allow_total"),
                    denyTotal = group.counter("deny_total"),
                    sidecarErrorsTotal = group.counter("sidecar_errors_total"),
                    // Bind a real Flink gauge; returned value is a Number per docs.
                    inFlight = group.gauge("in_flight", Gauge { slots.inFlight }),
                )
            }.getOrNull()
    }

    fun shutdown() {
        val c = client
        if (c != null && c is AutoCloseable) {
            runCatching { c.close() }
        }
        client = null
        dlqRouter = null
    }

    /** Evaluate one element. Thread-safe; blocking on semaphore. */
    fun evaluate(element: IN): FlinkProcessingOutcome<IN> {
        val c = client
        val d = dlqRouter
        if (c == null || d == null) {
            throw world.chio.sdk.errors.ChioValidationError(
                "Chio Flink operator used before open() initialised its collaborators " +
                    "(client / DLQ router)",
            )
        }

        slots.acquire()
        try {
            return evaluateLocked(element, c, d)
        } finally {
            slots.release()
        }
    }

    private fun evaluateLocked(
        element: IN,
        c: ChioClientLike,
        d: DlqRouter,
    ): FlinkProcessingOutcome<IN> {
        val requestId = newRequestId(config.requestIdPrefix)
        val subjectRaw: String? = config.subjectExtractor.apply(element)
        val subject: String = subjectRaw ?: ""
        val toolName = ScopeResolver.resolve(config.scopeMap, subject)
        val parameters = parametersFor(element, requestId, subject)

        metrics?.evaluationsTotal?.inc()

        var receipt: ChioReceipt
        try {
            receipt =
                c.evaluateToolCall(
                    capabilityId = config.capabilityId,
                    toolServer = config.toolServer,
                    toolName = toolName,
                    parameters = parameters,
                )
        } catch (denied: ChioDeniedError) {
            // Mirrors chio_streaming.core.evaluate_with_chio: denied 403 is a
            // real denial, synthesised into a deny receipt so the deny path
            // stays uniform.
            receipt =
                SyntheticDenyReceipt.synthesize(
                    capabilityId = config.capabilityId,
                    toolServer = config.toolServer,
                    toolName = toolName,
                    parameters = parameters,
                    reason = denied.reason ?: (denied.message ?: "denied"),
                    guard = denied.guard ?: "unknown",
                )
        } catch (err: ChioError) {
            // Mirrors chio_streaming.core.evaluate_with_chio: non-denial
            // sidecar errors (timeouts, connection resets, validation
            // errors, 4xx/5xx wrappers) are the only non-denied branch
            // that gets laundered into a synthetic deny under the DENY
            // behaviour. Other RuntimeExceptions (bugs in user-supplied
            // extractors, Jackson crashes, NullPointerException) propagate
            // so Flink restarts the task and the source rewinds.
            metrics?.sidecarErrorsTotal?.inc()
            if (config.onSidecarError != SidecarErrorBehaviour.DENY) {
                // failure_context parity with Python: topic + request_id
                // follow the error into task-restart logs / async
                // completeExceptionally.
                throw ChioStreamingError(
                    "Chio sidecar evaluation failed: ${err.message}",
                    topic = subject.ifEmpty { null },
                    requestId = requestId,
                    cause = err,
                )
            }
            receipt =
                SyntheticDenyReceipt.synthesize(
                    capabilityId = config.capabilityId,
                    toolServer = config.toolServer,
                    toolName = toolName,
                    parameters = parameters,
                    reason = "sidecar unavailable; failing closed",
                    guard = "chio-streaming-sidecar",
                )
        }

        val receiptAuthorized = receipt.isAllowed() && c.verifyReceipt(receipt)
        if (!receiptAuthorized) {
            metrics?.denyTotal?.inc()
            // Fail closed. An allow receipt that fails verification is unsafe to
            // emit, but the DLQ path is reserved for denials. Mirror the
            // denied/sidecar synthesis above and turn the unverified allow into
            // a synthetic deny before routing it to the DLQ.
            if (!receipt.isDenied()) {
                receipt =
                    SyntheticDenyReceipt.synthesize(
                        capabilityId = config.capabilityId,
                        toolServer = config.toolServer,
                        toolName = toolName,
                        parameters = parameters,
                        reason = "receipt failed verification; failing closed",
                        guard = "chio-streaming-verify",
                    )
            }
            val originalBytes = BodyCoercion.canonicalBodyBytes(element)
            val dlqRecord =
                d.buildRecord(
                    sourceTopic = subject.ifEmpty { "unknown" },
                    sourcePartition = null,
                    sourceOffset = null,
                    originalKey = null,
                    originalValue = originalBytes,
                    requestId = requestId,
                    receipt = receipt,
                )
            return FlinkProcessingOutcome(
                allowed = false,
                receipt = receipt,
                requestId = requestId,
                element = element,
                subtaskIndex = subtaskIndex,
                attemptNumber = attemptNumber,
                receiptBytes = null,
                dlqBytes = dlqRecord.value,
                dlqRecord = dlqRecord,
            )
        }

        var receiptBytes: ByteArray? = null
        if (config.receiptTopic != null) {
            val envelope =
                ReceiptEnvelope.build(
                    requestId = requestId,
                    receipt = receipt,
                    sourceTopic = if (subject.isEmpty()) null else subject,
                )
            receiptBytes = envelope.value
        }

        metrics?.allowTotal?.inc()
        return FlinkProcessingOutcome(
            allowed = true,
            receipt = receipt,
            requestId = requestId,
            element = element,
            subtaskIndex = subtaskIndex,
            attemptNumber = attemptNumber,
            receiptBytes = receiptBytes,
            acked = true,
        )
    }

    private fun parametersFor(
        element: IN,
        requestId: String,
        subject: String,
    ): Map<String, Any?> {
        val extractor = config.parametersExtractor
        if (extractor != null) {
            val raw = extractor.apply(element)
            val mutable = LinkedHashMap<String, Any?>(raw)
            mutable.putIfAbsent("request_id", requestId)
            mutable.putIfAbsent("subject", subject)
            return mutable
        }
        return DefaultParametersExtractor.extract(element, requestId, subject)
    }

    private fun newRequestId(prefix: String): String {
        val hex = UUID.randomUUID().toString().replace("-", "")
        return "$prefix-$hex"
    }

    private data class MetricGroup(
        val evaluationsTotal: Counter,
        val allowTotal: Counter,
        val denyTotal: Counter,
        val sidecarErrorsTotal: Counter,
        val inFlight: Gauge<Int>,
    )
}
