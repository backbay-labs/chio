/**
 * Immutable Chio Flink operator configuration. Mirrors the Python
 * ChioFlinkConfig dataclass and its __post_init__ validation.
 *
 * Factories (not instances) of ChioClient and DlqRouter are required
 * because Flink serialises operator closures across the JobManager ->
 * TaskManager boundary; a live HTTP client cannot survive that trip.
 */
package world.chio.flink

import world.chio.sdk.ChioClientLike
import world.chio.sdk.DlqRouter
import world.chio.sdk.errors.ChioValidationError
import java.io.Serializable

class ChioFlinkConfig<IN> private constructor(
    val capabilityId: String,
    val toolServer: String,
    val scopeMap: Map<String, String>,
    val receiptTopic: String?,
    val maxInFlight: Int,
    val onSidecarError: SidecarErrorBehaviour,
    val subjectExtractor: SerializableFunction<IN, String>,
    val parametersExtractor: SerializableFunction<IN, Map<String, Any?>>?,
    val clientFactory: SerializableSupplier<ChioClientLike>,
    val dlqRouterFactory: SerializableSupplier<DlqRouter>,
    val requestIdPrefix: String,
) : Serializable {
    companion object {
        private const val serialVersionUID: Long = 1L

        @JvmStatic
        fun <IN> builder(): Builder<IN> = Builder()
    }

    class Builder<IN> {
        private var capabilityId: String = ""
        private var toolServer: String = ""
        private var scopeMap: Map<String, String> = emptyMap()
        private var receiptTopic: String? = null
        private var maxInFlight: Int = 64
        private var onSidecarError: SidecarErrorBehaviour = SidecarErrorBehaviour.RAISE
        private var subjectExtractor: SerializableFunction<IN, String>? = null
        private var parametersExtractor: SerializableFunction<IN, Map<String, Any?>>? = null
        private var clientFactory: SerializableSupplier<ChioClientLike>? = null
        private var dlqRouterFactory: SerializableSupplier<DlqRouter>? = null
        private var requestIdPrefix: String = "chio-flink"

        fun capabilityId(id: String): Builder<IN> = apply { capabilityId = id }

        fun toolServer(server: String): Builder<IN> = apply { toolServer = server }

        fun scopeMap(map: Map<String, String>): Builder<IN> = apply { scopeMap = LinkedHashMap(map) }

        fun receiptTopic(topic: String?): Builder<IN> = apply { receiptTopic = topic }

        fun maxInFlight(n: Int): Builder<IN> = apply { maxInFlight = n }

        fun onSidecarError(b: SidecarErrorBehaviour): Builder<IN> = apply { onSidecarError = b }

        fun subjectExtractor(f: SerializableFunction<IN, String>): Builder<IN> = apply { subjectExtractor = f }

        fun parametersExtractor(f: SerializableFunction<IN, Map<String, Any?>>?): Builder<IN> = apply { parametersExtractor = f }

        fun clientFactory(s: SerializableSupplier<ChioClientLike>): Builder<IN> = apply { clientFactory = s }

        fun dlqRouterFactory(s: SerializableSupplier<DlqRouter>): Builder<IN> = apply { dlqRouterFactory = s }

        fun requestIdPrefix(p: String): Builder<IN> = apply { requestIdPrefix = p }

        fun build(): ChioFlinkConfig<IN> {
            if (capabilityId.isEmpty()) {
                throw ChioValidationError("ChioFlinkConfig.capabilityId must be non-empty")
            }
            if (toolServer.isEmpty()) {
                throw ChioValidationError("ChioFlinkConfig.toolServer must be non-empty")
            }
            if (maxInFlight < 1) {
                throw ChioValidationError("ChioFlinkConfig.maxInFlight must be >= 1")
            }
            if (requestIdPrefix.isEmpty()) {
                throw ChioValidationError("ChioFlinkConfig.requestIdPrefix must be non-empty")
            }
            val se =
                subjectExtractor ?: throw ChioValidationError(
                    "ChioFlinkConfig.subjectExtractor is required: Flink elements have no " +
                        "broker-provided subject, and an empty subject would make ScopeResolver " +
                        "reject every record. Supply a SerializableFunction<IN, String>.",
                )
            val cf =
                clientFactory ?: throw ChioValidationError(
                    "ChioFlinkConfig.clientFactory is required (Flink workers cannot hydrate a " +
                        "ChioClient from ambient DI)",
                )
            val df =
                dlqRouterFactory ?: throw ChioValidationError(
                    "ChioFlinkConfig.dlqRouterFactory is required (same serialization " +
                        "constraint as clientFactory)",
                )
            return ChioFlinkConfig(
                capabilityId = capabilityId,
                toolServer = toolServer,
                scopeMap = LinkedHashMap(scopeMap),
                receiptTopic = receiptTopic,
                maxInFlight = maxInFlight,
                onSidecarError = onSidecarError,
                subjectExtractor = se,
                parametersExtractor = parametersExtractor,
                clientFactory = cf,
                dlqRouterFactory = df,
                requestIdPrefix = requestIdPrefix,
            )
        }
    }
}
