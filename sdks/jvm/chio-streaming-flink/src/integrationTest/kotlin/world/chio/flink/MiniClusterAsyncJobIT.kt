package world.chio.flink

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import org.apache.flink.api.common.RuntimeExecutionMode
import org.apache.flink.api.common.typeinfo.TypeHint
import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.streaming.api.datastream.AsyncDataStream
import org.apache.flink.streaming.api.datastream.DataStream
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment
import org.apache.flink.test.junit5.MiniClusterExtension
import org.apache.flink.util.CloseableIterator
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.RegisterExtension
import world.chio.sdk.ChioClient
import world.chio.sdk.DlqRouter
import java.net.InetSocketAddress
import java.time.Duration
import java.util.concurrent.TimeUnit

@Tag("integration")
class MiniClusterAsyncJobIT {
    companion object {
        @JvmField
        @RegisterExtension
        val miniCluster: MiniClusterExtension = MiniClusterExtension()
    }

    @Test
    fun asyncPipelineRoutesAllowDenySyntheticAcrossSideOutputs() {
        val sidecar = startSidecar()
        try {
            val base = "http://127.0.0.1:${sidecar.address.port}"
            val env = StreamExecutionEnvironment.getExecutionEnvironment()
            env.setRuntimeMode(RuntimeExecutionMode.STREAMING)
            env.parallelism = 1
            val source: DataStream<Map<String, Any?>> =
                env.fromData(
                    mapOf("topic" to "allowed", "id" to "a") as Map<String, Any?>,
                    mapOf("topic" to "denied", "id" to "b") as Map<String, Any?>,
                    mapOf("topic" to "allowed", "id" to "c") as Map<String, Any?>,
                )

            val cfg =
                ChioFlinkConfig
                    .builder<Map<String, Any?>>()
                    .capabilityId("cap")
                    .toolServer("srv")
                    .subjectExtractor { e -> e["topic"]?.toString() ?: "" }
                    .clientFactory { ChioClient(base, Duration.ofSeconds(2)) }
                    .dlqRouterFactory { DlqRouter(defaultTopic = "chio-dlq") }
                    .receiptTopic("chio-receipts")
                    .build()

            val evaluated =
                AsyncDataStream.unorderedWait(
                    source,
                    ChioAsyncEvaluateFunction(cfg),
                    5,
                    TimeUnit.SECONDS,
                    16,
                )
            // process() needs an explicit return type; Flink's type extractor
            // cannot recover IN from EvaluationResult<IN> through the
            // ProcessFunction's generic signature.
            val split =
                evaluated
                    .process(ChioVerdictSplitFunction<Map<String, Any?>>())
                    .returns(TypeInformation.of(object : TypeHint<Map<String, Any?>>() {}))

            val main = split.executeAndCollect("main").consume()
            val dlq = split.getSideOutput(ChioOutputTags.dlqTag()).executeAndCollect("dlq").consume()
            val receipts = split.getSideOutput(ChioOutputTags.receiptTag()).executeAndCollect("receipts").consume()

            assert(main.isEmpty()) { "expected no allow from advisory-only route, got ${main.size}" }
            assert(dlq.size == 3) { "expected 3 fail-closed DLQ records, got ${dlq.size}" }
            assert(receipts.isEmpty()) { "expected no mediated receipts, got ${receipts.size}" }
        } finally {
            sidecar.stop(0)
        }
    }

    private fun <T> CloseableIterator<T>.consume(): List<T> {
        val out = ArrayList<T>()
        use { it.forEachRemaining { element -> out.add(element) } }
        return out
    }

    private fun startSidecar(): HttpServer {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/v1/evaluate/advisory") { exchange ->
            val body = exchange.requestBody.readAllBytes()
            val parsed: Map<String, Any?> = jacksonObjectMapper().readValue(body)
            val toolName = parsed["tool_name"] as String
            val params = parsed["parameters"] as Map<String, Any?>
            val paramHash = parsed["parameter_hash"] as String
            val resp =
                """
                {
                  "schema": "chio.sidecar.advisory-evaluation.v1",
                  "authorization": false,
                  "authorizationBasis": "advisory_only",
                  "receipt": {
                    "id": "srv-${params["request_id"]}",
                    "timestamp": 1700000000,
                    "capability_id": "cap",
                    "tool_server": "srv",
                    "tool_name": "$toolName",
                    "action": {"parameters": ${jacksonObjectMapper().writeValueAsString(params)}, "parameter_hash": "$paramHash"},
                    "decision": null,
                    "receipt_kind": "advisory_evaluation",
                    "boundary_class": "advisory_only",
                    "observation_outcome": "evaluated",
                    "tool_origin": "host_executed_unmediated",
                    "redaction_mode": "none",
                    "trust_level": "advisory",
                    "content_hash": "$paramHash",
                    "policy_hash": "p",
                    "evidence": [],
                    "kernel_key": "k",
                    "signature": "s"
                  }
                }
                """.trimIndent()
            respond(exchange, 200, resp)
        }
        server.createContext("/v1/receipts/verify") { exchange ->
            respond(
                exchange,
                200,
                """
                {
                  "signature_valid": true,
                  "signer_trusted": true,
                  "receipt_id_valid": true,
                  "parameter_hash_valid": true,
                  "receipt_kind": "advisory_evaluation",
                  "boundary_class": "advisory_only",
                  "trust_level": "advisory",
                  "result": "none",
                  "authorized": false,
                  "signer_key_hex": "${"d".repeat(64)}",
                  "ok": false
                }
                """.trimIndent(),
            )
        }
        server.start()
        return server
    }

    private fun respond(
        exchange: HttpExchange,
        status: Int,
        body: String,
    ) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        exchange.responseHeaders.add("Content-Type", "application/json")
        exchange.sendResponseHeaders(status, bytes.size.toLong())
        exchange.responseBody.use { it.write(bytes) }
    }
}
