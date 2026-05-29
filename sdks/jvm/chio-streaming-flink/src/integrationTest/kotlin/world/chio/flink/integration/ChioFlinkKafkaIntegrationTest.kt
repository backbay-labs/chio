/**
 * End-to-end Flink + Kafka (Redpanda) integration test for the JVM
 * Chio Flink operators.
 *
 * Mirrors the Python suite at
 * sdks/python/chio-streaming/tests/integration/test_flink_kafka_integration.py
 * so cross-language parity is provable: one allow + one deny event seeded
 * onto a real Redpanda topic, run through ChioAsyncEvaluateFunction +
 * ChioVerdictSplitFunction inside a Flink MiniCluster, with each side
 * output written to a real Kafka topic via KafkaSink. The test then reads
 * the receipt and DLQ topics back and asserts exactly one envelope on
 * each (== checks, not >=, so a duplicate-emit bug fails).
 *
 * Testcontainers manages Redpanda, so
 *   ./gradlew :chio-streaming-flink:integrationTest
 * works without `docker compose up`. A running Docker daemon is required.
 *
 * Tagged @Tag("integration") so default `gradle test` skips it; only the
 * dedicated `integrationTest` task runs it (see build.gradle.kts).
 */
package world.chio.flink.integration

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.apache.flink.api.common.RuntimeExecutionMode
import org.apache.flink.api.common.eventtime.WatermarkStrategy
import org.apache.flink.api.common.functions.MapFunction
import org.apache.flink.api.common.serialization.SerializationSchema
import org.apache.flink.api.common.serialization.SimpleStringSchema
import org.apache.flink.api.common.typeinfo.TypeHint
import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.connector.base.DeliveryGuarantee
import org.apache.flink.connector.kafka.sink.KafkaRecordSerializationSchema
import org.apache.flink.connector.kafka.sink.KafkaSink
import org.apache.flink.connector.kafka.source.KafkaSource
import org.apache.flink.connector.kafka.source.enumerator.initializer.OffsetsInitializer
import org.apache.flink.streaming.api.datastream.AsyncDataStream
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment
import org.apache.flink.streaming.api.functions.sink.v2.DiscardingSink
import org.apache.flink.test.junit5.MiniClusterExtension
import org.apache.kafka.clients.admin.AdminClient
import org.apache.kafka.clients.admin.AdminClientConfig
import org.apache.kafka.clients.admin.NewTopic
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.clients.consumer.KafkaConsumer
import org.apache.kafka.clients.producer.KafkaProducer
import org.apache.kafka.clients.producer.ProducerConfig
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.StringDeserializer
import org.apache.kafka.common.serialization.StringSerializer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.RegisterExtension
import org.testcontainers.redpanda.RedpandaContainer
import org.testcontainers.utility.DockerImageName
import world.chio.flink.ChioAsyncEvaluateFunction
import world.chio.flink.ChioFlinkConfig
import world.chio.flink.ChioOutputTags
import world.chio.flink.ChioVerdictSplitFunction
import world.chio.flink.SerializableFunction
import world.chio.flink.SerializableSupplier
import world.chio.sdk.CanonicalJson
import world.chio.sdk.ChioClientLike
import world.chio.sdk.ChioReceipt
import world.chio.sdk.Decision
import world.chio.sdk.DlqRouter
import world.chio.sdk.Hashing
import world.chio.sdk.ToolCallAction
import java.io.Serializable
import java.time.Duration
import java.util.Properties
import java.util.UUID
import java.util.concurrent.TimeUnit

private const val ALLOW_INTENT: String = "ok"
private const val DENY_INTENT: String = "evil"

// Pinned to match the python compose at infra/streaming-flink-compose.yml
// so cross-language parity tests run against the same broker image.
private const val REDPANDA_IMAGE: String = "redpandadata/redpanda:v24.2.7"

@Tag("integration")
class ChioFlinkKafkaIntegrationTest {
    companion object {
        @JvmField
        @RegisterExtension
        val miniCluster: MiniClusterExtension = MiniClusterExtension()

        private lateinit var redpanda: RedpandaContainer

        @BeforeAll
        @JvmStatic
        fun startRedpanda() {
            redpanda =
                RedpandaContainer(
                    DockerImageName
                        .parse(REDPANDA_IMAGE)
                        .asCompatibleSubstituteFor("redpandadata/redpanda"),
                )
            redpanda.start()
        }

        @AfterAll
        @JvmStatic
        fun stopRedpanda() {
            if (Companion::redpanda.isInitialized) {
                redpanda.stop()
            }
        }
    }

    @Test
    fun flinkJobOnRealKafkaProducesExactlyOneReceiptAndOneDlqEnvelope() {
        val bootstrap = redpanda.bootstrapServers
        val runId = UUID.randomUUID().toString().take(8)
        val sourceTopic = "chio-it-$runId-source"
        val receiptTopic = "chio-it-$runId-receipts"
        val dlqTopic = "chio-it-$runId-dlq"

        createTopics(bootstrap, listOf(sourceTopic, receiptTopic, dlqTopic))
        try {
            seedSourceEvents(bootstrap, sourceTopic)

            runFlinkJob(bootstrap, sourceTopic, receiptTopic, dlqTopic)

            // The bounded source publishes exactly one allow and one deny
            // event; the split operator must route each to its own side
            // output. Loose >=1 checks would mask a duplicate-emit bug.
            val receiptMessages = drainTopic(bootstrap, receiptTopic)
            val dlqMessages = drainTopic(bootstrap, dlqTopic)

            assertEquals(
                1,
                receiptMessages.size,
                "expected exactly 1 receipt envelope on Kafka, got ${receiptMessages.size}: $receiptMessages",
            )
            assertEquals(
                1,
                dlqMessages.size,
                "expected exactly 1 DLQ envelope on Kafka, got ${dlqMessages.size}: $dlqMessages",
            )

            // Receipt envelope shape (allow path).
            val receiptPayload: Map<String, Any?> =
                jacksonObjectMapper().readValue(receiptMessages.single())
            assertEquals("allow", receiptPayload["verdict"])
            val receiptId = receiptPayload["request_id"] as String
            assertTrue(
                receiptId.startsWith("chio-flink-it-"),
                "receipt request_id should carry the configured prefix; got '$receiptId'",
            )
            assertNotNull(receiptPayload["receipt"], "receipt envelope must embed source receipt")

            // DLQ envelope shape (deny path). Cross-broker contract: the
            // deny receipt rides inside the DLQ payload at receipt.decision.
            val dlqPayload: Map<String, Any?> =
                jacksonObjectMapper().readValue(dlqMessages.single())
            assertEquals("deny", dlqPayload["verdict"])
            assertEquals("intent flagged as evil", dlqPayload["reason"])
            assertEquals("intent-guard", dlqPayload["guard"])
            @Suppress("UNCHECKED_CAST")
            val embeddedReceipt = dlqPayload["receipt"] as Map<String, Any?>

            @Suppress("UNCHECKED_CAST")
            val embeddedDecision = embeddedReceipt["decision"] as Map<String, Any?>
            assertEquals("deny", embeddedDecision["verdict"])
        } finally {
            // Best-effort topic cleanup so parallel runs do not accumulate
            // garbage on a long-lived Redpanda instance. Failures here do
            // not fail the test (Testcontainers stops the broker anyway).
            runCatching { deleteTopics(bootstrap, listOf(sourceTopic, receiptTopic, dlqTopic)) }
        }
    }

    // -----------------------------------------------------------------
    // Flink job topology
    // -----------------------------------------------------------------

    private fun runFlinkJob(
        bootstrap: String,
        sourceTopic: String,
        receiptTopic: String,
        dlqTopic: String,
    ) {
        val env = StreamExecutionEnvironment.getExecutionEnvironment()
        env.setRuntimeMode(RuntimeExecutionMode.STREAMING)
        env.parallelism = 1

        // Bounded KafkaSource: stops at the latest offset at job startup.
        // After seedSourceEvents() commits, that latest offset == 2 records,
        // so env.execute() returns once both records drain through the
        // topology. This keeps the test bound to <90s without polling.
        val source =
            KafkaSource
                .builder<String>()
                .setBootstrapServers(bootstrap)
                .setTopics(sourceTopic)
                .setGroupId("chio-flink-it-${UUID.randomUUID().toString().take(8)}")
                .setStartingOffsets(OffsetsInitializer.earliest())
                .setBounded(OffsetsInitializer.latest())
                .setValueOnlyDeserializer(SimpleStringSchema())
                .build()

        val raw =
            env.fromSource(
                source,
                WatermarkStrategy.noWatermarks(),
                "chio-flink-kafka-it-source",
            )

        // Decode JSON into Map<String, Any?> so the parameters extractor
        // can read `intent`. Type hint is required: KafkaSource +
        // map(MapFunction) erases the value type at runtime, so without
        // .returns() Flink throws InvalidTypesException at the downstream
        // process() step. (The existing async IT uses fromData() which
        // sniffs runtime types from the literal values; we cannot.)
        val mapTypeInfo: TypeInformation<Map<String, Any?>> =
            TypeInformation.of(object : TypeHint<Map<String, Any?>>() {})
        val parsed = raw.map(JsonStringToMap()).returns(mapTypeInfo)

        val cfg =
            ChioFlinkConfig
                .builder<Map<String, Any?>>()
                .capabilityId("cap-it-flink-jvm")
                .toolServer("flink://it-jvm")
                .scopeMap(mapOf("transactions" to "events:consume:transactions"))
                .subjectExtractor(TransactionsSubjectExtractor())
                .parametersExtractor(IntentParametersExtractor())
                .clientFactory(IntentRoutingClientFactory())
                .dlqRouterFactory(DlqRouterFactory(dlqTopic))
                .receiptTopic(receiptTopic)
                .requestIdPrefix("chio-flink-it")
                .maxInFlight(4)
                .build()

        val evaluated =
            AsyncDataStream.unorderedWait(
                parsed,
                ChioAsyncEvaluateFunction(cfg),
                10_000L,
                TimeUnit.MILLISECONDS,
                16,
            )

        val split =
            evaluated
                .process(ChioVerdictSplitFunction<Map<String, Any?>>())
                .returns(mapTypeInfo)

        val receipts = split.getSideOutput(ChioOutputTags.receiptTag())
        val dlq = split.getSideOutput(ChioOutputTags.dlqTag())

        receipts
            .sinkTo(buildKafkaSink(bootstrap, receiptTopic))
            .name("chio-receipt-kafka-sink")
        dlq
            .sinkTo(buildKafkaSink(bootstrap, dlqTopic))
            .name("chio-dlq-kafka-sink")

        // The main allow stream is dropped (we assert only on side outputs),
        // but the topology still needs a terminal sink so Flink doesn't
        // prune the upstream operators during graph optimisation.
        split.sinkTo(DiscardingSink())

        env.execute("chio-flink-kafka-it-jvm")
    }

    private fun buildKafkaSink(
        bootstrap: String,
        topic: String,
    ): KafkaSink<ByteArray> =
        KafkaSink
            .builder<ByteArray>()
            .setBootstrapServers(bootstrap)
            .setRecordSerializer(
                KafkaRecordSerializationSchema
                    .builder<ByteArray>()
                    .setTopic(topic)
                    .setValueSerializationSchema(BytesPassThroughSchema())
                    .build(),
            )
            // AT_LEAST_ONCE is plenty for the assertion (== 1) since the
            // bounded source produces a single record per side output and
            // the test reads exactly that. EXACTLY_ONCE would require a
            // checkpointed transactional producer setup that the
            // MiniCluster default config does not enable.
            .setDeliveryGuarantee(DeliveryGuarantee.AT_LEAST_ONCE)
            .build()

    // -----------------------------------------------------------------
    // Kafka admin / produce / drain helpers
    // -----------------------------------------------------------------

    private fun adminClient(bootstrap: String): AdminClient {
        val props = Properties()
        props[AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG] = bootstrap
        return AdminClient.create(props)
    }

    private fun createTopics(
        bootstrap: String,
        topics: List<String>,
    ) {
        adminClient(bootstrap).use { admin ->
            val newTopics = topics.map { NewTopic(it, 1, 1.toShort()) }
            admin.createTopics(newTopics).all().get(30, TimeUnit.SECONDS)
        }
    }

    private fun deleteTopics(
        bootstrap: String,
        topics: List<String>,
    ) {
        adminClient(bootstrap).use { admin ->
            admin.deleteTopics(topics).all().get(15, TimeUnit.SECONDS)
        }
    }

    private fun seedSourceEvents(
        bootstrap: String,
        topic: String,
    ) {
        val props = Properties()
        props[ProducerConfig.BOOTSTRAP_SERVERS_CONFIG] = bootstrap
        props[ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG] = StringSerializer::class.java.name
        props[ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG] = StringSerializer::class.java.name
        props[ProducerConfig.ACKS_CONFIG] = "all"
        KafkaProducer<String, String>(props).use { producer ->
            producer
                .send(
                    ProducerRecord(
                        topic,
                        "t1",
                        """{"id":"t1","intent":"$ALLOW_INTENT"}""",
                    ),
                ).get(10, TimeUnit.SECONDS)
            producer
                .send(
                    ProducerRecord(
                        topic,
                        "t2",
                        """{"id":"t2","intent":"$DENY_INTENT"}""",
                    ),
                ).get(10, TimeUnit.SECONDS)
            producer.flush()
        }
    }

    /**
     * Read up to a small bounded number of records from [topic]. The poll
     * loop breaks early once we have AT LEAST one record, then tail-polls
     * for two more seconds so a duplicate-emit bug surfaces as a
     * size != 1 failure rather than a quiet pass.
     */
    private fun drainTopic(
        bootstrap: String,
        topic: String,
        timeout: Duration = Duration.ofSeconds(45),
    ): List<String> {
        val props = Properties()
        props[ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG] = bootstrap
        props[ConsumerConfig.GROUP_ID_CONFIG] =
            "chio-flink-it-reader-${UUID.randomUUID().toString().take(8)}"
        props[ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG] = StringDeserializer::class.java.name
        props[ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG] = StringDeserializer::class.java.name
        props[ConsumerConfig.AUTO_OFFSET_RESET_CONFIG] = "earliest"
        props[ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG] = "false"

        val out = ArrayList<String>()
        KafkaConsumer<String, String>(props).use { consumer ->
            consumer.subscribe(listOf(topic))
            val deadline = System.nanoTime() + timeout.toNanos()
            while (System.nanoTime() < deadline && out.isEmpty()) {
                val records = consumer.poll(Duration.ofMillis(500))
                for (r in records) out.add(r.value())
            }
            // Tail-poll for duplicates: keep reading for a few seconds
            // after the first message lands so a delayed duplicate (e.g.
            // KafkaSink retry, double-emit from a buggy split function)
            // is caught by the assertEquals(1, ...) in the test body.
            val tailDeadline = System.nanoTime() + Duration.ofSeconds(8).toNanos()
            while (System.nanoTime() < tailDeadline) {
                val records = consumer.poll(Duration.ofMillis(250))
                for (r in records) out.add(r.value())
            }
        }
        return out
    }
}

// ----------------------------------------------------------------------
// Top-level Serializable helpers (must round-trip JM -> TM through Flink's
// operator serialisation; nested classes inside the test class would
// drag a JUnit test-engine reference into the closure and fail).
// ----------------------------------------------------------------------

/** SimpleStringSchema-style passthrough for the side-output ByteArray. */
class BytesPassThroughSchema :
    SerializationSchema<ByteArray>,
    Serializable {
    override fun serialize(element: ByteArray): ByteArray = element

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/** Decode the JSON-on-Kafka payload into a Map<String, Any?>. */
class JsonStringToMap :
    MapFunction<String, Map<String, Any?>>,
    Serializable {
    override fun map(value: String): Map<String, Any?> = jacksonObjectMapper().readValue(value)

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/** Subject extractor: every test event lives on the `transactions` subject. */
class TransactionsSubjectExtractor : SerializableFunction<Map<String, Any?>, String> {
    override fun apply(input: Map<String, Any?>): String = "transactions"

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/**
 * Surface `intent` from the event into the chio params dict so the
 * routing client on the TaskManager can dispatch on it. (The default
 * extractor only writes request_id / subject / body_length / body_hash.)
 */
class IntentParametersExtractor : SerializableFunction<Map<String, Any?>, Map<String, Any?>> {
    override fun apply(input: Map<String, Any?>): Map<String, Any?> = mapOf("intent" to (input["intent"]?.toString() ?: ""))

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/**
 * Builds a ChioClientLike on each TaskManager subtask. Routes by
 * parameters["intent"] so the same client serves both allow and deny
 * paths in this test (mirroring the python suite's MockChioClient
 * policy closure).
 */
class IntentRoutingClientFactory : SerializableSupplier<ChioClientLike> {
    override fun get(): ChioClientLike = IntentRoutingClient()

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

class IntentRoutingClient :
    ChioClientLike,
    Serializable {
    override fun evaluateToolCall(
        capabilityId: String,
        toolServer: String,
        toolName: String,
        parameters: Map<String, Any?>,
    ): ChioReceipt {
        val intent = parameters["intent"]?.toString() ?: ""
        val hash = Hashing.sha256Hex(CanonicalJson.writeBytes(parameters))
        val decision =
            if (intent == DENY_INTENT) {
                Decision.deny("intent flagged as evil", "intent-guard")
            } else {
                Decision.allow()
            }
        return ChioReceipt(
            id = "fake-receipt-${parameters["request_id"]}",
            timestamp = 1_700_000_000L,
            capabilityId = capabilityId,
            toolServer = toolServer,
            toolName = toolName,
            action = ToolCallAction(parameters = parameters, parameterHash = hash),
            decision = decision,
            receiptKind = "mediated_decision",
            boundaryClass = "prevent",
            toolOrigin = "caller_executed",
            redactionMode = "none",
            contentHash = hash,
            policyHash = "fake-policy",
            evidence = emptyList(),
            kernelKey = "fake-key",
            signature = "fake-sig",
        )
    }

    override fun verifyReceipt(receipt: ChioReceipt): Boolean = true

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/** Builds a DlqRouter on each TaskManager subtask, pinned to one topic. */
class DlqRouterFactory(
    private val dlqTopic: String,
) : SerializableSupplier<DlqRouter> {
    override fun get(): DlqRouter = DlqRouter(defaultTopic = dlqTopic)

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
