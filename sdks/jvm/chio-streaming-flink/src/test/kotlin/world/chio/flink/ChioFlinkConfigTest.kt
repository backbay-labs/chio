package world.chio.flink

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import world.chio.flink.support.FakeChioClient
import world.chio.sdk.ChioClientLike
import world.chio.sdk.DlqRouter
import world.chio.sdk.errors.ChioValidationError
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import kotlin.test.assertEquals

@Tag("parity")
class ChioFlinkConfigTest {
    private fun baseBuilder(): ChioFlinkConfig.Builder<Map<String, Any?>> =
        ChioFlinkConfig
            .builder<Map<String, Any?>>()
            .capabilityId("cap-1")
            .toolServer("srv-1")
            .subjectExtractor { e -> e["topic"]?.toString() ?: "" }
            .clientFactory(SerializableClientFactory())
            .dlqRouterFactory(SerializableDlqFactory())

    @Test
    fun buildSucceedsWithRequiredFields() {
        val cfg = baseBuilder().build()
        assertEquals("cap-1", cfg.capabilityId)
        assertEquals("srv-1", cfg.toolServer)
        assertEquals(64, cfg.maxInFlight)
        assertEquals(SidecarErrorBehaviour.RAISE, cfg.onSidecarError)
        assertEquals("chio-flink", cfg.requestIdPrefix)
    }

    @Test
    fun emptyCapabilityIdThrows() {
        val b = baseBuilder().capabilityId("")
        assertThrows<ChioValidationError> { b.build() }
    }

    @Test
    fun emptyToolServerThrows() {
        val b = baseBuilder().toolServer("")
        assertThrows<ChioValidationError> { b.build() }
    }

    @Test
    fun emptyRequestIdPrefixThrows() {
        val b = baseBuilder().requestIdPrefix("")
        assertThrows<ChioValidationError> { b.build() }
    }

    @Test
    fun maxInFlightLessThanOneThrows() {
        val b = baseBuilder().maxInFlight(0)
        assertThrows<ChioValidationError> { b.build() }
    }

    @Test
    fun missingSubjectExtractorThrows() {
        val b =
            ChioFlinkConfig
                .builder<Map<String, Any?>>()
                .capabilityId("c")
                .toolServer("s")
                .clientFactory(SerializableClientFactory())
                .dlqRouterFactory(SerializableDlqFactory())
        assertThrows<ChioValidationError> { b.build() }
    }

    @Test
    fun missingClientFactoryThrows() {
        val b =
            ChioFlinkConfig
                .builder<Map<String, Any?>>()
                .capabilityId("c")
                .toolServer("s")
                .subjectExtractor { "t" }
                .dlqRouterFactory(SerializableDlqFactory())
        assertThrows<ChioValidationError> { b.build() }
    }

    @Test
    fun missingDlqRouterFactoryThrows() {
        val b =
            ChioFlinkConfig
                .builder<Map<String, Any?>>()
                .capabilityId("c")
                .toolServer("s")
                .subjectExtractor { "t" }
                .clientFactory(SerializableClientFactory())
        assertThrows<ChioValidationError> { b.build() }
    }

    @Test
    fun configRoundTripsThroughJavaSerialization() {
        val cfg = baseBuilder().receiptTopic("chio-receipts").build()
        val bytes =
            ByteArrayOutputStream().use { baos ->
                ObjectOutputStream(baos).use { oos -> oos.writeObject(cfg) }
                baos.toByteArray()
            }
        val back: ChioFlinkConfig<Map<String, Any?>> =
            ObjectInputStream(ByteArrayInputStream(bytes)).use { ois ->
                @Suppress("UNCHECKED_CAST")
                ois.readObject() as ChioFlinkConfig<Map<String, Any?>>
            }
        assertEquals("cap-1", back.capabilityId)
        assertEquals("chio-receipts", back.receiptTopic)
        // The factories should survive the round-trip.
        assertEquals(FakeChioClient.DEFAULT_RECEIPT_ID, (back.clientFactory.get() as FakeChioClient).fixedReceiptId)
    }

    /**
     * Static serializable factory classes. Lambdas would also work if
     * they were declared as `object` but keeping these concrete makes
     * the serialization test deterministic across JDKs.
     */
    class SerializableClientFactory : SerializableSupplier<ChioClientLike> {
        override fun get(): ChioClientLike = FakeChioClient()
    }

    class SerializableDlqFactory : SerializableSupplier<DlqRouter> {
        override fun get(): DlqRouter = DlqRouter(defaultTopic = "dlq")
    }
}
