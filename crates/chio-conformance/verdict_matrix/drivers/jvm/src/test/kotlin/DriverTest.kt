// JVM SDK verdict-matrix driver smoke test.
//
// Exercises the scenario-corpus loader, the verdict-tuple parser, the
// `/chio/evaluate` response decoder, and the unsupported-without-sidecar gate.
// Live execution against a running Chio sidecar is covered by the
// operator-supplied CHIO_VERDICT_MATRIX_SIDECAR_URL integration path.

package world.chio.verdictmatrix.jvm

import com.fasterxml.jackson.databind.ObjectMapper
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DriverTest {
    private val mapper = ObjectMapper()

    @Test
    fun driverNameIsStable() {
        assertEquals("jvm-sdk", DRIVER_NAME)
        assertEquals("deployment-shape", MATRIX_ROLE)
        assertEquals("rust-kernel", UNDERLYING_DRIVER)
    }

    @Test
    fun verdictTupleParserSortsScopes() {
        val tuple =
            parseVerdictTuple(
                mapOf(
                    "verdict" to "allow",
                    "reason_code" to "urn:chio:error:none",
                    "scope_set" to listOf("tool:write", "tool:read"),
                ),
            )
        assertEquals("allow", tuple.verdict)
        assertEquals(listOf("tool:read", "tool:write"), tuple.scopeSet)
    }

    @Test
    fun runDriverReportsUnsupportedWithoutSidecar() {
        val scenarioRoot = resolveScenarioRoot(emptyArray())
        val report = runDriver(scenarioRoot, sidecarUrl = null)
        assertEquals("jvm-sdk", report.driver)
        assertTrue(report.total > 0, "expected scenarios to load from corpus")
        assertEquals(report.total, report.unsupported)
        assertEquals(0, report.passed)
        assertEquals(0, report.failed)
        val first = report.outcomes.firstOrNull()
        assertNotNull(first, "expected at least one scenario outcome")
        assertEquals("unsupported", first!!.status)
        assertTrue(
            first.diagnostic?.contains("CHIO_VERDICT_MATRIX_SIDECAR_URL") == true,
            "diagnostic must name the sidecar env var",
        )
    }

    @Test
    fun runDriverRecordsFailWhenSidecarIsSetButUnreachable() {
        // A sidecar URL pointing at a closed port must surface as `fail`,
        // never a silent skip: a set-but-broken sidecar cannot pass.
        val scenarioRoot = resolveScenarioRoot(emptyArray())
        val report = runDriver(scenarioRoot, sidecarUrl = "http://127.0.0.1:1")
        assertTrue(report.total > 0, "expected scenarios to load from corpus")
        assertEquals(0, report.unsupported)
        assertEquals(0, report.passed)
        assertEquals(report.total, report.failed)
        assertEquals("fail", report.outcomes.first().status)
    }

    @Test
    fun decodesAllowResponseWithMatrixMetadata() {
        val response =
            mapper.readTree(
                """
                {"verdict":{"verdict":"allow"},
                 "receipt":{"metadata":{"verdict_matrix":{
                   "reason_code":"urn:chio:error:none",
                   "scope_set":["tool:write","tool:read"]}}}}
                """.trimIndent(),
            )
        val tuple = tupleFromEvaluateResponse(response)
        assertEquals("allow", tuple.verdict)
        assertEquals("urn:chio:error:none", tuple.reasonCode)
        assertEquals(listOf("tool:read", "tool:write"), tuple.scopeSet)
    }

    @Test
    fun decodesDenyResponseFallsBackToReason() {
        val response =
            mapper.readTree(
                """
                {"verdict":{"verdict":"deny","reason":"urn:chio:error:capability:revoked",
                 "guard":"capability"},"receipt":{"metadata":{}}}
                """.trimIndent(),
            )
        val tuple = tupleFromEvaluateResponse(response)
        assertEquals("deny", tuple.verdict)
        assertEquals("urn:chio:error:capability:revoked", tuple.reasonCode)
        assertTrue(tuple.scopeSet.isEmpty())
    }

    @Test
    fun httpRequestSetsToolCallFieldsAndGetForRead() {
        val request =
            scenarioToHttpRequest(
                "capability-subset-001-read-exact",
                mapOf(
                    "operation" to "tool.call",
                    "tool" to "files.read",
                    "input_json" to "{}",
                    "capability_scopes" to listOf("tool:read"),
                ),
            )
        assertEquals("GET", request.get("method").asText())
        assertEquals("verdict-matrix", request.get("tool_server").asText())
        assertEquals("files.read", request.get("tool_name").asText())
        // GET requests carry no body hash.
        assertTrue(request.get("body_hash") == null)
    }
}
