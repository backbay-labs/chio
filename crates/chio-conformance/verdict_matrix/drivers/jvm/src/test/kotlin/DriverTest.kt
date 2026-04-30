// M07.P6.T1: JVM SDK verdict-matrix driver smoke test.
//
// Exercises the scenario-corpus loader and the unsupported-without-sidecar
// path. Active execution against a live Chio sidecar is operator-tactical
// and out of P6 scope.

package io.backbay.chio.verdictmatrix.jvm

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DriverTest {
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
}
