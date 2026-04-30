// M07.P6.T1: JVM SDK verdict-matrix driver entry point.
//
// Loads the canonical scenario corpus from
// `crates/chio-conformance/verdict_matrix/scenarios/` and emits the
// (verdict, reason_code, scope_set) tuple per scenario as JSON on stdout.
//
// The deployment-shape driver does not embed kernel evaluation. It mirrors
// the trajectory-1 TypeScript node-http driver contract: an operator-
// supplied Chio sidecar URL is read from `CHIO_VERDICT_MATRIX_SIDECAR_URL`
// (or `CHIO_SIDECAR_URL`); when absent, every scenario is reported as
// `unsupported` with a diagnostic that names the missing variable. The
// production JVM SDK at `sdks/jvm/chio-sdk-jvm` provides the host bindings
// the driver invokes through the sidecar; the binding wiring lands in a
// follow-on operator-tactical ticket and is out of M07.P6.T1 scope.

package io.backbay.chio.verdictmatrix.jvm

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import java.io.File
import java.nio.file.Path

const val DRIVER_NAME: String = "jvm-sdk"
const val MATRIX_ROLE: String = "deployment-shape"
const val UNDERLYING_DRIVER: String = "rust-kernel"
private const val SIDECAR_ENV: String = "CHIO_VERDICT_MATRIX_SIDECAR_URL"
private const val SIDECAR_FALLBACK_ENV: String = "CHIO_SIDECAR_URL"

data class VerdictTuple(
    val verdict: String,
    val reasonCode: String,
    val scopeSet: List<String>,
)

data class ScenarioOutcome(
    val scenarioId: String,
    val status: String,
    val expected: VerdictTuple,
    val actual: VerdictTuple?,
    val diagnostic: String?,
)

data class DriverReport(
    val driver: String,
    val matrixRole: String,
    val underlyingDriver: String,
    val total: Int,
    val passed: Int,
    val failed: Int,
    val unsupported: Int,
    val outcomes: List<ScenarioOutcome>,
)

fun resolveScenarioRoot(args: Array<String>): Path {
    val explicit =
        args
            .toList()
            .windowed(2, step = 1)
            .firstOrNull { it[0] == "--scenario-root" }
            ?.get(1)
    if (explicit != null) {
        return Path.of(explicit)
    }
    val cwd = Path.of("").toAbsolutePath()
    var candidate: Path? = cwd
    while (candidate != null) {
        val cargo = candidate.resolve("Cargo.toml").toFile()
        val matrix = candidate.resolve("crates/chio-conformance/verdict_matrix").toFile()
        if (cargo.exists() && matrix.exists()) {
            return matrix.toPath().resolve("scenarios")
        }
        candidate = candidate.parent
    }
    return cwd.resolve("crates/chio-conformance/verdict_matrix/scenarios")
}

fun loadScenarios(root: Path): List<Map<String, Any?>> {
    val mapper = ObjectMapper().registerKotlinModule()
    val rootFile = root.toFile()
    if (!rootFile.exists() || !rootFile.isDirectory) {
        throw IllegalStateException("scenario root `${root}` does not exist or is not a directory")
    }
    val scenarios = mutableListOf<Map<String, Any?>>()
    rootFile.walkTopDown()
        .filter { it.isFile && it.name.endsWith(".json") }
        .sortedBy { it.absolutePath }
        .forEach { file ->
            @Suppress("UNCHECKED_CAST")
            val parsed = mapper.readValue(file, Map::class.java) as Map<String, Any?>
            val schema = parsed["schema"] as? String
            require(schema == "chio.verdict-matrix.scenario.v1") {
                "${file.path} has unsupported scenario schema `$schema`"
            }
            scenarios += parsed
        }
    return scenarios
}

@Suppress("UNCHECKED_CAST")
fun parseVerdictTuple(raw: Map<String, Any?>): VerdictTuple {
    val scopes = (raw["scope_set"] as? List<Any?>).orEmpty().map { it.toString() }.sorted()
    return VerdictTuple(
        verdict = raw["verdict"]?.toString() ?: "error",
        reasonCode = raw["reason_code"]?.toString() ?: "urn:chio:error:kernel:internal-error",
        scopeSet = scopes,
    )
}

fun runDriver(scenarioRoot: Path, sidecarUrl: String?): DriverReport {
    val scenarios = loadScenarios(scenarioRoot)
    val outcomes = mutableListOf<ScenarioOutcome>()
    for (scenario in scenarios) {
        val id = scenario["id"]?.toString() ?: continue
        @Suppress("UNCHECKED_CAST")
        val expected = parseVerdictTuple(scenario["expected"] as? Map<String, Any?> ?: emptyMap())
        if (sidecarUrl.isNullOrBlank()) {
            outcomes +=
                ScenarioOutcome(
                    scenarioId = id,
                    status = "unsupported",
                    expected = expected,
                    actual = null,
                    diagnostic =
                        "set $SIDECAR_ENV (or $SIDECAR_FALLBACK_ENV) to a live Chio sidecar; " +
                            "the JVM SDK does not embed kernel evaluation",
                )
            continue
        }
        outcomes +=
            ScenarioOutcome(
                scenarioId = id,
                status = "unsupported",
                expected = expected,
                actual = null,
                diagnostic =
                    "JVM SDK driver sidecar wiring is operator-tactical; the M07.P6.T1 " +
                        "scaffold registers the driver shape only",
            )
    }
    val unsupported = outcomes.count { it.status == "unsupported" }
    return DriverReport(
        driver = DRIVER_NAME,
        matrixRole = MATRIX_ROLE,
        underlyingDriver = UNDERLYING_DRIVER,
        total = outcomes.size,
        passed = outcomes.count { it.status == "pass" },
        failed = outcomes.count { it.status == "fail" },
        unsupported = unsupported,
        outcomes = outcomes,
    )
}

fun main(args: Array<String>) {
    val scenarioRoot = resolveScenarioRoot(args)
    val sidecarUrl =
        System.getenv(SIDECAR_ENV)?.takeIf { it.isNotBlank() }
            ?: System.getenv(SIDECAR_FALLBACK_ENV)?.takeIf { it.isNotBlank() }
    val report = runDriver(scenarioRoot, sidecarUrl)
    val mapper = ObjectMapper().registerKotlinModule()
    println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(report))
    if (report.failed > 0) {
        System.exit(1)
    }
}
