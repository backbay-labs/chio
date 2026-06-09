// JVM SDK verdict-matrix driver entry point.
//
// Loads the canonical scenario corpus from
// `crates/chio-conformance/verdict_matrix/scenarios/` and emits the
// (verdict, reason_code, scope_set) tuple per scenario as JSON on stdout.
//
// The deployment-shape driver does not embed kernel evaluation. It mirrors
// the TypeScript node-http and JVM `chio-sdk-jvm` client contract: it forwards
// each scenario to a Chio sidecar over the production `POST /chio/evaluate`
// wire surface using the JDK HttpClient.
//
// Runtime-availability gate: the sidecar URL is read from
// `CHIO_VERDICT_MATRIX_SIDECAR_URL` (or `CHIO_SIDECAR_URL`). When a sidecar URL
// is present the driver issues a real HTTP POST per scenario, parses the
// verdict and the `verdict_matrix` receipt metadata, and emits a pass/fail
// tuple against the scenario's expected tuple; a sidecar that is
// set-but-unreachable surfaces as a `fail` (never a silent skip). When no
// sidecar URL is set every scenario is reported as `unsupported` with a
// diagnostic that names the missing variable, because the JVM SDK has no
// in-process kernel and therefore no verdict it can honestly emit on its own.

package world.chio.verdictmatrix.jvm

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.time.Duration

const val DRIVER_NAME: String = "jvm-sdk"
const val MATRIX_ROLE: String = "deployment-shape"
const val UNDERLYING_DRIVER: String = "rust-kernel"
private const val SIDECAR_ENV: String = "CHIO_VERDICT_MATRIX_SIDECAR_URL"
private const val SIDECAR_FALLBACK_ENV: String = "CHIO_SIDECAR_URL"
private const val MATRIX_SERVER_ID: String = "verdict-matrix"
private const val REASON_NONE: String = "urn:chio:error:none"
private const val REASON_KERNEL_INTERNAL: String = "urn:chio:error:kernel:internal-error"
private const val EVALUATE_PATH: String = "/chio/evaluate"

// Synthetic request timestamp (unix seconds). The verdict-matrix corpus is
// time-invariant, so a fixed value keeps relayed requests deterministic.
private const val REQUEST_TIMESTAMP_SECS: Long = 1_700_000_000L

private val MAPPER: ObjectMapper = ObjectMapper().registerKotlinModule()

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
            val parsed = MAPPER.readValue(file, Map::class.java) as Map<String, Any?>
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
        reasonCode = raw["reason_code"]?.toString() ?: REASON_KERNEL_INTERNAL,
        scopeSet = scopes,
    )
}

private fun normalize(tuple: VerdictTuple): VerdictTuple = tuple.copy(scopeSet = tuple.scopeSet.sorted())

@Suppress("UNCHECKED_CAST")
private fun scenarioScript(scenario: Map<String, Any?>): Map<String, Any?> =
    scenario["script"] as? Map<String, Any?> ?: emptyMap()

private fun methodForTool(tool: String): String =
    if (tool.endsWith(".read") || tool.endsWith(".get") || tool == "metrics.query") "GET" else "POST"

private fun pathSegment(value: String): String =
    URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

private fun toolPath(tool: String): String =
    "/chio/tools/${pathSegment(MATRIX_SERVER_ID)}/${pathSegment(tool)}"

/**
 * Build the `ChioHttpRequest` body for a scenario, populating the tool-call
 * fields the sidecar's capability-scope evaluator reads. Mirrors the node-http
 * transport-client driver so the deployment shapes share one wire contract.
 */
fun scenarioToHttpRequest(scenarioId: String, script: Map<String, Any?>): ObjectNode {
    val tool = script["tool"]?.toString() ?: ""
    val method = methodForTool(tool)
    val path = toolPath(tool)
    val inputJson = script["input_json"]?.toString() ?: "null"
    val arguments: JsonNode =
        try {
            MAPPER.readTree(inputJson)
        } catch (_: Exception) {
            MAPPER.nullNode()
        }
    val root = MAPPER.createObjectNode()
    root.put("request_id", "req-$scenarioId")
    root.put("method", method)
    root.put("path", path)
    root.set<ObjectNode>("query", MAPPER.createObjectNode())
    val headers = MAPPER.createObjectNode()
    headers.put("content-type", "application/json")
    root.set<ObjectNode>("headers", headers)
    val caller = MAPPER.createObjectNode()
    caller.put("subject", "agent:$scenarioId")
    val authMethod = MAPPER.createObjectNode()
    authMethod.put("method", "anonymous")
    caller.set<ObjectNode>("auth_method", authMethod)
    caller.put("verified", true)
    caller.put("agent_id", "agent:$scenarioId")
    root.set<ObjectNode>("caller", caller)
    val bodyLength = if (method == "GET" || method == "HEAD") 0 else inputJson.toByteArray().size
    root.put("body_length", bodyLength)
    if (bodyLength > 0) {
        root.put("body_hash", "0".repeat(64))
    }
    root.put("route_pattern", path)
    root.put("capability_id", "cap-$scenarioId")
    root.put("tool_server", MATRIX_SERVER_ID)
    root.put("tool_name", tool)
    root.set<JsonNode>("arguments", arguments)
    root.put("timestamp", REQUEST_TIMESTAMP_SECS)
    return root
}

private fun capabilityTokenFor(scenarioId: String, script: Map<String, Any?>): String {
    @Suppress("UNCHECKED_CAST")
    val scopes = (script["capability_scopes"] as? List<Any?>).orEmpty().map { it.toString() }
    val node = MAPPER.createObjectNode()
    node.put("id", "cap-$scenarioId")
    val scopeArray = node.putArray("scopes")
    scopes.forEach { scopeArray.add(it) }
    return MAPPER.writeValueAsString(node)
}

/**
 * Derive the matrix verdict tuple from a `/chio/evaluate` response body. The
 * authoritative `reason_code` and `scope_set` come from
 * `receipt.metadata.verdict_matrix`; the verdict tag falls back to the deny
 * reason when the matrix metadata is absent.
 */
fun tupleFromEvaluateResponse(response: JsonNode): VerdictTuple {
    val verdictNode = response.get("verdict")
    val verdictTag = verdictNode?.get("verdict")?.asText() ?: "error"
    val verdict =
        when (verdictTag) {
            "allow" -> "allow"
            "deny" -> "deny"
            else -> "error"
        }
    val matrix = response.get("receipt")?.get("metadata")?.get("verdict_matrix")
    val reasonCode =
        matrix?.get("reason_code")?.takeIf { it.isTextual }?.asText()
            ?: reasonFromVerdict(verdictTag, verdictNode)
    val scopeSet =
        matrix?.get("scope_set")?.takeIf { it.isArray }?.mapNotNull {
            if (it.isTextual) it.asText() else null
        }?.sorted() ?: emptyList()
    return VerdictTuple(verdict, reasonCode, scopeSet)
}

private fun reasonFromVerdict(verdictTag: String, verdictNode: JsonNode?): String =
    when (verdictTag) {
        "allow" -> REASON_NONE
        "deny" -> verdictNode?.get("reason")?.takeIf { it.isTextual }?.asText() ?: REASON_KERNEL_INTERNAL
        else -> REASON_KERNEL_INTERNAL
    }

private fun evaluateScenario(
    client: HttpClient,
    baseUrl: String,
    scenarioId: String,
    expected: VerdictTuple,
    script: Map<String, Any?>,
): ScenarioOutcome {
    val body = MAPPER.writeValueAsString(scenarioToHttpRequest(scenarioId, script))
    val request =
        HttpRequest.newBuilder()
            .uri(URI.create("$baseUrl$EVALUATE_PATH"))
            .timeout(Duration.ofSeconds(5))
            .header("content-type", "application/json")
            .header("x-chio-capability", capabilityTokenFor(scenarioId, script))
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()
    val response =
        try {
            client.send(request, HttpResponse.BodyHandlers.ofString())
        } catch (e: Exception) {
            return ScenarioOutcome(
                scenarioId,
                "fail",
                expected,
                null,
                "sidecar POST failed: ${e.message}",
            )
        }
    if (response.statusCode() / 100 != 2) {
        return ScenarioOutcome(
            scenarioId,
            "fail",
            expected,
            null,
            "sidecar returned ${response.statusCode()}: ${response.body()}",
        )
    }
    val parsed =
        try {
            MAPPER.readTree(response.body())
        } catch (e: Exception) {
            return ScenarioOutcome(
                scenarioId,
                "fail",
                expected,
                null,
                "failed to parse sidecar response: ${e.message}",
            )
        }
    val actual = normalize(tupleFromEvaluateResponse(parsed))
    val pass = actual == expected
    return ScenarioOutcome(
        scenarioId,
        if (pass) "pass" else "fail",
        expected,
        actual,
        if (pass) null else "tuple mismatch against sidecar verdict",
    )
}

fun runDriver(scenarioRoot: Path, sidecarUrl: String?): DriverReport {
    val scenarios = loadScenarios(scenarioRoot)
    val sidecar = sidecarUrl?.trim()?.takeIf { it.isNotEmpty() }?.trimEnd('/')
    val client: HttpClient? =
        if (sidecar != null) {
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
        } else {
            null
        }
    val outcomes = mutableListOf<ScenarioOutcome>()
    for (scenario in scenarios) {
        val id = scenario["id"]?.toString() ?: continue
        @Suppress("UNCHECKED_CAST")
        val expected = normalize(parseVerdictTuple(scenario["expected"] as? Map<String, Any?> ?: emptyMap()))
        if (sidecar == null || client == null) {
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
        val category = scenario["category"]?.toString() ?: ""
        if (category == "capability" || category == "revocation") {
            outcomes +=
                ScenarioOutcome(
                    scenarioId = id,
                    status = "unsupported",
                    expected = expected,
                    actual = null,
                    diagnostic =
                        "JVM deployment-shape relay has no signed CapabilityToken builder; " +
                            "sidecar evaluation of $category scenarios requires a signed " +
                            "CapabilityToken (issuer + signature + time-valid) per " +
                            "chio-http-core authority validate_capability_token",
                )
            continue
        }
        outcomes += evaluateScenario(client, sidecar, id, expected, scenarioScript(scenario))
    }
    return DriverReport(
        driver = DRIVER_NAME,
        matrixRole = MATRIX_ROLE,
        underlyingDriver = UNDERLYING_DRIVER,
        total = outcomes.size,
        passed = outcomes.count { it.status == "pass" },
        failed = outcomes.count { it.status == "fail" },
        unsupported = outcomes.count { it.status == "unsupported" },
        outcomes = outcomes,
    )
}

fun main(args: Array<String>) {
    val scenarioRoot = resolveScenarioRoot(args)
    val sidecarUrl =
        System.getenv(SIDECAR_ENV)?.takeIf { it.isNotBlank() }
            ?: System.getenv(SIDECAR_FALLBACK_ENV)?.takeIf { it.isNotBlank() }
    val report = runDriver(scenarioRoot, sidecarUrl)
    println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(report))
    if (report.failed > 0) {
        System.exit(1)
    }
}
