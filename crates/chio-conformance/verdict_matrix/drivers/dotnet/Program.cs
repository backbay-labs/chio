// dotnet SDK verdict-matrix driver entry point.
//
// Loads the canonical scenario corpus from
// crates/chio-conformance/verdict_matrix/scenarios/ and emits a JSON report
// on stdout shaped as (verdict, reason_code, scope_set) per scenario. The
// deployment-shape driver does not embed kernel evaluation; it mirrors the
// TypeScript node-http and dotnet ChioMiddleware client contract by forwarding
// each scenario to a Chio sidecar over the production POST /chio/evaluate wire
// surface.
//
// Runtime-availability gate: the sidecar URL is read from
// CHIO_VERDICT_MATRIX_SIDECAR_URL (with CHIO_SIDECAR_URL fallback). When a
// sidecar URL is present the driver issues a real HTTP POST per scenario,
// parses the verdict and the verdict_matrix receipt metadata, and emits a
// pass/fail tuple against the scenario's expected tuple; a sidecar that is
// set-but-unreachable surfaces as a fail (never a silent skip). When no
// sidecar URL is set every scenario is reported as unsupported with a
// diagnostic that names the missing variable, because the dotnet SDK has no
// in-process kernel and therefore no verdict it can honestly emit on its own.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;

namespace BackBay.Chio.VerdictMatrix.Dotnet;

public sealed record VerdictTuple(
    [property: JsonPropertyName("verdict")] string Verdict,
    [property: JsonPropertyName("reason_code")] string ReasonCode,
    [property: JsonPropertyName("scope_set")] IReadOnlyList<string> ScopeSet);

public sealed record ScenarioOutcome(
    [property: JsonPropertyName("scenario_id")] string ScenarioId,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("expected")] VerdictTuple Expected,
    [property: JsonPropertyName("actual")] VerdictTuple? Actual,
    [property: JsonPropertyName("diagnostic")] string? Diagnostic);

public sealed record DriverReport(
    [property: JsonPropertyName("driver")] string Driver,
    [property: JsonPropertyName("matrix_role")] string MatrixRole,
    [property: JsonPropertyName("underlying_driver")] string UnderlyingDriver,
    [property: JsonPropertyName("total")] int Total,
    [property: JsonPropertyName("passed")] int Passed,
    [property: JsonPropertyName("failed")] int Failed,
    [property: JsonPropertyName("unsupported")] int Unsupported,
    [property: JsonPropertyName("outcomes")] IReadOnlyList<ScenarioOutcome> Outcomes);

public static class Driver
{
    public const string DriverName = "dotnet-sdk";
    public const string MatrixRole = "deployment-shape";
    public const string UnderlyingDriver = "rust-kernel";
    private const string SidecarEnv = "CHIO_VERDICT_MATRIX_SIDECAR_URL";
    private const string SidecarFallbackEnv = "CHIO_SIDECAR_URL";
    private const string ScenarioSchema = "chio.verdict-matrix.scenario.v1";
    private const string MatrixServerId = "verdict-matrix";
    private const string ReasonNone = "urn:chio:error:none";
    private const string ReasonKernelInternal = "urn:chio:error:kernel:internal-error";
    private const string EvaluatePath = "/chio/evaluate";
    // Synthetic request timestamp (unix seconds). The verdict-matrix corpus is
    // time-invariant, so a fixed value keeps relayed requests deterministic.
    private const long RequestTimestampSecs = 1_700_000_000;

    public static string ResolveScenarioRoot(string[] args)
    {
        for (var i = 0; i + 1 < args.Length; i++)
        {
            if (args[i] == "--scenario-root")
            {
                return args[i + 1];
            }
        }

        var current = Directory.GetCurrentDirectory();
        var dir = new DirectoryInfo(current);
        while (dir is not null)
        {
            var cargo = Path.Combine(dir.FullName, "Cargo.toml");
            var matrix = Path.Combine(dir.FullName, "crates", "chio-conformance", "verdict_matrix");
            if (File.Exists(cargo) && Directory.Exists(matrix))
            {
                return Path.Combine(matrix, "scenarios");
            }
            dir = dir.Parent;
        }
        return Path.Combine(current, "crates", "chio-conformance", "verdict_matrix", "scenarios");
    }

    public static IReadOnlyList<JsonElement> LoadScenarios(string root)
    {
        if (!Directory.Exists(root))
        {
            throw new InvalidOperationException($"scenario root `{root}` does not exist");
        }

        var files = Directory.EnumerateFiles(root, "*.json", SearchOption.AllDirectories)
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToList();
        var scenarios = new List<JsonElement>();
        foreach (var file in files)
        {
            using var stream = File.OpenRead(file);
            using var doc = JsonDocument.Parse(stream);
            var root_ = doc.RootElement.Clone();
            if (!root_.TryGetProperty("schema", out var schema)
                || schema.GetString() != ScenarioSchema)
            {
                throw new InvalidOperationException(
                    $"{file} has unsupported scenario schema");
            }
            scenarios.Add(root_);
        }
        return scenarios;
    }

    public static VerdictTuple ParseTuple(JsonElement raw)
    {
        var verdict = raw.TryGetProperty("verdict", out var v) ? v.GetString() ?? "error" : "error";
        var reason = raw.TryGetProperty("reason_code", out var r)
            ? r.GetString() ?? ReasonKernelInternal
            : ReasonKernelInternal;
        var scopes = new List<string>();
        if (raw.TryGetProperty("scope_set", out var scopeSet) && scopeSet.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in scopeSet.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    scopes.Add(item.GetString() ?? string.Empty);
                }
            }
        }
        scopes.Sort(StringComparer.Ordinal);
        return new VerdictTuple(verdict, reason, scopes);
    }

    private static VerdictTuple Normalize(VerdictTuple tuple)
    {
        var scopes = tuple.ScopeSet.ToList();
        scopes.Sort(StringComparer.Ordinal);
        return tuple with { ScopeSet = scopes };
    }

    private static string MethodForTool(string tool) =>
        tool.EndsWith(".read", StringComparison.Ordinal)
        || tool.EndsWith(".get", StringComparison.Ordinal)
        || tool == "metrics.query"
            ? "GET"
            : "POST";

    /// <summary>
    /// Build the ChioHttpRequest body for a scenario, populating the tool-call
    /// fields the sidecar's capability-scope evaluator reads. Mirrors the
    /// node-http transport-client driver so the deployment shapes share one
    /// wire contract.
    /// </summary>
    public static string ScenarioToHttpRequest(string scenarioId, JsonElement script)
    {
        var tool = script.TryGetProperty("tool", out var toolEl) ? toolEl.GetString() ?? string.Empty : string.Empty;
        var method = MethodForTool(tool);
        var inputJson = script.TryGetProperty("input_json", out var inputEl) ? inputEl.GetString() ?? "null" : "null";
        var bodyLength = method is "GET" or "HEAD" ? 0 : Encoding.UTF8.GetByteCount(inputJson);

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("request_id", $"req-{scenarioId}");
            writer.WriteString("method", method);
            writer.WriteString("path", "/" + tool.Replace(".", "/"));
            writer.WriteStartObject("query");
            writer.WriteEndObject();
            writer.WriteStartObject("headers");
            writer.WriteString("content-type", "application/json");
            writer.WriteEndObject();
            writer.WriteStartObject("caller");
            writer.WriteString("subject", $"agent:{scenarioId}");
            writer.WriteStartObject("auth_method");
            writer.WriteString("method", "anonymous");
            writer.WriteEndObject();
            writer.WriteBoolean("verified", true);
            writer.WriteString("agent_id", $"agent:{scenarioId}");
            writer.WriteEndObject();
            writer.WriteNumber("body_length", bodyLength);
            if (bodyLength > 0)
            {
                writer.WriteString("body_hash", new string('0', 64));
            }
            writer.WriteString("route_pattern", $"{MatrixServerId}:{tool}");
            writer.WriteString("capability_id", $"cap-{scenarioId}");
            writer.WriteString("tool_server", MatrixServerId);
            writer.WriteString("tool_name", tool);
            writer.WritePropertyName("arguments");
            WriteRawJsonOrNull(writer, inputJson);
            writer.WriteNumber("timestamp", RequestTimestampSecs);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static void WriteRawJsonOrNull(Utf8JsonWriter writer, string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            doc.RootElement.WriteTo(writer);
        }
        catch (JsonException)
        {
            writer.WriteNullValue();
        }
    }

    private static string CapabilityTokenFor(string scenarioId, JsonElement script)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("id", $"cap-{scenarioId}");
            writer.WriteStartArray("scopes");
            if (script.TryGetProperty("capability_scopes", out var scopes) && scopes.ValueKind == JsonValueKind.Array)
            {
                foreach (var scope in scopes.EnumerateArray())
                {
                    if (scope.ValueKind == JsonValueKind.String)
                    {
                        writer.WriteStringValue(scope.GetString());
                    }
                }
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// Derive the matrix verdict tuple from a /chio/evaluate response body. The
    /// authoritative reason_code and scope_set come from
    /// receipt.metadata.verdict_matrix; the verdict tag falls back to the deny
    /// reason when the matrix metadata is absent.
    /// </summary>
    public static VerdictTuple TupleFromEvaluateResponse(JsonElement response)
    {
        var hasVerdict = response.TryGetProperty("verdict", out var verdictObj);
        var verdictTag = hasVerdict && verdictObj.TryGetProperty("verdict", out var tagEl)
            ? tagEl.GetString() ?? "error"
            : "error";
        var verdict = verdictTag switch
        {
            "allow" => "allow",
            "deny" => "deny",
            _ => "error",
        };

        JsonElement matrix = default;
        var hasMatrix = response.TryGetProperty("receipt", out var receipt)
            && receipt.TryGetProperty("metadata", out var metadata)
            && metadata.TryGetProperty("verdict_matrix", out matrix);

        string reasonCode;
        if (hasMatrix && matrix.TryGetProperty("reason_code", out var reasonEl)
            && reasonEl.ValueKind == JsonValueKind.String)
        {
            reasonCode = reasonEl.GetString() ?? ReasonKernelInternal;
        }
        else
        {
            reasonCode = ReasonFromVerdict(verdictTag, hasVerdict ? verdictObj : default);
        }

        var scopeSet = new List<string>();
        if (hasMatrix && matrix.TryGetProperty("scope_set", out var scopeEl)
            && scopeEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in scopeEl.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    scopeSet.Add(item.GetString() ?? string.Empty);
                }
            }
        }
        scopeSet.Sort(StringComparer.Ordinal);
        return new VerdictTuple(verdict, reasonCode, scopeSet);
    }

    private static string ReasonFromVerdict(string verdictTag, JsonElement verdictObj) =>
        verdictTag switch
        {
            "allow" => ReasonNone,
            "deny" => verdictObj.ValueKind == JsonValueKind.Object
                      && verdictObj.TryGetProperty("reason", out var reason)
                      && reason.ValueKind == JsonValueKind.String
                ? reason.GetString() ?? ReasonKernelInternal
                : ReasonKernelInternal,
            _ => ReasonKernelInternal,
        };

    private static ScenarioOutcome EvaluateScenario(
        HttpClient client,
        string baseUrl,
        string scenarioId,
        VerdictTuple expected,
        JsonElement script)
    {
        try
        {
            var body = ScenarioToHttpRequest(scenarioId, script);
            using var content = new StringContent(body, Encoding.UTF8, "application/json");
            using var message = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}{EvaluatePath}")
            {
                Content = content,
            };
            message.Headers.TryAddWithoutValidation("x-chio-capability", CapabilityTokenFor(scenarioId, script));
            using var response = client.Send(message);
            var responseBody = new StreamReader(response.Content.ReadAsStream()).ReadToEnd();
            if (!response.IsSuccessStatusCode)
            {
                return new ScenarioOutcome(scenarioId, "fail", expected, null,
                    $"sidecar returned {(int)response.StatusCode}: {responseBody}");
            }
            using var doc = JsonDocument.Parse(responseBody);
            var actual = Normalize(TupleFromEvaluateResponse(doc.RootElement));
            var pass = TupleEquals(actual, expected);
            return new ScenarioOutcome(
                scenarioId,
                pass ? "pass" : "fail",
                expected,
                actual,
                pass ? null : "tuple mismatch against sidecar verdict");
        }
        catch (Exception ex)
        {
            return new ScenarioOutcome(scenarioId, "fail", expected, null,
                $"sidecar POST failed: {ex.Message}");
        }
    }

    private static bool TupleEquals(VerdictTuple left, VerdictTuple right) =>
        left.Verdict == right.Verdict
        && left.ReasonCode == right.ReasonCode
        && left.ScopeSet.SequenceEqual(right.ScopeSet);

    public static DriverReport RunDriver(string scenarioRoot, string? sidecarUrl)
    {
        var scenarios = LoadScenarios(scenarioRoot);
        var sidecar = string.IsNullOrWhiteSpace(sidecarUrl) ? null : sidecarUrl.Trim().TrimEnd('/');
        HttpClient? client = sidecar is null
            ? null
            : new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        try
        {
            var outcomes = new List<ScenarioOutcome>();
            foreach (var scenario in scenarios)
            {
                if (!scenario.TryGetProperty("id", out var idEl))
                {
                    continue;
                }
                var id = idEl.GetString() ?? string.Empty;
                var expected = Normalize(scenario.TryGetProperty("expected", out var exp)
                    ? ParseTuple(exp)
                    : new VerdictTuple("error", ReasonKernelInternal, Array.Empty<string>()));

                if (sidecar is null || client is null)
                {
                    outcomes.Add(new ScenarioOutcome(id, "unsupported", expected, null,
                        $"set {SidecarEnv} (or {SidecarFallbackEnv}) to a live Chio sidecar; "
                        + "the dotnet SDK does not embed kernel evaluation"));
                    continue;
                }

                var category = scenario.TryGetProperty("category", out var catEl)
                    ? catEl.GetString() ?? string.Empty
                    : string.Empty;
                if (category is "capability" or "revocation")
                {
                    outcomes.Add(new ScenarioOutcome(id, "unsupported", expected, null,
                        "dotnet deployment-shape relay has no signed CapabilityToken builder; "
                        + $"sidecar evaluation of `{category}` scenarios requires issuer + signature + "
                        + "time-valid fields per chio-http-core::authority::validate_capability_token"));
                    continue;
                }

                var script = scenario.TryGetProperty("script", out var scriptEl)
                    ? scriptEl
                    : default;
                outcomes.Add(EvaluateScenario(client, sidecar, id, expected, script));
            }
            return new DriverReport(
                Driver: DriverName,
                MatrixRole: MatrixRole,
                UnderlyingDriver: UnderlyingDriver,
                Total: outcomes.Count,
                Passed: outcomes.Count(o => o.Status == "pass"),
                Failed: outcomes.Count(o => o.Status == "fail"),
                Unsupported: outcomes.Count(o => o.Status == "unsupported"),
                Outcomes: outcomes);
        }
        finally
        {
            client?.Dispose();
        }
    }
}

public sealed class DriverTests
{
    [Fact]
    public void DriverNameIsStable()
    {
        Assert.Equal("dotnet-sdk", Driver.DriverName);
        Assert.Equal("deployment-shape", Driver.MatrixRole);
        Assert.Equal("rust-kernel", Driver.UnderlyingDriver);
    }

    [Fact]
    public void ParseTupleSortsScopes()
    {
        using var doc = JsonDocument.Parse(
            "{\"verdict\":\"allow\",\"reason_code\":\"urn:chio:error:none\","
            + "\"scope_set\":[\"tool:write\",\"tool:read\"]}");
        var tuple = Driver.ParseTuple(doc.RootElement);
        Assert.Equal("allow", tuple.Verdict);
        Assert.Equal(new[] { "tool:read", "tool:write" }, tuple.ScopeSet);
    }

    [Fact]
    public void RunDriverReportsUnsupportedWithoutSidecar()
    {
        var root = Driver.ResolveScenarioRoot(Array.Empty<string>());
        if (!Directory.Exists(root))
        {
            // Test runs from arbitrary working directory in package distribution; skip when
            // corpus is not co-located.
            return;
        }
        var report = Driver.RunDriver(root, sidecarUrl: null);
        Assert.Equal("dotnet-sdk", report.Driver);
        Assert.True(report.Total > 0);
        Assert.Equal(report.Total, report.Unsupported);
        Assert.Equal(0, report.Passed);
        Assert.Equal(0, report.Failed);
        var first = report.Outcomes.FirstOrDefault();
        Assert.NotNull(first);
        Assert.Equal("unsupported", first!.Status);
        Assert.Contains("CHIO_VERDICT_MATRIX_SIDECAR_URL", first.Diagnostic ?? string.Empty);
    }

    [Fact]
    public void RunDriverRecordsFailWhenSidecarIsSetButUnreachable()
    {
        // A sidecar URL pointing at a closed port must surface as fail, never
        // a silent skip: a set-but-broken sidecar cannot pass.
        var root = Driver.ResolveScenarioRoot(Array.Empty<string>());
        if (!Directory.Exists(root))
        {
            return;
        }
        var report = Driver.RunDriver(root, sidecarUrl: "http://127.0.0.1:1");
        Assert.True(report.Total > 0);
        Assert.Equal(0, report.Unsupported);
        Assert.Equal(0, report.Passed);
        Assert.Equal(report.Total, report.Failed);
        Assert.Equal("fail", report.Outcomes.First().Status);
    }

    [Fact]
    public void DecodesAllowResponseWithMatrixMetadata()
    {
        using var doc = JsonDocument.Parse(
            "{\"verdict\":{\"verdict\":\"allow\"},\"receipt\":{\"metadata\":{\"verdict_matrix\":"
            + "{\"reason_code\":\"urn:chio:error:none\",\"scope_set\":[\"tool:write\",\"tool:read\"]}}}}");
        var tuple = Driver.TupleFromEvaluateResponse(doc.RootElement);
        Assert.Equal("allow", tuple.Verdict);
        Assert.Equal("urn:chio:error:none", tuple.ReasonCode);
        Assert.Equal(new[] { "tool:read", "tool:write" }, tuple.ScopeSet);
    }

    [Fact]
    public void DecodesDenyResponseFallsBackToReason()
    {
        using var doc = JsonDocument.Parse(
            "{\"verdict\":{\"verdict\":\"deny\",\"reason\":\"urn:chio:error:capability:revoked\","
            + "\"guard\":\"capability\"},\"receipt\":{\"metadata\":{}}}");
        var tuple = Driver.TupleFromEvaluateResponse(doc.RootElement);
        Assert.Equal("deny", tuple.Verdict);
        Assert.Equal("urn:chio:error:capability:revoked", tuple.ReasonCode);
        Assert.Empty(tuple.ScopeSet);
    }

    [Fact]
    public void HttpRequestSetsToolCallFieldsAndGetForRead()
    {
        using var script = JsonDocument.Parse(
            "{\"operation\":\"tool.call\",\"tool\":\"files.read\",\"input_json\":\"{}\","
            + "\"capability_scopes\":[\"tool:read\"]}");
        var body = Driver.ScenarioToHttpRequest("capability-subset-001-read-exact", script.RootElement);
        using var parsed = JsonDocument.Parse(body);
        Assert.Equal("GET", parsed.RootElement.GetProperty("method").GetString());
        Assert.Equal("verdict-matrix", parsed.RootElement.GetProperty("tool_server").GetString());
        Assert.Equal("files.read", parsed.RootElement.GetProperty("tool_name").GetString());
        // GET requests carry no body hash.
        Assert.False(parsed.RootElement.TryGetProperty("body_hash", out _));
    }
}
