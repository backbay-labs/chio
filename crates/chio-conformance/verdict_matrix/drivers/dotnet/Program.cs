// M07.P6.T2: dotnet SDK verdict-matrix driver entry point.
//
// Loads the canonical scenario corpus from
// crates/chio-conformance/verdict_matrix/scenarios/ and emits a JSON report
// on stdout shaped as (verdict, reason_code, scope_set) per scenario. The
// deployment-shape driver does not embed kernel evaluation; it mirrors the
// trajectory-1 TypeScript node-http driver contract by reading an operator-
// supplied Chio sidecar URL from CHIO_VERDICT_MATRIX_SIDECAR_URL (with
// CHIO_SIDECAR_URL fallback). When the variable is absent, every scenario is
// reported as unsupported with a diagnostic that names the missing variable.
// The trajectory-1 sdks/dotnet/ChioMiddleware package provides the host
// kernel bindings the driver invokes through the sidecar; the binding wiring
// lands in a follow-on operator-tactical ticket and is out of M07.P6.T2 scope.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
            ? r.GetString() ?? "urn:chio:error:kernel:internal-error"
            : "urn:chio:error:kernel:internal-error";
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

    public static DriverReport RunDriver(string scenarioRoot, string? sidecarUrl)
    {
        var scenarios = LoadScenarios(scenarioRoot);
        var outcomes = new List<ScenarioOutcome>();
        foreach (var scenario in scenarios)
        {
            if (!scenario.TryGetProperty("id", out var idEl))
            {
                continue;
            }
            var id = idEl.GetString() ?? string.Empty;
            var expected = scenario.TryGetProperty("expected", out var exp)
                ? ParseTuple(exp)
                : new VerdictTuple("error", "urn:chio:error:kernel:internal-error", Array.Empty<string>());
            var diagnostic = string.IsNullOrWhiteSpace(sidecarUrl)
                ? $"set {SidecarEnv} (or {SidecarFallbackEnv}) to a live Chio sidecar; "
                  + "the dotnet SDK does not embed kernel evaluation"
                : "dotnet SDK driver sidecar wiring is operator-tactical; the M07.P6.T2 "
                  + "scaffold registers the driver shape only";
            outcomes.Add(new ScenarioOutcome(id, "unsupported", expected, null, diagnostic));
        }
        var unsupported = outcomes.Count(o => o.Status == "unsupported");
        return new DriverReport(
            Driver: DriverName,
            MatrixRole: MatrixRole,
            UnderlyingDriver: UnderlyingDriver,
            Total: outcomes.Count,
            Passed: outcomes.Count(o => o.Status == "pass"),
            Failed: outcomes.Count(o => o.Status == "fail"),
            Unsupported: unsupported,
            Outcomes: outcomes);
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
}
