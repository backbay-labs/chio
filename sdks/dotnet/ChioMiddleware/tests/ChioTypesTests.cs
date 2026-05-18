// Conformance tests for Chio .NET types.
//
// Validates that .NET types serialize to the same JSON structure as the
// Rust kernel types (shared test vectors).

using System.Text.Json;
using Backbay.Chio;
using Xunit;

namespace Backbay.Chio.Tests;

public class ChioTypesTests
{
    private static readonly string ReceiptId = new('a', 64);
    private static readonly string ContentHash = new('b', 64);

    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    [Fact]
    public void VerdictDefaultIsNotAllow()
    {
        var verdict = new Verdict();
        Assert.False(verdict.IsAllowed());
        Assert.False(verdict.IsDenied());
    }

    [Fact]
    public void VerdictAllow_Serialization()
    {
        var verdict = Verdict.Allow();
        var json = JsonSerializer.Serialize(verdict, _jsonOptions);
        Assert.Contains("\"verdict\":\"allow\"", json);

        var back = JsonSerializer.Deserialize<Verdict>(json, _jsonOptions);
        Assert.NotNull(back);
        Assert.True(back.IsAllowed());
        Assert.False(back.IsDenied());
    }

    [Fact]
    public void VerdictDeny_Serialization()
    {
        var verdict = Verdict.Deny("no capability", "CapabilityGuard", 403);
        var json = JsonSerializer.Serialize(verdict, _jsonOptions);
        Assert.Contains("\"verdict\":\"deny\"", json);
        Assert.Contains("\"reason\":\"no capability\"", json);
        Assert.Contains("\"guard\":\"CapabilityGuard\"", json);
        Assert.Contains("\"http_status\":403", json);

        var back = JsonSerializer.Deserialize<Verdict>(json, _jsonOptions);
        Assert.NotNull(back);
        Assert.True(back.IsDenied());
        Assert.Equal("no capability", back.Reason);
    }

    [Fact]
    public void CallerIdentityAnonymous_Serialization()
    {
        var caller = CallerIdentity.CreateAnonymous();
        var json = JsonSerializer.Serialize(caller, _jsonOptions);
        Assert.Contains("\"subject\":\"anonymous\"", json);
        Assert.Contains("\"method\":\"anonymous\"", json);
        Assert.Contains("\"verified\":false", json);

        var back = JsonSerializer.Deserialize<CallerIdentity>(json, _jsonOptions);
        Assert.NotNull(back);
        Assert.Equal("anonymous", back.Subject);
        Assert.False(back.Verified);
    }

    [Fact]
    public void CallerIdentityBearer_Serialization()
    {
        var caller = new CallerIdentity
        {
            Subject = "bearer:abc123",
            AuthMethod = AuthMethod.Bearer("abc123def456"),
        };
        var json = JsonSerializer.Serialize(caller, _jsonOptions);
        Assert.Contains("\"subject\":\"bearer:abc123\"", json);
        Assert.Contains("\"method\":\"bearer\"", json);
        Assert.Contains("\"token_hash\":\"abc123def456\"", json);

        var back = JsonSerializer.Deserialize<CallerIdentity>(json, _jsonOptions);
        Assert.NotNull(back);
        Assert.Equal("bearer:abc123", back.Subject);
        Assert.Equal("bearer", back.AuthMethod.Method);
    }

    [Fact]
    public void ChioHttpRequest_Serialization()
    {
        var request = new ChioHttpRequest
        {
            RequestId = "req-001",
            Method = "GET",
            RoutePattern = "/pets/{petId}",
            Path = "/pets/42",
            Query = new Dictionary<string, string> { { "verbose", "true" } },
            Caller = CallerIdentity.CreateAnonymous(),
            Timestamp = 1700000000,
        };
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        Assert.Contains("\"request_id\":\"req-001\"", json);
        Assert.Contains("\"method\":\"GET\"", json);
        Assert.Contains("\"route_pattern\":\"/pets/{petId}\"", json);
        Assert.Contains("\"timestamp\":1700000000", json);

        var back = JsonSerializer.Deserialize<ChioHttpRequest>(json, _jsonOptions);
        Assert.NotNull(back);
        Assert.Equal("req-001", back.RequestId);
        Assert.Equal("/pets/{petId}", back.RoutePattern);
    }

    [Fact]
    public void HttpReceipt_SerializationRoundtrip()
    {
        var receipt = new HttpReceipt
        {
            Id = ReceiptId,
            RequestId = "req-001",
            RoutePattern = "/pets/{petId}",
            Method = "GET",
            CallerIdentityHash = "abc123",
            Verdict = Verdict.Allow(),
            ReceiptKind = "mediated_decision",
            BoundaryClass = "prevent",
            ToolOrigin = "caller_executed",
            RedactionMode = "none",
            TrustLevel = "mediated",
            Evidence = new List<GuardEvidence>(),
            ResponseStatus = 200,
            Timestamp = 1700000000,
            ContentHash = ContentHash,
            PolicyHash = "cafebabe",
            KernelKey = "test-key",
            Signature = "test-sig",
        };

        var json = JsonSerializer.Serialize(receipt, _jsonOptions);
        var back = JsonSerializer.Deserialize<HttpReceipt>(json, _jsonOptions);
        Assert.NotNull(back);
        Assert.Equal(ReceiptId, back.Id);
        Assert.True(back.Verdict.IsAllowed());
        Assert.True(back.IsAuthorized());
        Assert.Equal(200, back.ResponseStatus);
    }

    [Fact]
    public void GuardEvidence_Serialization()
    {
        var evidence = new GuardEvidence
        {
            GuardName = "CapabilityGuard",
            VerdictResult = true,
            Details = "capability token presented",
        };
        var json = JsonSerializer.Serialize(evidence, _jsonOptions);
        Assert.Contains("\"guard_name\":\"CapabilityGuard\"", json);
        Assert.Contains("\"verdict\":true", json);

        var back = JsonSerializer.Deserialize<GuardEvidence>(json, _jsonOptions);
        Assert.NotNull(back);
        Assert.Equal("CapabilityGuard", back.GuardName);
        Assert.True(back.VerdictResult);
    }

    [Fact]
    public void Sha256Hex_KnownVector()
    {
        var hash = ChioIdentityExtractor.Sha256Hex("");
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
    }

    [Fact]
    public void EvaluateResponse_Deserialization()
    {
        var json = """
        {
            "verdict": {"verdict": "allow"},
            "receipt": {
                "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "request_id": "req-001",
                "route_pattern": "/pets",
                "method": "GET",
                "caller_identity_hash": "hash",
                "verdict": {"verdict": "allow"},
                "receipt_kind": "mediated_decision",
                "boundary_class": "prevent",
                "tool_origin": "caller_executed",
                "redaction_mode": "none",
                "trust_level": "mediated",
                "evidence": [],
                "response_status": 200,
                "timestamp": 1700000000,
                "content_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "policy_hash": "def",
                "kernel_key": "key",
                "signature": "sig"
            },
            "evidence": []
        }
        """;

        var response = JsonSerializer.Deserialize<EvaluateResponse>(json, _jsonOptions);
        Assert.NotNull(response);
        Assert.True(response.Verdict.IsAllowed());
        Assert.True(response.Receipt.IsAuthorized());
        Assert.Equal(ReceiptId, response.Receipt.Id);
    }

    [Fact]
    public void VerifyReceiptResponseAuthorizesRequiresFullAuthorityTuple()
    {
        var receipt = new HttpReceipt
        {
            Id = ReceiptId,
            RequestId = "req-001",
            RoutePattern = "/pets",
            Method = "GET",
            CallerIdentityHash = "hash",
            Verdict = Verdict.Allow(),
            ReceiptKind = "mediated_decision",
            BoundaryClass = "prevent",
            ToolOrigin = "caller_executed",
            RedactionMode = "none",
            TrustLevel = "mediated",
            ResponseStatus = 200,
            Timestamp = 1700000000,
            ContentHash = ContentHash,
            PolicyHash = "policy",
            KernelKey = "key",
            Signature = "signature",
        };
        var response = new VerifyReceiptResponse
        {
            Ok = true,
            Authorized = true,
            SignatureValid = true,
            SignerTrusted = true,
            ReceiptIdValid = true,
            ParameterHashValid = true,
            ReceiptKind = "mediated_decision",
            BoundaryClass = "prevent",
            TrustLevel = "mediated",
            Result = "allow",
            SignerKeyHex = new string('d', 64),
        };

        Assert.True(response.Authorizes(receipt));
        response.SignatureValid = false;
        Assert.False(response.Authorizes(receipt));
    }

    [Fact]
    public void ErrorResponse_Serialization()
    {
        var error = new ChioErrorResponse
        {
            Error = ChioErrorCodes.AccessDenied,
            Message = "no capability",
            ReceiptId = "receipt-001",
            Suggestion = "provide a valid capability token",
        };
        var json = JsonSerializer.Serialize(error, _jsonOptions);
        Assert.Contains("\"error\":\"chio_access_denied\"", json);
        Assert.Contains("\"receipt_id\":\"receipt-001\"", json);
    }

    [Fact]
    public void AuthMethod_StaticFactories()
    {
        var anon = AuthMethod.Anonymous();
        Assert.Equal("anonymous", anon.Method);
        Assert.Null(anon.TokenHash);

        var bearer = AuthMethod.Bearer("hash123");
        Assert.Equal("bearer", bearer.Method);
        Assert.Equal("hash123", bearer.TokenHash);

        var apiKey = AuthMethod.ApiKey("X-API-Key", "keyhash");
        Assert.Equal("api_key", apiKey.Method);
        Assert.Equal("X-API-Key", apiKey.KeyName);
        Assert.Equal("keyhash", apiKey.KeyHash);
    }

    [Fact]
    public void ErrorCodes_Constants()
    {
        Assert.Equal("chio_access_denied", ChioErrorCodes.AccessDenied);
        Assert.Equal("chio_sidecar_unreachable", ChioErrorCodes.SidecarUnreachable);
        Assert.Equal("chio_evaluation_failed", ChioErrorCodes.EvaluationFailed);
        Assert.Equal("chio_invalid_receipt", ChioErrorCodes.InvalidReceipt);
        Assert.Equal("chio_timeout", ChioErrorCodes.Timeout);
    }
}
