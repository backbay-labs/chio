// Core types for the Chio HTTP substrate.
//
// These types mirror the Rust chio-http-core crate and define the contract
// between .NET middleware and the Chio sidecar kernel.

using System.Text.Json.Serialization;

namespace Backbay.Chio;

/// <summary>
/// How the caller authenticated to the upstream API.
/// </summary>
public class AuthMethod
{
    [JsonPropertyName("method")]
    public string Method { get; set; } = "anonymous";

    [JsonPropertyName("token_hash")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenHash { get; set; }

    [JsonPropertyName("key_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeyName { get; set; }

    [JsonPropertyName("key_hash")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeyHash { get; set; }

    [JsonPropertyName("cookie_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CookieName { get; set; }

    [JsonPropertyName("cookie_hash")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CookieHash { get; set; }

    [JsonPropertyName("subject_dn")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SubjectDn { get; set; }

    [JsonPropertyName("fingerprint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Fingerprint { get; set; }

    public static AuthMethod Anonymous() => new() { Method = "anonymous" };

    public static AuthMethod Bearer(string tokenHash) =>
        new() { Method = "bearer", TokenHash = tokenHash };

    public static AuthMethod ApiKey(string keyName, string keyHash) =>
        new() { Method = "api_key", KeyName = keyName, KeyHash = keyHash };
}

/// <summary>
/// The identity of the caller as extracted from the HTTP request.
/// </summary>
public class CallerIdentity
{
    [JsonPropertyName("subject")]
    public string Subject { get; set; } = "anonymous";

    [JsonPropertyName("auth_method")]
    public AuthMethod AuthMethod { get; set; } = AuthMethod.Anonymous();

    [JsonPropertyName("verified")]
    public bool Verified { get; set; }

    [JsonPropertyName("tenant")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Tenant { get; set; }

    [JsonPropertyName("agent_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AgentId { get; set; }

    public static CallerIdentity CreateAnonymous() =>
        new() { Subject = "anonymous", AuthMethod = AuthMethod.Anonymous() };
}

/// <summary>
/// The kernel's evaluation verdict.
/// </summary>
public class Verdict
{
    [JsonPropertyName("verdict")]
    public string VerdictType { get; set; } = "";

    [JsonPropertyName("reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Reason { get; set; }

    [JsonPropertyName("guard")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Guard { get; set; }

    [JsonPropertyName("http_status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int HttpStatus { get; set; }

    public bool IsAllowed() => VerdictType == "allow";
    public bool IsDenied() => VerdictType == "deny";

    public static Verdict Allow() => new() { VerdictType = "allow" };

    public static Verdict Deny(string reason, string guard, int httpStatus = 403) =>
        new() { VerdictType = "deny", Reason = reason, Guard = guard, HttpStatus = httpStatus };
}

/// <summary>
/// Per-guard evaluation evidence.
/// </summary>
public class GuardEvidence
{
    [JsonPropertyName("guard_name")]
    public string GuardName { get; set; } = "";

    [JsonPropertyName("verdict")]
    public bool VerdictResult { get; set; }

    [JsonPropertyName("details")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Details { get; set; }
}

/// <summary>
/// Signed receipt for an HTTP request evaluation.
/// </summary>
public class HttpReceipt
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("request_id")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("route_pattern")]
    public string RoutePattern { get; set; } = "";

    [JsonPropertyName("method")]
    public string Method { get; set; } = "";

    [JsonPropertyName("caller_identity_hash")]
    public string CallerIdentityHash { get; set; } = "";

    [JsonPropertyName("session_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SessionId { get; set; }

    [JsonPropertyName("verdict")]
    public Verdict Verdict { get; set; } = new();

    [JsonPropertyName("receipt_kind")]
    public string ReceiptKind { get; set; } = "";

    [JsonPropertyName("boundary_class")]
    public string BoundaryClass { get; set; } = "";

    [JsonPropertyName("observation_outcome")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ObservationOutcome { get; set; }

    [JsonPropertyName("tool_origin")]
    public string ToolOrigin { get; set; } = "";

    [JsonPropertyName("redaction_mode")]
    public string RedactionMode { get; set; } = "";

    [JsonPropertyName("actor_chain")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<Dictionary<string, object?>>? ActorChain { get; set; }

    [JsonPropertyName("evidence")]
    public List<GuardEvidence> Evidence { get; set; } = new();

    [JsonPropertyName("response_status")]
    public int ResponseStatus { get; set; }

    [JsonPropertyName("timestamp")]
    public long Timestamp { get; set; }

    [JsonPropertyName("content_hash")]
    public string ContentHash { get; set; } = "";

    [JsonPropertyName("policy_hash")]
    public string PolicyHash { get; set; } = "";

    [JsonPropertyName("trust_level")]
    public string TrustLevel { get; set; } = "";

    [JsonPropertyName("capability_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CapabilityId { get; set; }

    [JsonPropertyName("metadata")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Metadata { get; set; }

    [JsonPropertyName("kernel_key")]
    public string KernelKey { get; set; } = "";

    [JsonPropertyName("signature")]
    public string Signature { get; set; } = "";

    public bool IsAuthorized() =>
        ReceiptKind == "mediated_decision" &&
        BoundaryClass == "prevent" &&
        ObservationOutcome is null &&
        TrustLevel == "mediated" &&
        Verdict.IsAllowed();
}

/// <summary>
/// HTTP request sent to the Chio sidecar for evaluation.
/// </summary>
public class ChioHttpRequest
{
    [JsonPropertyName("request_id")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("method")]
    public string Method { get; set; } = "";

    [JsonPropertyName("route_pattern")]
    public string RoutePattern { get; set; } = "";

    [JsonPropertyName("path")]
    public string Path { get; set; } = "";

    [JsonPropertyName("query")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Query { get; set; }

    [JsonPropertyName("headers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Headers { get; set; }

    [JsonPropertyName("caller")]
    public CallerIdentity Caller { get; set; } = CallerIdentity.CreateAnonymous();

    [JsonPropertyName("body_hash")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BodyHash { get; set; }

    [JsonPropertyName("body_length")]
    public long BodyLength { get; set; }

    [JsonPropertyName("session_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SessionId { get; set; }

    [JsonPropertyName("capability_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CapabilityId { get; set; }

    [JsonPropertyName("timestamp")]
    public long Timestamp { get; set; }
}

/// <summary>
/// Sidecar evaluation response.
/// </summary>
public class EvaluateResponse
{
    [JsonPropertyName("verdict")]
    public Verdict Verdict { get; set; } = new();

    [JsonPropertyName("receipt")]
    public HttpReceipt Receipt { get; set; } = new();

    [JsonPropertyName("evidence")]
    public List<GuardEvidence> Evidence { get; set; } = new();
}

/// <summary>
/// Structured authority result returned by /chio/verify.
/// </summary>
public class VerifyReceiptResponse
{
    [JsonPropertyName("signature_valid")]
    public bool SignatureValid { get; set; }

    [JsonPropertyName("signer_trusted")]
    public bool SignerTrusted { get; set; }

    [JsonPropertyName("receipt_id_valid")]
    public bool ReceiptIdValid { get; set; }

    [JsonPropertyName("parameter_hash_valid")]
    public bool ParameterHashValid { get; set; }

    [JsonPropertyName("receipt_kind")]
    public string ReceiptKind { get; set; } = "";

    [JsonPropertyName("boundary_class")]
    public string BoundaryClass { get; set; } = "";

    [JsonPropertyName("trust_level")]
    public string TrustLevel { get; set; } = "";

    [JsonPropertyName("result")]
    public string Result { get; set; } = "";

    [JsonPropertyName("authorized")]
    public bool Authorized { get; set; }

    [JsonPropertyName("signer_key_hex")]
    public string SignerKeyHex { get; set; } = "";

    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    public bool Authorizes(HttpReceipt receipt) =>
        Ok &&
        Authorized &&
        SignatureValid &&
        SignerTrusted &&
        ReceiptIdValid &&
        ParameterHashValid &&
        ReceiptKind == "mediated_decision" &&
        BoundaryClass == "prevent" &&
        TrustLevel == "mediated" &&
        Result == "allow" &&
        receipt.IsAuthorized() &&
        IsLowerHex64(receipt.Id) &&
        IsLowerHex64(receipt.ContentHash) &&
        !string.IsNullOrWhiteSpace(receipt.Signature);

    private static bool IsLowerHex64(string value)
    {
        if (value.Length != 64)
        {
            return false;
        }
        foreach (var ch in value)
        {
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
            {
                return false;
            }
        }
        return true;
    }
}

/// <summary>
/// Reserved degraded state marker. The middleware always fails closed.
/// </summary>
public class ChioPassthrough
{
    [JsonPropertyName("mode")]
    public string Mode { get; set; } = "allow_without_receipt";

    [JsonPropertyName("error")]
    public string Error { get; set; } = ChioErrorCodes.SidecarUnreachable;

    [JsonPropertyName("message")]
    public string Message { get; set; } = "";
}

/// <summary>
/// Structured error response body.
/// </summary>
public class ChioErrorResponse
{
    [JsonPropertyName("error")]
    public string Error { get; set; } = "";

    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("receipt_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ReceiptId { get; set; }

    [JsonPropertyName("suggestion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Suggestion { get; set; }
}

/// <summary>
/// Chio error codes.
/// </summary>
public static class ChioErrorCodes
{
    public const string AccessDenied = "chio_access_denied";
    public const string SidecarUnreachable = "chio_sidecar_unreachable";
    public const string EvaluationFailed = "chio_evaluation_failed";
    public const string InvalidReceipt = "chio_invalid_receipt";
    public const string Timeout = "chio_timeout";
}

public static class ChioContextKeys
{
    public const string Passthrough = "ChioPassthrough";
}
