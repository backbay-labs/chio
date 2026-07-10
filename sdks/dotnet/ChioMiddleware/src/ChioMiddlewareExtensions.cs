// ASP.NET Core middleware for Chio capability validation and receipt signing.
//
// Intercepts all HTTP requests, extracts caller identity, sends evaluation
// requests to the Chio sidecar kernel, and either allows the request to
// proceed with a verified signed receipt or returns a structured deny response.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.IO;

namespace Backbay.Chio;

/// <summary>
/// Configuration options for the Chio middleware.
/// </summary>
public class ChioMiddlewareOptions
{
    /// <summary>
    /// Base URL of the Chio sidecar kernel. Defaults to CHIO_SIDECAR_URL env var
    /// or "http://127.0.0.1:9090".
    /// </summary>
    public string SidecarUrl { get; set; } =
        Environment.GetEnvironmentVariable("CHIO_SIDECAR_URL") ?? "http://127.0.0.1:9090";

    /// <summary>
    /// HTTP timeout for sidecar calls in seconds. Default: 5.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 5;

    /// <summary>
    /// Reserved no-op option. The middleware always denies when the sidecar is
    /// unreachable.
    /// </summary>
    public string OnSidecarError { get; set; } = "deny";

    /// <summary>
    /// Custom identity extractor. Defaults to header-based extraction.
    /// </summary>
    public IdentityExtractorDelegate? IdentityExtractor { get; set; }

    /// <summary>
    /// Custom route pattern resolver. Maps (method, path) to a route pattern.
    /// Defaults to returning the raw path.
    /// </summary>
    public Func<string, string, string>? RouteResolver { get; set; }
}

/// <summary>
/// ASP.NET Core middleware that protects HTTP APIs with Chio evaluation.
/// </summary>
public class ChioProtectMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ChioSidecarClient _client;
    private readonly ChioMiddlewareOptions _options;
    private readonly IdentityExtractorDelegate _identityExtractor;
    private readonly Func<string, string, string> _routeResolver;
    private readonly ILogger<ChioProtectMiddleware> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    private static readonly HashSet<string> ValidMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
    };

    public ChioProtectMiddleware(
        RequestDelegate next,
        IOptions<ChioMiddlewareOptions> options,
        ILogger<ChioProtectMiddleware> logger)
    {
        _next = next;
        _options = options.Value;
        _client = new ChioSidecarClient(_options.SidecarUrl, _options.TimeoutSeconds);
        _identityExtractor = _options.IdentityExtractor ?? ChioIdentityExtractor.DefaultExtract;
        _routeResolver = _options.RouteResolver ?? ((_, path) => path);
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        };
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;
        var method = request.Method.ToUpperInvariant();

        if (!ValidMethods.Contains(method))
        {
            await WriteJsonError(context, 405, new ChioErrorResponse
            {
                Error = ChioErrorCodes.EvaluationFailed,
                Message = $"unsupported HTTP method: {method}",
            });
            return;
        }

        // Extract caller identity.
        var caller = _identityExtractor(request);

        // Resolve route pattern.
        var routePattern = _routeResolver(method, request.Path.Value ?? "/");

        // Hash request body.
        string? bodyHash = null;
        long bodyLength = 0;
        if (request.ContentLength.HasValue && request.ContentLength.Value > 0)
        {
            request.EnableBuffering();
            await using var buffer = new MemoryStream();
            await request.Body.CopyToAsync(buffer);
            var bodyBytes = buffer.ToArray();
            bodyLength = bodyBytes.LongLength;
            if (bodyBytes.Length > 0)
            {
                bodyHash = ChioIdentityExtractor.Sha256Hex(bodyBytes);
            }
            request.Body.Position = 0;
        }

        var capabilityToken = ResolveCapabilityToken(request);

        // Extract selected headers.
        var headers = new Dictionary<string, string>();
        foreach (var headerName in new[] { "content-type", "content-length" })
        {
            if (request.Headers.TryGetValue(headerName, out var values))
            {
                var val = values.FirstOrDefault();
                if (val != null)
                    headers[headerName] = val;
            }
        }

        // Build Chio HTTP request.
        var chioRequest = new ChioHttpRequest
        {
            RequestId = Guid.NewGuid().ToString(),
            Method = method,
            RoutePattern = routePattern,
            Path = request.Path.Value ?? "/",
            Query = request.Query.ToDictionary(q => q.Key, q => q.Value.FirstOrDefault() ?? ""),
            Headers = headers,
            Caller = caller,
            BodyHash = bodyHash,
            BodyLength = bodyLength,
            CapabilityId = CapabilityIdFromToken(capabilityToken),
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };

        // Evaluate against sidecar.
        EvaluateResponse result;
        try
        {
            result = await _client.EvaluateAsync(chioRequest, capabilityToken);
        }
        catch (ChioSidecarException ex)
        {
            _logger.LogError(ex, "Chio sidecar error");
            if (ex.Code == ChioErrorCodes.InvalidReceipt)
            {
                await WriteJsonError(context, 502, new ChioErrorResponse
                {
                    Error = ChioErrorCodes.InvalidReceipt,
                    Message = $"Chio sidecar receipt verification failed: {ex.Message}",
                });
                return;
            }
            await WriteJsonError(context, 502, new ChioErrorResponse
            {
                Error = ChioErrorCodes.SidecarUnreachable,
                Message = $"Chio sidecar error: {ex.Message}",
            });
            return;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Chio sidecar error");
            await WriteJsonError(context, 502, new ChioErrorResponse
            {
                Error = ChioErrorCodes.SidecarUnreachable,
                Message = $"Chio sidecar error: {ex.Message}",
            });
            return;
        }

        // Check verdicts. Anything other than explicit allow from both the
        // response and embedded receipt fails closed.
        if (!result.Verdict.IsAllowed() || !result.Receipt.IsAuthorized())
        {
            var status = result.Verdict.HttpStatus > 0 ? result.Verdict.HttpStatus : 403;
            await WriteJsonError(context, status, new ChioErrorResponse
            {
                Error = ChioErrorCodes.AccessDenied,
                Message = result.Verdict.Reason ?? "denied",
                ReceiptId = result.Receipt.Id,
                Suggestion = "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter",
            });
            return;
        }

        // Attach receipt ID after authorization and receipt verification.
        context.Response.Headers["X-Chio-Receipt-Id"] = result.Receipt.Id;

        // Request allowed and verified -- forward to next middleware.
        await _next(context);
    }

    private async Task WriteJsonError(HttpContext context, int statusCode, ChioErrorResponse error)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(error, _jsonOptions);
    }

    private static string? CapabilityIdFromToken(string? rawToken)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(rawToken);
            return doc.RootElement.TryGetProperty("id", out var idElement)
                && idElement.ValueKind == JsonValueKind.String
                ? idElement.GetString()
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? ResolveCapabilityToken(HttpRequest request)
    {
        if (request.Headers.TryGetValue("X-Chio-Capability", out var capabilityValues))
        {
            var headerToken = capabilityValues.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(headerToken))
            {
                return headerToken;
            }
        }

        return request.Query.TryGetValue("chio_capability", out var queryCapability)
            ? queryCapability.FirstOrDefault()
            : null;
    }
}

/// <summary>
/// Extension methods for registering Chio middleware.
/// </summary>
public static class ChioMiddlewareExtensions
{
    /// <summary>
    /// Add Chio middleware services to the dependency injection container.
    /// </summary>
    public static IServiceCollection AddChioProtection(
        this IServiceCollection services,
        Action<ChioMiddlewareOptions>? configure = null)
    {
        if (configure != null)
        {
            services.Configure(configure);
        }
        else
        {
            services.Configure<ChioMiddlewareOptions>(_ => { });
        }
        return services;
    }

    /// <summary>
    /// Use Chio protection middleware in the request pipeline.
    /// </summary>
    public static IApplicationBuilder UseChioProtection(this IApplicationBuilder app)
    {
        return app.UseMiddleware<ChioProtectMiddleware>();
    }
}
