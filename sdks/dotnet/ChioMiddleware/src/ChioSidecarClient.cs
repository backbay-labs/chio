// Chio sidecar HTTP client for .NET.
//
// Communicates with the Chio Rust kernel running as a localhost sidecar.
// Sends evaluation requests over HTTP and returns signed receipts.

using System.Net.Http.Json;
using System.Text.Json;

namespace Backbay.Chio;

/// <summary>
/// Exception thrown when the Chio sidecar is unreachable or returns an error.
/// </summary>
public class ChioSidecarException : Exception
{
    public string Code { get; }
    public int? StatusCode { get; }

    public ChioSidecarException(string code, string message, int? statusCode = null)
        : base(message)
    {
        Code = code;
        StatusCode = statusCode;
    }
}

/// <summary>
/// Chio sidecar client. Sends evaluation requests to the Rust kernel.
/// </summary>
public class ChioSidecarClient : IDisposable
{
    public const string DefaultSidecarUrl = "http://127.0.0.1:9090";

    private readonly string _baseUrl;
    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions;

    public ChioSidecarClient(string? baseUrl = null, int timeoutSeconds = 5)
    {
        _baseUrl = (baseUrl ?? Environment.GetEnvironmentVariable("CHIO_SIDECAR_URL") ?? DefaultSidecarUrl)
            .TrimEnd('/');
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(timeoutSeconds)
        };
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        };
    }

    /// <summary>
    /// Evaluate an HTTP request against the Chio kernel.
    /// </summary>
    public async Task<EvaluateResponse> EvaluateAsync(ChioHttpRequest request, string? capabilityToken = null)
    {
        HttpResponseMessage response;
        try
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}/chio/evaluate")
            {
                Content = JsonContent.Create(request, options: _jsonOptions)
            };
            if (!string.IsNullOrWhiteSpace(capabilityToken))
            {
                message.Headers.Add("X-Chio-Capability", capabilityToken);
            }
            response = await _httpClient.SendAsync(message);
        }
        catch (Exception ex)
        {
            throw new ChioSidecarException(
                ChioErrorCodes.SidecarUnreachable,
                $"Failed to reach Chio sidecar at {_baseUrl}: {ex.Message}"
            );
        }

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();
            throw new ChioSidecarException(
                ChioErrorCodes.EvaluationFailed,
                $"Sidecar returned {(int)response.StatusCode}: {body}",
                (int)response.StatusCode
            );
        }

        var result = await response.Content.ReadFromJsonAsync<EvaluateResponse>(_jsonOptions);
        if (result is null)
        {
            throw new ChioSidecarException(
                ChioErrorCodes.EvaluationFailed,
                "Sidecar returned null response"
            );
        }
        if (result.Verdict.IsAllowed() || result.Receipt.Verdict.IsAllowed())
        {
            if (!result.Verdict.IsAllowed() || !result.Receipt.IsAuthorized())
            {
                throw new ChioSidecarException(
                    ChioErrorCodes.InvalidReceipt,
                    "Sidecar returned an allow-shaped response without mediated receipt authorization"
                );
            }
            var verification = await VerifyReceiptAsync(result.Receipt);
            if (!verification.Authorizes(result.Receipt))
            {
                throw new ChioSidecarException(
                    ChioErrorCodes.InvalidReceipt,
                    "Sidecar returned an unverified receipt"
                );
            }
        }
        return result;
    }

    /// <summary>
    /// Verify a receipt authority result against the sidecar.
    /// </summary>
    public async Task<VerifyReceiptResponse> VerifyReceiptAsync(HttpReceipt receipt)
    {
        try
        {
            var response = await _httpClient.PostAsJsonAsync(
                $"{_baseUrl}/chio/verify",
                receipt,
                _jsonOptions
            );

            if (!response.IsSuccessStatusCode)
                return new VerifyReceiptResponse();

            return await response.Content.ReadFromJsonAsync<VerifyReceiptResponse>(_jsonOptions)
                ?? new VerifyReceiptResponse();
        }
        catch
        {
            return new VerifyReceiptResponse();
        }
    }

    /// <summary>
    /// Health check for the sidecar.
    /// </summary>
    public async Task<bool> HealthCheckAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync($"{_baseUrl}/chio/health");
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        _httpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}
