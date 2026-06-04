using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Backbay.Chio;
using Xunit;

namespace Backbay.Chio.Tests;

public class ChioMiddlewareCapabilityTests
{
    private static readonly string ReceiptId = new('a', 64);
    private static readonly string ContentHash = new('b', 64);

    private static string StructuredVerifyResponse(bool authorized)
    {
        var truth = authorized ? "true" : "false";
        var result = authorized ? "allow" : "deny";
        return $$"""
        {
          "signature_valid": {{truth}},
          "signer_trusted": {{truth}},
          "receipt_id_valid": {{truth}},
          "parameter_hash_valid": {{truth}},
          "receipt_kind": "mediated_decision",
          "boundary_class": "prevent",
          "trust_level": "mediated",
          "result": "{{result}}",
          "authorized": {{truth}},
          "signer_key_hex": "{{new string('d', 64)}}",
          "ok": {{truth}}
        }
        """;
    }

    [Fact]
    public async Task QueryCapabilityTokenIsForwardedToSidecar()
    {
        var port = GetFreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        var observedCapability = "";
        var sidecarTask = Task.Run(async () =>
        {
            var requestContext = await listener.GetContextAsync();
            observedCapability = requestContext.Request.Headers["X-Chio-Capability"] ?? "";

            var responseJson = $$"""
            {
              "verdict": { "verdict": "allow" },
              "receipt": {
                "id": "{{ReceiptId}}",
                "request_id": "req-1",
                "route_pattern": "/pets",
                "method": "GET",
                "caller_identity_hash": "hash",
                "verdict": { "verdict": "allow" },
                "receipt_kind": "mediated_decision",
                "boundary_class": "prevent",
                "tool_origin": "caller_executed",
                "redaction_mode": "none",
                "trust_level": "mediated",
                "evidence": [],
                "response_status": 200,
                "timestamp": 1700000000,
                "content_hash": "{{ContentHash}}",
                "policy_hash": "policy",
                "kernel_key": "kernel",
                "signature": "signature"
              },
              "evidence": []
            }
            """;

            var bytes = Encoding.UTF8.GetBytes(responseJson);
            requestContext.Response.StatusCode = 200;
            requestContext.Response.ContentType = "application/json";
            await requestContext.Response.OutputStream.WriteAsync(bytes);
            requestContext.Response.Close();

            var verifyContext = await listener.GetContextAsync();
            var verifyBytes = Encoding.UTF8.GetBytes(StructuredVerifyResponse(true));
            verifyContext.Response.StatusCode = 200;
            verifyContext.Response.ContentType = "application/json";
            await verifyContext.Response.OutputStream.WriteAsync(verifyBytes);
            verifyContext.Response.Close();
        });

        var middleware = new ChioProtectMiddleware(
            next: context =>
            {
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return Task.CompletedTask;
            },
            options: Options.Create(new ChioMiddlewareOptions
            {
                SidecarUrl = $"http://127.0.0.1:{port}",
            }),
            logger: NullLogger<ChioProtectMiddleware>.Instance
        );

        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = "/pets";
        context.Request.QueryString = new QueryString("?chio_capability=query-token");

        await middleware.InvokeAsync(context);
        await sidecarTask;

        Assert.Equal("query-token", observedCapability);
        Assert.Equal(ReceiptId, context.Response.Headers["X-Chio-Receipt-Id"]);
        Assert.Equal(StatusCodes.Status204NoContent, context.Response.StatusCode);
    }

    [Fact]
    public async Task LegacyFailOpenSettingStillFailsClosed()
    {
        var nextCalled = false;
        var middleware = new ChioProtectMiddleware(
            next: context =>
            {
                nextCalled = true;
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return Task.CompletedTask;
            },
            options: Options.Create(new ChioMiddlewareOptions
            {
                SidecarUrl = "http://127.0.0.1:1",
                OnSidecarError = "allow",
                TimeoutSeconds = 1,
            }),
            logger: NullLogger<ChioProtectMiddleware>.Instance
        );

        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = "/pets";

        await middleware.InvokeAsync(context);

        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status502BadGateway, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("X-Chio-Receipt-Id"));
    }

    [Fact]
    public async Task SidecarClientRejectsUnverifiedAllow()
    {
        var port = GetFreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        var sidecarTask = Task.Run(async () =>
        {
            var requestContext = await listener.GetContextAsync();
            var responseJson = $$"""
            {
              "verdict": { "verdict": "allow" },
              "receipt": {
                "id": "{{ReceiptId}}",
                "request_id": "req-1",
                "route_pattern": "/pets",
                "method": "GET",
                "caller_identity_hash": "hash",
                "verdict": { "verdict": "allow" },
                "receipt_kind": "mediated_decision",
                "boundary_class": "prevent",
                "tool_origin": "caller_executed",
                "redaction_mode": "none",
                "trust_level": "mediated",
                "evidence": [],
                "response_status": 200,
                "timestamp": 1700000000,
                "content_hash": "{{ContentHash}}",
                "policy_hash": "policy",
                "kernel_key": "kernel",
                "signature": "signature"
              },
              "evidence": []
            }
            """;
            var bytes = Encoding.UTF8.GetBytes(responseJson);
            requestContext.Response.StatusCode = 200;
            requestContext.Response.ContentType = "application/json";
            await requestContext.Response.OutputStream.WriteAsync(bytes);
            requestContext.Response.Close();

            var verifyContext = await listener.GetContextAsync();
            var verifyBytes = Encoding.UTF8.GetBytes(StructuredVerifyResponse(false));
            verifyContext.Response.StatusCode = 200;
            verifyContext.Response.ContentType = "application/json";
            await verifyContext.Response.OutputStream.WriteAsync(verifyBytes);
            verifyContext.Response.Close();
        });

        using var client = new ChioSidecarClient($"http://127.0.0.1:{port}");
        var request = new ChioHttpRequest
        {
            RequestId = "req-1",
            Method = "GET",
            RoutePattern = "/pets",
            Path = "/pets",
            Caller = CallerIdentity.CreateAnonymous(),
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };
        var ex = await Assert.ThrowsAsync<ChioSidecarException>(
            () => client.EvaluateAsync(request)
        );
        await sidecarTask;

        Assert.Equal(ChioErrorCodes.InvalidReceipt, ex.Code);
    }

    [Fact]
    public async Task SidecarClientRejectsAuthorizedFlagWithoutAuthorityTuple()
    {
        var port = GetFreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        var sidecarTask = Task.Run(async () =>
        {
            var requestContext = await listener.GetContextAsync();
            var responseJson = $$"""
            {
              "verdict": { "verdict": "allow" },
              "receipt": {
                "id": "{{ReceiptId}}",
                "request_id": "req-1",
                "route_pattern": "/pets",
                "method": "GET",
                "caller_identity_hash": "hash",
                "verdict": { "verdict": "allow" },
                "receipt_kind": "mediated_decision",
                "boundary_class": "prevent",
                "tool_origin": "caller_executed",
                "redaction_mode": "none",
                "trust_level": "mediated",
                "evidence": [],
                "response_status": 200,
                "timestamp": 1700000000,
                "content_hash": "{{ContentHash}}",
                "policy_hash": "policy",
                "kernel_key": "kernel",
                "signature": "signature"
              },
              "evidence": []
            }
            """;
            var bytes = Encoding.UTF8.GetBytes(responseJson);
            requestContext.Response.StatusCode = 200;
            requestContext.Response.ContentType = "application/json";
            await requestContext.Response.OutputStream.WriteAsync(bytes);
            requestContext.Response.Close();

            var verifyContext = await listener.GetContextAsync();
            var verifyJson = $$"""
            {
              "signature_valid": false,
              "signer_trusted": true,
              "receipt_id_valid": true,
              "parameter_hash_valid": true,
              "receipt_kind": "mediated_decision",
              "boundary_class": "prevent",
              "trust_level": "mediated",
              "result": "allow",
              "authorized": true,
              "signer_key_hex": "{{new string('d', 64)}}",
              "ok": true
            }
            """;
            var verifyBytes = Encoding.UTF8.GetBytes(verifyJson);
            verifyContext.Response.StatusCode = 200;
            verifyContext.Response.ContentType = "application/json";
            await verifyContext.Response.OutputStream.WriteAsync(verifyBytes);
            verifyContext.Response.Close();
        });

        using var client = new ChioSidecarClient($"http://127.0.0.1:{port}");
        var request = new ChioHttpRequest
        {
            RequestId = "req-1",
            Method = "GET",
            RoutePattern = "/pets",
            Path = "/pets",
            Caller = CallerIdentity.CreateAnonymous(),
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };
        var ex = await Assert.ThrowsAsync<ChioSidecarException>(
            () => client.EvaluateAsync(request)
        );
        await sidecarTask;

        Assert.Equal(ChioErrorCodes.InvalidReceipt, ex.Code);
    }

    private static int GetFreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
