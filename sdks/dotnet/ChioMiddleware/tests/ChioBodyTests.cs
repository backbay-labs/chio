using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Backbay.Chio;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Backbay.Chio.Tests;

public class ChioBodyTests
{
    private static ChioProtectMiddleware Middleware(string endpoint, long limit, Action next) => new(
        _ => { next(); return Task.CompletedTask; },
        Options.Create(new ChioMiddlewareOptions { SidecarUrl = endpoint, MaxRequestBodyBytes = limit }),
        NullLogger<ChioProtectMiddleware>.Instance);

    private static DefaultHttpContext Request(byte[] bytes, long? declaredLength = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/notes";
        context.Request.ContentType = "application/json";
        context.Request.ContentLength = declaredLength;
        context.Request.Body = new ChunkedBody(bytes);
        context.Response.Body = new MemoryStream();
        return context;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompleteBodyIsHashedAndRewoundWithoutAssumingContentLength(bool knownLength)
    {
        using var reservation = new TcpListener(IPAddress.Loopback, 0);
        reservation.Start();
        var port = ((IPEndPoint)reservation.LocalEndpoint).Port;
        reservation.Stop();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        var bytes = Encoding.UTF8.GetBytes("{\"text\":\"release 界 checklist\"}");
        var context = Request(bytes, knownLength ? bytes.Length : null);
        var observed = Task.Run(async () =>
        {
            var exchange = await listener.GetContextAsync().WaitAsync(TimeSpan.FromSeconds(10));
            using var document = await JsonDocument.ParseAsync(exchange.Request.InputStream);
            var payload = document.RootElement.Clone();
            // Refuse evaluation: this unit test inspects request construction,
            // and never fabricates an authorized or cryptographically valid receipt.
            exchange.Response.StatusCode = 503;
            exchange.Response.Close();
            return payload;
        });
        var nextCalled = false;
        await Middleware($"http://127.0.0.1:{port}", 8192, () => nextCalled = true).InvokeAsync(context);
        var sent = await observed;
        Assert.Equal(bytes.Length, sent.GetProperty("body_length").GetInt32());
        Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), sent.GetProperty("body_hash").GetString());
        Assert.Equal(0, context.Request.Body.Position);
        using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
        Assert.Equal(Encoding.UTF8.GetString(bytes), await reader.ReadToEndAsync());
        Assert.False(nextCalled);
        Assert.Equal(502, context.Response.StatusCode);
        await context.Request.Body.DisposeAsync();
    }

    [Theory]
    [InlineData(null)]
    [InlineData(9L)]
    public async Task OversizedBodyStopsBeforeAuthorityAndHandler(long? declaredLength)
    {
        var context = Request(Encoding.UTF8.GetBytes("123456789"), declaredLength);
        var nextCalled = false;
        await Middleware("http://127.0.0.1:1", 8, () => nextCalled = true).InvokeAsync(context);
        Assert.Equal(413, context.Response.StatusCode);
        Assert.False(nextCalled);
        Assert.False(context.Response.Headers.ContainsKey("X-Chio-Receipt-Id"));
        await context.Request.Body.DisposeAsync();
    }

    [Fact]
    public async Task IncompleteBodyStopsBeforeAuthorityAndHandler()
    {
        var context = Request(Encoding.UTF8.GetBytes("123"), 8);
        var nextCalled = false;
        await Middleware("http://127.0.0.1:1", 8, () => nextCalled = true).InvokeAsync(context);
        Assert.Equal(400, context.Response.StatusCode);
        Assert.False(nextCalled);
        await context.Request.Body.DisposeAsync();
    }

    private sealed class ChunkedBody(byte[] bytes) : Stream
    {
        private readonly MemoryStream inner = new(bytes);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, Math.Min(count, 7));
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer[..Math.Min(buffer.Length, 7)], cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }
}
