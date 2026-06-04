using Microsoft.AspNetCore.Http;
using Xunit;

namespace HelloDotnet.Tests;

public sealed class HelloEndpointsTests
{
    [Fact]
    public void HealthRouteBypassesChioProtectionOnlyForHealthz()
    {
        Assert.False(HelloApp.RequiresChioProtection(new PathString("/healthz")));
        Assert.False(HelloApp.RequiresChioProtection(new PathString("/HEALTHZ")));
        Assert.True(HelloApp.RequiresChioProtection(new PathString("/hello")));
        Assert.True(HelloApp.RequiresChioProtection(new PathString("/echo")));
    }

    [Fact]
    public void EchoContractAcceptsValidPayload()
    {
        var ok = EchoContract.TryCreateResponse(
            new EchoRequest("hello", 2),
            out var response,
            out var error);

        Assert.True(ok);
        Assert.NotNull(response);
        Assert.Null(error);
        Assert.Equal("hello", response.Message);
        Assert.Equal(2, response.Count);
    }

    [Theory]
    [InlineData("", 1, "message must contain at least one non-whitespace character")]
    [InlineData("   ", 1, "message must contain at least one non-whitespace character")]
    [InlineData("hello", 0, "count must be greater than or equal to 1")]
    [InlineData("hello", -1, "count must be greater than or equal to 1")]
    public void EchoContractRejectsInvalidPayload(
        string message,
        int count,
        string expectedMessage)
    {
        var ok = EchoContract.TryCreateResponse(
            new EchoRequest(message, count),
            out var response,
            out var error);

        Assert.False(ok);
        Assert.Null(response);
        Assert.NotNull(error);
        Assert.Equal("invalid_echo_request", error.Error);
        Assert.Equal(expectedMessage, error.Message);
    }
}
