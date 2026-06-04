using Backbay.Chio;

namespace HelloDotnet;

internal static class HelloApp
{
    internal static WebApplication Create(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddChioProtection();

        var app = builder.Build();
        app.MapGet("/healthz", HelloEndpoints.Health);
        app.UseWhen(
            context => RequiresChioProtection(context.Request.Path),
            branch => branch.UseChioProtection());
        app.MapHelloEndpoints();
        return app;
    }

    internal static bool RequiresChioProtection(PathString path) =>
        !path.Equals("/healthz", StringComparison.OrdinalIgnoreCase);
}

internal static class HelloEndpoints
{
    internal static IEndpointRouteBuilder MapHelloEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/hello", Hello);
        app.MapPost("/echo", Echo);
        return app;
    }

    internal static IResult Health() => Results.Json(new HealthResponse("ok"));

    internal static IResult Hello() => Results.Json(new HelloResponse("hello from dotnet"));

    internal static IResult Echo(EchoRequest payload)
    {
        if (!EchoContract.TryCreateResponse(payload, out var response, out var error))
        {
            return Results.BadRequest(error);
        }

        return Results.Json(response);
    }
}

internal static class EchoContract
{
    internal static bool TryCreateResponse(
        EchoRequest payload,
        out EchoResponse? response,
        out EchoErrorResponse? error)
    {
        if (string.IsNullOrWhiteSpace(payload.Message))
        {
            response = null;
            error = new EchoErrorResponse(
                "invalid_echo_request",
                "message must contain at least one non-whitespace character");
            return false;
        }

        if (payload.Count < 1)
        {
            response = null;
            error = new EchoErrorResponse(
                "invalid_echo_request",
                "count must be greater than or equal to 1");
            return false;
        }

        response = new EchoResponse(payload.Message, payload.Count);
        error = null;
        return true;
    }
}

internal sealed record HealthResponse(string Status);

internal sealed record HelloResponse(string Message);

internal sealed record EchoRequest(string Message, int Count = 1);

internal sealed record EchoResponse(string Message, int Count);

internal sealed record EchoErrorResponse(string Error, string Message);
