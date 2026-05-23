import { describe, it, expect } from "vitest";
import { Elysia } from "elysia";
import { chio } from "../src/index.js";

describe("chio elysia plugin", () => {
  it("exports chio as a function", () => {
    expect(typeof chio).toBe("function");
  });

  it("returns an Elysia instance", () => {
    const plugin = chio({});
    expect(plugin).toBeInstanceOf(Elysia);
  });

  it("skip patterns bypass evaluation", async () => {
    const app = new Elysia()
      .use(
        chio({
          sidecarUrl: "http://127.0.0.1:1", // Unreachable
          skip: ["/health"],
        }),
      )
      .get("/health", () => ({ ok: true }));

    const response = await app.handle(
      new Request("http://localhost/health", { method: "GET" }),
    );

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({ ok: true });
  });

  it("denies requests when sidecar is unreachable (fail-closed)", async () => {
    const app = new Elysia()
      .use(
        chio({
          sidecarUrl: "http://127.0.0.1:1", // Unreachable
          timeoutMs: 500,
        }),
      )
      .get("/test", () => ({ data: "should not reach here" }));

    const response = await app.handle(
      new Request("http://localhost/test", { method: "GET" }),
    );

    expect(response.status).toBe(502);
    const body = await response.json();
    expect(body.error).toBe("chio_sidecar_unreachable");
  });

  it("fails closed when legacy onSidecarError is allow", async () => {
    const app = new Elysia()
      .use(
        chio({
          sidecarUrl: "http://127.0.0.1:1", // Unreachable
          onSidecarError: "allow",
          timeoutMs: 500,
        }),
      )
      .get("/test", () => ({ data: "reached handler" }));

    const response = await app.handle(
      new Request("http://localhost/test", { method: "GET" }),
    );

    expect(response.status).toBe(502);
    const body = await response.json();
    expect(body.error).toBe("chio_sidecar_unreachable");
  });

  it("skip patterns with regex work", async () => {
    const app = new Elysia()
      .use(
        chio({
          sidecarUrl: "http://127.0.0.1:1", // Unreachable
          skip: [/^\/internal\//],
        }),
      )
      .get("/internal/status", () => ({ status: "ok" }));

    const response = await app.handle(
      new Request("http://localhost/internal/status", { method: "GET" }),
    );

    expect(response.status).toBe(200);
  });
});
