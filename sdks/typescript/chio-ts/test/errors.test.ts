import test from "node:test";
import assert from "node:assert/strict";

import {
  canonicalizeJson,
  canonicalizeJsonString,
  ChioInvariantError,
  signUtf8MessageEd25519,
  verifyUtf8MessageEd25519,
} from "../src/index.ts";

import {
  ChioError,
  DpopSignError,
  QueryError,
  TransportError,
} from "../src/errors.ts";

// --- Existing invariant error tests ---

test("invalid JSON surfaces a stable chio invariant error", () => {
  assert.throws(
    () => canonicalizeJsonString("{"),
    (error: unknown) =>
      error instanceof ChioInvariantError &&
      error.code === "json" &&
      error.message === "input is not valid JSON",
  );
});

test("unsupported canonical JSON values surface a stable code", () => {
  assert.throws(
    () => canonicalizeJson(undefined),
    (error: unknown) =>
      error instanceof ChioInvariantError &&
      error.code === "canonical_json",
  );
});

test("invalid signing seed surfaces a stable code", () => {
  assert.throws(
    () => signUtf8MessageEd25519("hello", "zz"),
    (error: unknown) =>
      error instanceof ChioInvariantError &&
      error.code === "invalid_hex",
  );
});

test("malformed public keys are errors, not false verifications", () => {
  assert.throws(
    () => verifyUtf8MessageEd25519("hello", "abcd", "00".repeat(64)),
    (error: unknown) =>
      error instanceof ChioInvariantError &&
      error.code === "invalid_public_key",
  );
});

// --- New SDK-level error hierarchy tests ---

test("ChioError has name ChioError, a code property, and extends Error", () => {
  const err = new ChioError("some_code", "some message");
  assert.equal(err.name, "ChioError");
  assert.equal(err.code, "some_code");
  assert.equal(err.message, "some message");
  assert.ok(err instanceof Error);
  assert.ok(err instanceof ChioError);
});

test("ChioError supports ErrorOptions cause", () => {
  const cause = new Error("root cause");
  const err = new ChioError("some_code", "wrapper", { cause });
  assert.equal(err.cause, cause);
});

test("DpopSignError has name DpopSignError, code dpop_sign_error, and is instanceof ChioError", () => {
  const err = new DpopSignError("failed to sign");
  assert.equal(err.name, "DpopSignError");
  assert.equal(err.code, "dpop_sign_error");
  assert.equal(err.message, "failed to sign");
  assert.ok(err instanceof Error);
  assert.ok(err instanceof ChioError);
  assert.ok(err instanceof DpopSignError);
});

test("DpopSignError supports ErrorOptions cause", () => {
  const cause = new Error("crypto failure");
  const err = new DpopSignError("sign error", { cause });
  assert.equal(err.cause, cause);
});

test("QueryError has name QueryError, code query_error, optional status, and is instanceof ChioError", () => {
  const errNoStatus = new QueryError("query failed");
  assert.equal(errNoStatus.name, "QueryError");
  assert.equal(errNoStatus.code, "query_error");
  assert.equal(errNoStatus.message, "query failed");
  assert.equal(errNoStatus.status, undefined);
  assert.ok(errNoStatus instanceof ChioError);

  const errWithStatus = new QueryError("not found", 404);
  assert.equal(errWithStatus.status, 404);
  assert.ok(errWithStatus instanceof ChioError);
  assert.ok(errWithStatus instanceof QueryError);
});

test("QueryError supports ErrorOptions cause", () => {
  const cause = new Error("network issue");
  const err = new QueryError("query failed", undefined, { cause });
  assert.equal(err.cause, cause);
});

test("TransportError has name TransportError, code transport_error, and is instanceof ChioError", () => {
  const err = new TransportError("connection refused");
  assert.equal(err.name, "TransportError");
  assert.equal(err.code, "transport_error");
  assert.equal(err.message, "connection refused");
  assert.ok(err instanceof Error);
  assert.ok(err instanceof ChioError);
  assert.ok(err instanceof TransportError);
});

test("TransportError supports ErrorOptions cause", () => {
  const cause = new Error("ECONNREFUSED");
  const err = new TransportError("transport failed", { cause });
  assert.equal(err.cause, cause);
});

test("all SDK error subclasses are instanceof ChioError", () => {
  const errors: ChioError[] = [
    new DpopSignError("dpop"),
    new QueryError("query"),
    new TransportError("transport"),
  ];
  for (const err of errors) {
    assert.ok(err instanceof ChioError, `${err.name} should be instanceof ChioError`);
  }
});
