export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

import { ChioInvariantError } from "./errors.ts";

type ParsedJson =
  | { readonly type: "null" }
  | { readonly type: "boolean"; readonly value: boolean }
  | { readonly type: "number"; readonly raw: string }
  | { readonly type: "string"; readonly value: string }
  | { readonly type: "array"; readonly items: ParsedJson[] }
  | { readonly type: "object"; readonly entries: Map<string, ParsedJson> };

function compareUtf16(a: string, b: string): number {
  if (a < b) {
    return -1;
  }
  if (a > b) {
    return 1;
  }
  return 0;
}

function canonicalizeRawNumber(raw: string): string {
  if (!/[.eE]/.test(raw)) {
    return raw === "-0" ? "0" : raw;
  }

  const value = Number(raw);
  if (!Number.isFinite(value)) {
    throw new ChioInvariantError("canonical_json", "canonical JSON does not support non-finite numbers");
  }
  const rendered = JSON.stringify(value);
  if (rendered === undefined) {
    throw new ChioInvariantError("canonical_json", "canonical JSON does not support invalid numbers");
  }
  return rendered;
}

function canonicalizeParsedJson(value: ParsedJson): string {
  switch (value.type) {
    case "null":
      return "null";
    case "boolean":
      return value.value ? "true" : "false";
    case "number":
      return canonicalizeRawNumber(value.raw);
    case "string":
      return JSON.stringify(value.value);
    case "array":
      return `[${value.items.map((item) => canonicalizeParsedJson(item)).join(",")}]`;
    case "object":
      return `{${Array.from(value.entries.entries())
        .sort(([left], [right]) => compareUtf16(left, right))
        .map(([key, entryValue]) => `${JSON.stringify(key)}:${canonicalizeParsedJson(entryValue)}`)
        .join(",")}}`;
  }
}

class JsonTextCanonicalParser {
  private readonly input: string;
  private position = 0;

  constructor(input: string) {
    this.input = input;
  }

  parse(): ParsedJson {
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.position !== this.input.length) {
      throw new ChioInvariantError("json", "input contains trailing data after JSON value");
    }
    return value;
  }

  private parseValue(): ParsedJson {
    this.skipWhitespace();
    const next = this.input[this.position];
    switch (next) {
      case "{":
        return this.parseObject();
      case "[":
        return this.parseArray();
      case "\"":
        return { type: "string", value: this.parseString() };
      case "t":
        this.consumeLiteral("true");
        return { type: "boolean", value: true };
      case "f":
        this.consumeLiteral("false");
        return { type: "boolean", value: false };
      case "n":
        this.consumeLiteral("null");
        return { type: "null" };
      default:
        if (next !== undefined && (next === "-" || (next >= "0" && next <= "9"))) {
          return { type: "number", raw: this.parseNumber() };
        }
        throw new ChioInvariantError("json", "input is not valid JSON");
    }
  }

  private parseObject(): ParsedJson {
    this.position += 1;
    this.skipWhitespace();
    const entries = new Map<string, ParsedJson>();
    if (this.consumeIf("}")) {
      return { type: "object", entries };
    }

    while (true) {
      this.skipWhitespace();
      if (this.input[this.position] !== "\"") {
        throw new ChioInvariantError("json", "input is not valid JSON");
      }
      const key = this.parseString();
      this.skipWhitespace();
      this.expect(":");
      if (entries.has(key)) {
        throw new ChioInvariantError("json", `input contains duplicate object key: ${key}`);
      }
      entries.set(key, this.parseValue());
      this.skipWhitespace();
      if (this.consumeIf("}")) {
        return { type: "object", entries };
      }
      this.expect(",");
    }
  }

  private parseArray(): ParsedJson {
    this.position += 1;
    this.skipWhitespace();
    const items: ParsedJson[] = [];
    if (this.consumeIf("]")) {
      return { type: "array", items };
    }

    while (true) {
      items.push(this.parseValue());
      this.skipWhitespace();
      if (this.consumeIf("]")) {
        return { type: "array", items };
      }
      this.expect(",");
    }
  }

  private parseString(): string {
    const start = this.position;
    this.position += 1;
    while (this.position < this.input.length) {
      const current = this.input[this.position];
      if (current === "\"") {
        this.position += 1;
        try {
          return JSON.parse(this.input.slice(start, this.position)) as string;
        } catch (cause) {
          throw new ChioInvariantError("json", "input is not valid JSON", { cause });
        }
      }
      if (current === "\\") {
        this.position += 1;
        if (this.position >= this.input.length) {
          break;
        }
      }
      this.position += 1;
    }
    throw new ChioInvariantError("json", "input is not valid JSON");
  }

  private parseNumber(): string {
    const match = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
    match.lastIndex = this.position;
    const result = match.exec(this.input);
    if (!result) {
      throw new ChioInvariantError("json", "input is not valid JSON");
    }
    this.position = match.lastIndex;
    return result[0];
  }

  private consumeLiteral(literal: string): void {
    if (!this.input.startsWith(literal, this.position)) {
      throw new ChioInvariantError("json", "input is not valid JSON");
    }
    this.position += literal.length;
  }

  private consumeIf(token: string): boolean {
    if (this.input[this.position] !== token) {
      return false;
    }
    this.position += 1;
    return true;
  }

  private expect(token: string): void {
    if (!this.consumeIf(token)) {
      throw new ChioInvariantError("json", "input is not valid JSON");
    }
  }

  private skipWhitespace(): void {
    while (/[ \n\r\t]/.test(this.input[this.position] ?? "")) {
      this.position += 1;
    }
  }
}

export function canonicalizeJson(value: unknown): string {
  if (value === null) {
    return "null";
  }

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new ChioInvariantError("canonical_json", "canonical JSON does not support non-finite numbers");
      }
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object":
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
      }

      const entries = Object.entries(value as Record<string, unknown>);
      for (const [, entryValue] of entries) {
        if (entryValue === undefined) {
          throw new ChioInvariantError(
            "canonical_json",
            "canonical JSON does not support undefined object fields",
          );
        }
      }

      return `{${entries
        .sort(([left], [right]) => compareUtf16(left, right))
        .map(([key, entryValue]) => `${JSON.stringify(key)}:${canonicalizeJson(entryValue)}`)
        .join(",")}}`;
    default:
      throw new ChioInvariantError(
        "canonical_json",
        `canonical JSON does not support values of type ${typeof value}`,
      );
  }
}

export function canonicalizeJsonString(input: string): string {
  return canonicalizeParsedJson(new JsonTextCanonicalParser(input).parse());
}
