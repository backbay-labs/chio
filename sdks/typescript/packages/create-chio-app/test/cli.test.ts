import { describe, expect, test } from "bun:test";
import {
  helpText,
  isDirectNodeRun,
  parseArgs,
  runCli,
  type ScaffoldEnv,
} from "../src/index.js";
import { listTemplateSlugs, TEMPLATES } from "../src/templates.js";

interface CallLog {
  copies: { source: string; dest: string }[];
  mkdirs: string[];
}

function fakeEnv(opts: {
  existing?: readonly string[];
  isDir?: (path: string) => boolean;
  templateRoot?: string;
  cwd?: string;
}): { env: ScaffoldEnv; log: CallLog } {
  const log: CallLog = { copies: [], mkdirs: [] };
  const existing = new Set(opts.existing ?? []);
  const env: ScaffoldEnv = {
    templateRoot: opts.templateRoot ?? "/repo",
    cwd: opts.cwd ?? "/work",
    copy: (source, dest) => {
      log.copies.push({ source, dest });
    },
    exists: path => existing.has(path),
    mkdir: path => {
      log.mkdirs.push(path);
      existing.add(path);
    },
    isDirectory: opts.isDir ?? (() => true),
  };
  return { env, log };
}

describe("parseArgs", () => {
  test("captures slug and destination", () => {
    const opts = parseArgs(["next-ai-sdk-receipts", "./out"]);
    expect(opts.slug).toBe("next-ai-sdk-receipts");
    expect(opts.destination).toBe("./out");
    expect(opts.help).toBe(false);
  });

  test("recognizes --help and --list", () => {
    expect(parseArgs(["--help"]).help).toBe(true);
    expect(parseArgs(["--list"]).listTemplates).toBe(true);
  });
});

describe("template registry", () => {
  test("lists all three known templates", () => {
    const slugs = listTemplateSlugs();
    expect(slugs).toContain("next-ai-sdk-receipts");
    expect(slugs).toContain("fastapi-langchain");
    expect(slugs).toContain("cloudflare-worker");
    expect(slugs.length).toBe(3);
  });

  test("each entry pins a bench runner", () => {
    for (const template of TEMPLATES) {
      expect(template.bench.endsWith(".rs")).toBe(true);
      expect(template.directory.startsWith("templates/")).toBe(true);
    }
  });
});

describe("Node entrypoint detection", () => {
  test("matches resolved argv entry URL", () => {
    expect(
      isDirectNodeRun(
        new URL("file:///workspace/pkg/dist/index.js").href,
        "/workspace/pkg/dist/index.js",
      ),
    ).toBe(true);
  });

  test("does not run on library import", () => {
    expect(
      isDirectNodeRun(
        new URL("file:///workspace/pkg/dist/index.js").href,
        "/workspace/consumer/index.js",
      ),
    ).toBe(false);
  });
});

describe("runCli", () => {
  test("returns help when --help passed", () => {
    const { env } = fakeEnv({});
    const result = runCli(["--help"], env);
    expect(result.status).toBe("help");
    expect(result.message).toContain("Usage:");
  });

  test("returns list when --list passed", () => {
    const { env } = fakeEnv({});
    const result = runCli(["--list"], env);
    expect(result.status).toBe("list");
    expect(result.message).toContain("next-ai-sdk-receipts");
  });

  test("errors on unknown template", () => {
    const { env } = fakeEnv({});
    const result = runCli(["does-not-exist"], env);
    expect(result.status).toBe("error");
    expect(result.message).toContain("unknown template");
  });

  test("errors when destination already exists", () => {
    const { env } = fakeEnv({
      existing: ["/work/next-ai-sdk-receipts"],
    });
    const result = runCli(["next-ai-sdk-receipts"], env);
    expect(result.status).toBe("error");
    expect(result.message).toContain("already exists");
  });

  test("errors when template source missing", () => {
    const { env } = fakeEnv({ isDir: () => false });
    const result = runCli(["next-ai-sdk-receipts"], env);
    expect(result.status).toBe("error");
    expect(result.message).toContain("template source not found");
  });

  test("rejects destinations outside cwd", () => {
    const { env, log } = fakeEnv({});
    const result = runCli(["next-ai-sdk-receipts", "../outside"], env);
    expect(result.status).toBe("error");
    expect(result.message).toContain("must stay within");
    expect(log.mkdirs).toEqual([]);
    expect(log.copies).toEqual([]);
  });

  test("scaffolds template into destination", () => {
    const { env, log } = fakeEnv({});
    const result = runCli(["next-ai-sdk-receipts", "my-app"], env);
    expect(result.status).toBe("ok");
    expect(result.message).toContain("Scaffolded next-ai-sdk-receipts");
    expect(log.mkdirs.length).toBe(1);
    expect(log.copies.length).toBe(1);
    expect(log.copies[0]?.dest.endsWith("/my-app")).toBe(true);
  });
});

describe("helpText", () => {
  test("includes every template description", () => {
    const text = helpText();
    for (const template of TEMPLATES) {
      expect(text).toContain(template.slug);
      expect(text).toContain(template.description);
    }
  });
});
