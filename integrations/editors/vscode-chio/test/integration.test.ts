// Contract tests for the VSCode extension surface.
//
// The full extension only runs inside a VSCode host, so these tests
// pin the LSP client wiring helpers (`buildServerOptions`,
// `buildClientOptions`, `buildDocumentSelector`) without booting an
// editor. Diagnostic-flow assertions across the live `chio-lsp`
// binary are wired in as a follow-on once a VSCode integration host
// is available in CI.

import { describe, expect, it } from "vitest";

// `vscode-languageclient/node` reaches for `vscode` at module load
// time. Vitest aliases the `vscode` import to `test/vscode_stub.ts`
// (see `vitest.config.ts`) so the wiring helpers can be imported in a
// plain node test runner.

import {
    buildClientOptions,
    buildDocumentSelector,
    buildServerOptions,
} from "../src/lsp_client";

describe("Chio VSCode extension", () => {
    it("subscribes to all three Chio language IDs", () => {
        const selector = buildDocumentSelector();
        const ids = selector.map((s) => s.language).sort();
        expect(ids).toEqual(["chio-guard", "chio-manifest", "chio-yaml"]);
    });

    it("spawns chio-lsp by default with no extra args", () => {
        const opts = buildServerOptions({ path: "chio-lsp", args: [] });
        // Both `run` and `debug` configs must point to the same binary
        // so users do not get inconsistent diagnostics in debug mode.
        expect(opts).toMatchObject({
            run: { command: "chio-lsp", args: [] },
            debug: { command: "chio-lsp", args: [] },
        });
    });

    it("forwards the configured path and arguments to the spawn", () => {
        const opts = buildServerOptions({
            path: "/usr/local/bin/chio",
            args: ["lsp", "--log", "info"],
        });
        expect(opts).toMatchObject({
            run: {
                command: "/usr/local/bin/chio",
                args: ["lsp", "--log", "info"],
            },
        });
    });

    it("registers the chio configuration section for synchronization", () => {
        const opts = buildClientOptions();
        expect(opts.synchronize).toMatchObject({ configurationSection: "chio" });
    });

    it("ships a document selector for every contributed language", () => {
        const selectorIds = new Set(
            buildDocumentSelector().map((s) => s.language),
        );
        for (const id of ["chio-yaml", "chio-manifest", "chio-guard"]) {
            expect(selectorIds.has(id)).toBe(true);
        }
    });
});
