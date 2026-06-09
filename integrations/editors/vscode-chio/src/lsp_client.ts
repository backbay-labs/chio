// LSP client wiring for the Chio extension.
//
// The extension spawns the `chio-lsp` binary (or `chio lsp` subcommand on
// the unified `chio` binary) over stdio and exposes its diagnostics,
// completion, hover, and go-to-definition capabilities to VSCode.
//
// Diagnostics carry `urn:chio:error:*` registry codes via the LSP
// `Diagnostic.code` field; the extension does not interpret the code, it
// only forwards it through `vscode-languageclient`.

import type {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
} from "vscode-languageclient/node";

// Mirror of `vscode-languageclient/node`'s `TransportKind.stdio` so the
// wiring helpers can be imported without pulling in the full client
// (which itself reaches for `vscode` at module load time). The numeric
// value matches `TransportKind.stdio` in vscode-languageclient 9.x.
const TRANSPORT_KIND_STDIO = 0;

/// Configuration accepted by `buildServerOptions`.
///
/// `path` is the resolved binary on disk (defaults to `chio-lsp` so
/// `PATH` lookup happens at spawn time). `args` is forwarded verbatim.
export interface ChioServerConfig {
    readonly path: string;
    readonly args: readonly string[];
}

/// Returns the document selector the language client subscribes to.
///
/// Mirrors the `contributes.languages` block in `package.json`. Exposed
/// as a function so unit tests can pin the contract without booting
/// VSCode.
export function buildDocumentSelector(): { scheme: string; language: string }[] {
    return [
        { scheme: "file", language: "chio-yaml" },
        { scheme: "file", language: "chio-manifest" },
        { scheme: "file", language: "chio-guard" },
    ];
}

/// Builds the `ServerOptions` payload that `vscode-languageclient`
/// consumes to spawn `chio-lsp`. Keeping this pure makes it testable
/// outside of a VSCode host.
export function buildServerOptions(config: ChioServerConfig): ServerOptions {
    return {
        run: {
            command: config.path,
            args: [...config.args],
            transport: TRANSPORT_KIND_STDIO,
        },
        debug: {
            command: config.path,
            args: [...config.args],
            transport: TRANSPORT_KIND_STDIO,
        },
    };
}

/// Builds the `LanguageClientOptions` payload (document selector +
/// trace toggle) used to construct the language client.
export function buildClientOptions(): LanguageClientOptions {
    return {
        documentSelector: buildDocumentSelector(),
        synchronize: {
            // Editor-side notification when the user edits chio.yaml so
            // chio-lsp can refresh diagnostics. The server is the
            // authority, the client just forwards.
            configurationSection: "chio",
        },
    };
}

/// Constructs a fresh `LanguageClient` configured to spawn `chio-lsp`.
///
/// The caller is responsible for `start()` / `stop()` lifecycle; this
/// helper just assembles the options so tests can pin the contract.
export function createLanguageClient(config: ChioServerConfig): LanguageClient {
    const serverOptions = buildServerOptions(config);
    const clientOptions = buildClientOptions();
    // Lazy require so the wiring helpers can be loaded outside a real
    // VSCode host. The full client reaches for `vscode` at module load
    // time, which only resolves inside the editor.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const lc = require("vscode-languageclient/node") as {
        LanguageClient: new (
            id: string,
            name: string,
            serverOptions: ServerOptions,
            clientOptions: LanguageClientOptions,
        ) => LanguageClient;
    };
    return new lc.LanguageClient(
        "chio",
        "Chio Language Server",
        serverOptions,
        clientOptions,
    );
}
