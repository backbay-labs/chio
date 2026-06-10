// VSCode extension entrypoint for Chio.
//
// Activated when the editor opens any of the Chio language IDs
// (`chio-yaml`, `chio-manifest`, `chio-guard`). Spawns the `chio-lsp`
// binary and forwards its diagnostics to VSCode.

import * as vscode from "vscode";
import { LanguageClient } from "vscode-languageclient/node";
import { ChioServerConfig, createLanguageClient } from "./lsp_client";

let client: LanguageClient | undefined;

/// Resolves the `chio.lsp.path` and `chio.lsp.args` settings into a
/// `ChioServerConfig`. Pure helper so the activation logic can be
/// unit-tested without a live VSCode host.
export function readServerConfig(
    settings: vscode.WorkspaceConfiguration,
): ChioServerConfig {
    const path = settings.get<string>("lsp.path", "chio-lsp");
    const args = settings.get<string[]>("lsp.args", []);
    return { path, args };
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    const settings = vscode.workspace.getConfiguration("chio");
    const config = readServerConfig(settings);
    client = createLanguageClient(config);
    context.subscriptions.push({
        dispose: () => {
            void client?.stop();
        },
    });
    await client.start();
}

export async function deactivate(): Promise<void> {
    if (client === undefined) {
        return;
    }
    await client.stop();
    client = undefined;
}
