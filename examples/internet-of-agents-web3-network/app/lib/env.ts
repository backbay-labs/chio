// Server-only environment accessors.
//
// Never import from a client component; the Next bundler will inline these
// values as string literals if it is forced to, which would leak the server
// bundle-dir path into the browser.

import "server-only";

export interface ServerEnv {
  bundleDir: string;
  mode: "server" | "static";
}

export class EnvError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvError";
  }
}

export function readServerEnv(): ServerEnv {
  const raw = process.env.CHIO_BUNDLE_DIR;
  if (raw === undefined || raw.trim() === "") {
    throw new EnvError(
      "CHIO_BUNDLE_DIR is not set. Set it to an absolute path pointing at an artifact-dir produced by orchestrate.py.",
    );
  }
  const mode = process.env.CHIO_BUNDLE_MODE === "static" ? "static" : "server";
  return { bundleDir: raw, mode };
}
