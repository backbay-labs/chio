// Health probe. Returns 200 { ok, bundleDir, manifestSha } when the manifest
// is readable, 500 with a diagnostic otherwise. smoke.sh polls this endpoint.

import { NextResponse } from "next/server";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { EnvError, readServerEnv } from "@/lib/env";

export const dynamic = "force-dynamic";

export async function GET(): Promise<NextResponse> {
  try {
    const env = readServerEnv();
    const manifestAbs = path.resolve(env.bundleDir, "bundle-manifest.json");
    const body = await fs.readFile(manifestAbs);
    const sha = crypto.createHash("sha256").update(body).digest("hex");
    return NextResponse.json({
      ok: true,
      bundleDir: env.bundleDir,
      manifestSha: sha,
      mode: env.mode,
    });
  } catch (err) {
    const message =
      err instanceof EnvError
        ? err.message
        : err instanceof Error
          ? err.message
          : String(err);
    return NextResponse.json(
      {
        ok: false,
        error: message,
      },
      { status: 500 },
    );
  }
}
