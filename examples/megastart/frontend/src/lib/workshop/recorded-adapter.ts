import { z } from "zod";
import { DigestSchema, IdSchema, type RecordedWorkshop } from "./schema";

const RunSchema = z.object({
  id: z.enum(["baseline", "extended"]),
  mode: z.literal("reference"),
  phase: z.literal("awaiting_review"),
  published: z.literal(false),
  candidate: z.string().min(1).max(64_000),
  immutableTests: z.literal(true),
  identity: z.object({
    candidate: IdSchema,
    candidate_sha256: DigestSchema,
    source_sha256: DigestSchema,
    tests_sha256: DigestSchema,
    test_receipt: DigestSchema,
    review_receipt: DigestSchema,
  }),
  tests: z
    .array(
      z
        .string()
        .regex(/^[a-zA-Z0-9_:]+$/)
        .max(256),
    )
    .min(1)
    .max(512),
  testOutput: z.string().max(64_000),
  testSource: z.string().min(1).max(64_000),
});
export const RecordingSchema = z
  .object({
    schemaVersion: z.literal(1),
    kind: z.literal("recorded-reference-outcomes"),
    qualification: z.string().min(1).max(2048),
    archiveSha256: DigestSchema,
    executableSha256: DigestSchema,
    original: z.string().min(1).max(64_000),
    regression: z.string().min(1).max(64_000),
    runs: z.array(RunSchema).min(1).max(16),
  })
  .superRefine((record, ctx) => {
    if (new Set(record.runs.map((run) => run.id)).size !== record.runs.length)
      ctx.addIssue({ code: "custom", message: "Duplicate recorded mission" });
    for (const run of record.runs) {
      const results = [
        ...run.testOutput.matchAll(/^test (\S+) \.\.\. (ok|FAILED|ignored)$/gm),
      ];
      const success = /test result: ok\. (\d+) passed; 0 failed;/.exec(
        run.testOutput,
      );
      if (
        !success ||
        Number(success[1]) !== run.tests.length ||
        results.length !== run.tests.length ||
        new Set(run.tests).size !== run.tests.length ||
        run.tests.some(
          (name) =>
            !results.some((match) => match[1] === name && match[2] === "ok"),
        )
      )
        ctx.addIssue({
          code: "custom",
          message: `Recorded checks do not match actual output: ${run.id}`,
        });
    }
  });
export type Recording = z.infer<typeof RecordingSchema>;

/** Read-only adapter. Future local setup is deliberately not an input. */
export function recordedWorkshop(
  input: unknown,
  id: "baseline" | "extended" = "baseline",
): RecordedWorkshop {
  const record = RecordingSchema.parse(input);
  const run = record.runs.find((item) => item.id === id);
  if (!run) throw new Error("This recorded mission is unavailable.");
  return {
    source: {
      kind: "recorded",
      recordId: run.id,
      mode: "reference",
      qualification: record.qualification,
      canMutate: false,
    },
    label:
      id === "baseline"
        ? "Moving average"
        : "Moving average · added regression",
    original: record.original,
    candidate: run.candidate,
    harness: run.testSource,
    regression: record.regression,
    tests: {
      status: "passed",
      checks: run.tests.map((name) => ({ name, status: "passed" })),
      output: run.testOutput,
      compiler_output: null,
      candidate_digest: run.identity.candidate_sha256,
      harness_digest: run.identity.tests_sha256,
      complete: true,
    },
    proposal: {
      candidate_id: run.identity.candidate,
      candidate_digest: run.identity.candidate_sha256,
      harness_digest: run.identity.tests_sha256,
      source_digest: run.identity.source_sha256,
      test_receipt: run.identity.test_receipt,
      review_receipt: run.identity.review_receipt,
    },
    published: false,
    archiveDigest: record.archiveSha256,
  };
}

/** Source strings use Chio's canonical JSON-string encoding, not raw file bytes. */
export async function sourceDigest(source: string): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(source));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export async function verifyRecording(input: unknown): Promise<Recording> {
  const record = RecordingSchema.parse(input);
  for (const run of record.runs) {
    const [original, candidate, harness] = await Promise.all([
      sourceDigest(record.original),
      sourceDigest(run.candidate),
      sourceDigest(run.testSource),
    ]);
    if (
      original !== run.identity.source_sha256 ||
      candidate !== run.identity.candidate_sha256 ||
      harness !== run.identity.tests_sha256
    )
      throw new Error(`Recorded source identity mismatch: ${run.id}`);
  }
  return record;
}
