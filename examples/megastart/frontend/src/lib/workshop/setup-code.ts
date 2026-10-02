import { z } from "zod";

export const ROLE_IDS = ["research", "implementation", "review"] as const;
export const AGENT_IDS = ["claude", "codex", "hermes", "pi"] as const;
export const AgentIdSchema = z.enum(AGENT_IDS);
export const RoleSchema = z.enum(ROLE_IDS);
export type AgentId = z.infer<typeof AgentIdSchema>;
export type Role = z.infer<typeof RoleSchema>;

export const SetupSchema = z
  .object({
    schemaVersion: z.literal(1),
    system: z.literal("software-factory"),
    project: z.literal("moving-average"),
    exampleRevision: z.literal(1),
    workers: z.discriminatedUnion("mode", [
      z.object({ mode: z.literal("reference") }).strict(),
      z
        .object({
          mode: z.literal("native"),
          roles: z
            .object({
              research: AgentIdSchema,
              implementation: AgentIdSchema,
              review: AgentIdSchema,
            })
            .strict(),
        })
        .strict(),
    ]),
  })
  .strict();

export type Setup = z.infer<typeof SetupSchema>;
export const REFERENCE_SETUP: Setup = {
  schemaVersion: 1,
  system: "software-factory",
  project: "moving-average",
  exampleRevision: 1,
  workers: { mode: "reference" },
};

export class InvalidSetup extends Error {
  readonly code = "INVALID_SETUP";
  constructor() {
    super(
      "This setup code is not supported. Choose a setup in Build and copy its complete command.",
    );
  }
}

/** Strict finite handoff; it grants no execution authority and accepts no paths. */
export function decodeSetup(code: unknown): Setup {
  if (
    typeof code !== "string" ||
    code.length > 96 ||
    !/^[a-z0-9.]+$/.test(code)
  )
    throw new InvalidSetup();
  if (code === "sf1.reference") return SetupSchema.parse(REFERENCE_SETUP);
  const match =
    /^sf1\.native\.(claude|codex|hermes|pi)\.(claude|codex|hermes|pi)\.(claude|codex|hermes|pi)$/.exec(
      code,
    );
  if (!match) throw new InvalidSetup();
  return SetupSchema.parse({
    ...REFERENCE_SETUP,
    workers: {
      mode: "native",
      roles: { research: match[1], implementation: match[2], review: match[3] },
    },
  });
}

export function encodeSetup(value: Setup): string {
  const setup = SetupSchema.parse(value);
  return setup.workers.mode === "reference"
    ? "sf1.reference"
    : `sf1.native.${ROLE_IDS.map((role) => (setup.workers.mode === "native" ? setup.workers.roles[role] : "")).join(".")}`;
}

/** Only a validated token enters the shell command. No user text interpolation. */
export function workshopCommand(value: Setup): string {
  return `chio megastart workshop --setup ${encodeSetup(value)}`;
}

export const AGENT_NAMES: Record<AgentId, string> = {
  claude: "Claude Code",
  codex: "Codex",
  hermes: "Hermes",
  pi: "Pi",
};
export function setupLabel(setup: Setup): string {
  if (setup.workers.mode === "reference") return "Reference workers";
  const { roles } = setup.workers;
  if (
    roles.research === roles.implementation &&
    roles.review === roles.research
  )
    return `${AGENT_NAMES[roles.research]} · all roles`;
  return ROLE_IDS.map((role) => AGENT_NAMES[roles[role]]).join(" / ");
}
