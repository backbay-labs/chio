#!/usr/bin/env node
// create-chio-app entry point. Plain Node (no external dependencies) so
// the first-run install stays under the TTFRH budget. The CLI clones a
// template from the in-repo registry into the user's working directory
// and prints the next command. Network egress is opt-in.

import { cpSync, existsSync, mkdirSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { findTemplate, listTemplateSlugs, TEMPLATES } from "./templates.js";

export interface CliOptions {
  readonly slug: string | undefined;
  readonly destination: string | undefined;
  readonly help: boolean;
  readonly listTemplates: boolean;
}

export interface CliResult {
  readonly status: "ok" | "error" | "help" | "list";
  readonly message: string;
  readonly destination?: string | undefined;
}

export function parseArgs(argv: readonly string[]): CliOptions {
  let slug: string | undefined;
  let destination: string | undefined;
  let help = false;
  let listTemplates = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      help = true;
      continue;
    }
    if (arg === "--list" || arg === "--list-templates") {
      listTemplates = true;
      continue;
    }
    if (slug === undefined) {
      slug = arg;
      continue;
    }
    if (destination === undefined) {
      destination = arg;
    }
  }
  return { slug, destination, help, listTemplates };
}

export function helpText(): string {
  const lines = [
    "Usage: create-chio-app <template> [destination]",
    "",
    "Templates:",
    ...TEMPLATES.map(t => `  ${t.slug.padEnd(24)} ${t.description}`),
    "",
    "Flags:",
    "  --help          Show this message",
    "  --list          List template slugs and exit",
  ];
  return lines.join("\n");
}

export interface ScaffoldEnv {
  readonly templateRoot: string;
  readonly cwd: string;
  readonly copy: (source: string, dest: string) => void;
  readonly exists: (path: string) => boolean;
  readonly mkdir: (path: string) => void;
  readonly isDirectory: (path: string) => boolean;
}

export function defaultScaffoldEnv(templateRoot: string): ScaffoldEnv {
  return {
    templateRoot,
    cwd: process.cwd(),
    copy: (source, dest) => {
      cpSync(source, dest, { recursive: true });
    },
    exists: path => existsSync(path),
    mkdir: path => mkdirSync(path, { recursive: true }),
    isDirectory: path => {
      try {
        return statSync(path).isDirectory();
      } catch {
        return false;
      }
    },
  };
}

export function runCli(
  argv: readonly string[],
  env: ScaffoldEnv,
): CliResult {
  const opts = parseArgs(argv);
  if (opts.help) {
    return { status: "help", message: helpText() };
  }
  if (opts.listTemplates) {
    return {
      status: "list",
      message: listTemplateSlugs().join("\n"),
    };
  }
  if (opts.slug === undefined) {
    return {
      status: "error",
      message: `error: missing template slug\n\n${helpText()}`,
    };
  }
  const template = findTemplate(opts.slug);
  if (template === undefined) {
    return {
      status: "error",
      message:
        `error: unknown template '${opts.slug}'\nknown: ${listTemplateSlugs().join(", ")}`,
    };
  }
  const sourceDir = resolve(env.templateRoot, template.directory);
  if (!env.isDirectory(sourceDir)) {
    return {
      status: "error",
      message: `error: template source not found at ${sourceDir}`,
    };
  }
  const cwd = resolve(env.cwd);
  const destination = resolve(cwd, opts.destination ?? template.slug);
  const relativeDestination = relative(cwd, destination);
  if (
    relativeDestination === ".." ||
    relativeDestination.startsWith(`..${sep}`) ||
    isAbsolute(relativeDestination)
  ) {
    return {
      status: "error",
      message: `error: destination ${destination} must stay within ${cwd}`,
    };
  }
  if (env.exists(destination)) {
    return {
      status: "error",
      message: `error: destination ${destination} already exists`,
    };
  }
  env.mkdir(destination);
  env.copy(sourceDir, destination);
  return {
    status: "ok",
    message: [
      `Scaffolded ${template.slug} at ${destination}`,
      `next: cd ${opts.destination ?? template.slug} && ${template.nextCommand}`,
      `bench: ${template.bench}`,
    ].join("\n"),
    destination,
  };
}

export function findTemplateRoot(start: string): string {
  let current = start;
  while (true) {
    const marker = join(current, "templates", "next-ai-sdk-receipts");
    if (existsSync(marker)) {
      return current;
    }
    const parent = resolve(current, "..");
    if (parent === current) {
      return start;
    }
    current = parent;
  }
}

export function isDirectNodeRun(metaUrl: string, argvEntry: string | undefined): boolean {
  if (argvEntry === undefined) {
    return false;
  }
  try {
    return realpathSync(fileURLToPath(metaUrl)) === realpathSync(resolve(argvEntry));
  } catch {
    return metaUrl === pathToFileURL(resolve(argvEntry)).href;
  }
}

if (isDirectNodeRun(import.meta.url, process.argv[1])) {
  const argv = process.argv.slice(2);
  const moduleDir = dirname(fileURLToPath(import.meta.url));
  const root = findTemplateRoot(moduleDir);
  const env = defaultScaffoldEnv(root);
  const result = runCli(argv, env);
  // eslint-disable-next-line no-console
  console.log(result.message);
  if (result.status === "error") {
    process.exit(1);
  }
}
