/**
 * @chio-protocol/guard-ts -- TypeScript SDK for Chio guard components.
 *
 * Targets the chio:guard@0.2.0 WIT world. Types are generated from
 * wit/chio-guard/world.wit via jco. Run `npm run generate-types` to
 * regenerate after WIT changes.
 */

export type { GuardRequest, Host, Verdict, VerdictAllow, VerdictDeny } from "./types.js";
export { PolicyContext, allow, deny, host } from "./types.js";
