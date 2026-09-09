// Private launcher child. Standard input is its parent lifeline, not guest input.
import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { createInterface } from "node:readline";
const [modulePath, configPath] = process.argv.slice(2);
const {startGatewayHttp} = await import(pathToFileURL(modulePath).href);
const config = JSON.parse(readFileSync(configPath, "utf8"));
const {verifyCompletedOutcome} = await import(pathToFileURL(join(dirname(modulePath), "execution.js")).href);
const gateway = await startGatewayHttp(config);
if (typeof gateway.acknowledgeDelivery !== "function") throw new Error("Host delivery contract required");
let stopped = false;
async function stop() {if (stopped) return; stopped = true; await gateway.close();}
process.once("SIGTERM", () => {void stop().finally(() => process.exit(143));});
process.once("SIGINT", () => {void stop().finally(() => process.exit(130));});
const input = createInterface({input: process.stdin, crlfDelay: Infinity});
input.once("close", () => {void stop();});
process.stdout.write(JSON.stringify({schema: "chio.hermes.launcher-transport.v1", url: gateway.url, token: gateway.token}) + "\n");
for await (const line of input) {
  try {
    if (line.length > 65536 || stopped) throw new Error("private transport closed or oversized request");
    const request = JSON.parse(line);
    if (request.method !== "acknowledge" || !Number.isSafeInteger(request.id)) throw new Error("unsupported private operation");
    const id = request.outcome?.requestId;
    if (typeof id !== "string") throw new Error("actual host outcome required");
    const path = join(config.journalDir, createHash("sha256").update(id).digest("hex") + ".json");
    const retained = JSON.parse(readFileSync(path, "utf8"));
    if (!retained.request || !verifyCompletedOutcome(request.outcome, config.execution, retained.request)) throw new Error("received host result differs from intended signed outcome");
    const result = await gateway.acknowledgeDelivery(request.proof);
    process.stdout.write(JSON.stringify({id: request.id, result}) + "\n");
  } catch {process.stdout.write(JSON.stringify({error: "delivery acknowledgement unresolved"}) + "\n");}
}
await stop();
