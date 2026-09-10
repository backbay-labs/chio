// Fixed localhost bridge for Docker Desktop host services. It accepts only the
// configured model and kernel paths and never forwards to a model-chosen URL.
import http from "node:http";

const kernelPort = Number(process.env.CHIO_UPSTREAM_KERNEL_PORT);
const modelPort = Number(process.env.CHIO_UPSTREAM_MODEL_PORT);
if (![kernelPort, modelPort].every((port) => Number.isInteger(port) && port > 0 && port < 65536)) throw new Error("Explicit upstream ports required");
http.createServer((request, response) => {
  const model = request.url.startsWith("/v1/");
  if (!model && request.url !== "/mcp") { response.writeHead(404); response.end(); return; }
  const upstream = http.request({ hostname: "host.docker.internal", port: model ? modelPort : kernelPort, path: request.url, method: request.method, headers: { ...request.headers, host: `127.0.0.1:${model ? modelPort : kernelPort}` } }, (incoming) => {
    response.writeHead(incoming.statusCode, incoming.headers);
    incoming.pipe(response);
  });
  upstream.on("error", () => { response.writeHead(502); response.end("upstream unavailable"); });
  request.on("aborted", () => upstream.destroy());
  request.pipe(upstream);
}).listen(8787, process.env.CHIO_RELAY_CONTAINER === "1" ? "0.0.0.0" : "127.0.0.1");
