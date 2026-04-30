# TypeScript Node HTTP Verdict Driver

This driver adapts the verdict matrix scenarios to the TypeScript
`@chio-protocol/node-http` SDK. It builds `ChioHttpRequest` values through the
SDK helper, calls `ChioSidecarClient.evaluate`, and projects the returned SDK
verdict into the matrix tuple:

- `verdict`
- `reason_code`
- `scope_set`

The TypeScript SDK is a transport client, not an embedded kernel. The driver
therefore reports scenarios as unsupported unless `CHIO_VERDICT_MATRIX_SIDECAR_URL`
or `CHIO_SIDECAR_URL` points at a live Chio sidecar that emits verdict matrix
receipt metadata. It does not stub `fetch` or synthesize verdicts from scenario
fields.

The conformance package runs the driver with:

```bash
cd sdks/typescript/packages/conformance
npm test -- verdict_matrix
```
