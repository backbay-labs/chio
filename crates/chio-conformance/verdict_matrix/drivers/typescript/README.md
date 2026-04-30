# TypeScript Node HTTP Verdict Driver

This driver adapts the verdict matrix scenarios to the TypeScript
`@chio-protocol/node-http` SDK. It builds `ChioHttpRequest` values through the
SDK helper, calls `ChioSidecarClient.evaluate`, and projects the returned SDK
verdict into the matrix tuple:

- `verdict`
- `reason_code`
- `scope_set`

The conformance package runs the driver with:

```bash
cd sdks/typescript/packages/conformance
npm test -- verdict_matrix
```
