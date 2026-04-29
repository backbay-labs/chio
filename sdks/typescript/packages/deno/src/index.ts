type WasmExport = (...args: never[]) => unknown;

export type DenoWasmInput =
  | URL
  | Request
  | Response
  | BufferSource
  | WebAssembly.Module;

type DenoWasmGlueModule = {
  default: (input?: { module_or_path: DenoWasmInput } | DenoWasmInput) => Promise<unknown>;
  evaluate: (requestJson: string) => unknown;
  mint_signing_seed_hex: () => string;
  sign_receipt: (bodyJson: string, signingSeedHex: string) => unknown;
  verify_capability: (tokenJson: string, authorityPubHex: string) => unknown;
  verify_receipt: (envelope: Uint8Array, trustedIssuers?: unknown) => unknown;
};

type DenoWasmBindings = {
  evaluate: DenoWasmGlueModule['evaluate'];
  mint_signing_seed_hex: DenoWasmGlueModule['mint_signing_seed_hex'];
  sign_receipt: DenoWasmGlueModule['sign_receipt'];
  verify_capability: DenoWasmGlueModule['verify_capability'];
  verify_receipt: DenoWasmGlueModule['verify_receipt'];
};

let wasmReady: Promise<DenoWasmBindings> | undefined;

export function resolveDenoWasmUrl(baseUrl: string | URL = import.meta.url): URL {
  return new URL('./web/chio_kernel_browser_bg.wasm', baseUrl);
}

export function resolveDenoWasmGlueUrl(baseUrl: string | URL = import.meta.url): URL {
  return new URL('./web/chio_kernel_browser.js', baseUrl);
}

async function importDenoWasmGlue(baseUrl: string | URL): Promise<DenoWasmGlueModule> {
  return await import(resolveDenoWasmGlueUrl(baseUrl).href) as DenoWasmGlueModule;
}

function assertWasmExport(value: unknown, name: string): asserts value is WasmExport {
  if (typeof value !== 'function') {
    throw new Error(`missing wasm export: ${name}`);
  }
}

function validateDenoWasmGlue(module: DenoWasmGlueModule): void {
  assertWasmExport(module.default, 'default');
  assertWasmExport(module.evaluate, 'evaluate');
  assertWasmExport(module.mint_signing_seed_hex, 'mint_signing_seed_hex');
  assertWasmExport(module.sign_receipt, 'sign_receipt');
  assertWasmExport(module.verify_capability, 'verify_capability');
  assertWasmExport(module.verify_receipt, 'verify_receipt');
}

export async function loadDenoWasm(
  input: DenoWasmInput | Promise<DenoWasmInput> = fetch(resolveDenoWasmUrl()),
): Promise<DenoWasmBindings> {
  if (wasmReady === undefined) {
    wasmReady = (async () => {
      const module = await importDenoWasmGlue(import.meta.url);
      validateDenoWasmGlue(module);
      await module.default({ module_or_path: await input });
      return {
        evaluate: module.evaluate,
        mint_signing_seed_hex: module.mint_signing_seed_hex,
        sign_receipt: module.sign_receipt,
        verify_capability: module.verify_capability,
        verify_receipt: module.verify_receipt,
      };
    })();
  }

  return wasmReady;
}

export async function evaluate(requestJson: string): Promise<unknown> {
  return (await loadDenoWasm()).evaluate(requestJson);
}

export async function mint_signing_seed_hex(): Promise<string> {
  return (await loadDenoWasm()).mint_signing_seed_hex();
}

export async function sign_receipt(bodyJson: string, signingSeedHex: string): Promise<unknown> {
  return (await loadDenoWasm()).sign_receipt(bodyJson, signingSeedHex);
}

export async function verify_capability(tokenJson: string, authorityPubHex: string): Promise<unknown> {
  return (await loadDenoWasm()).verify_capability(tokenJson, authorityPubHex);
}

export async function verify_receipt(
  envelope: Uint8Array,
  trustedIssuers?: string | string[],
): Promise<unknown> {
  return (await loadDenoWasm()).verify_receipt(envelope, trustedIssuers);
}

export async function verifyReceiptHex(
  envelopeHex: string,
  trustedIssuers?: string | string[],
): Promise<unknown> {
  const normalized = envelopeHex.startsWith('0x') ? envelopeHex.slice(2) : envelopeHex;
  if (normalized.length % 2 !== 0) {
    throw new Error('receipt hex must have an even number of characters');
  }
  if (!/^[0-9a-fA-F]*$/.test(normalized)) {
    throw new Error('receipt hex must contain only hexadecimal characters');
  }

  const pairs = normalized.match(/.{2}/g) ?? [];
  const envelope = Uint8Array.from(pairs.map(byte => Number.parseInt(byte, 16)));
  return verify_receipt(envelope, trustedIssuers);
}

export default async function handler(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== '/__chio_deno_smoke') {
    return new Response('not found', { status: 404 });
  }

  const bindings = await loadDenoWasm();
  return Response.json({
    package: '@chio-protocol/deno',
    runtime: 'deno',
    wasmTarget: 'web',
    wasmUrl: resolveDenoWasmUrl().href,
    verifyReceipt: typeof bindings.verify_receipt === 'function',
  });
}
