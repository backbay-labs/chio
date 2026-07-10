import { receiptHexToBytes } from '@chio-protocol/wasm-core';
import init, {
  evaluate as wasmEvaluate,
  mint_signing_seed_hex as wasmMintSigningSeedHex,
  sign_receipt as wasmSignReceipt,
  type InitInput,
  verify_capability as wasmVerifyCapability,
  verify_receipt as wasmVerifyReceipt,
} from './web/chio_kernel_browser.js';

export const config = { runtime: 'edge' } as const;

export type EdgeWasmInput = InitInput | Promise<InitInput>;

type EdgeWasmBindings = {
  evaluate: typeof wasmEvaluate;
  mint_signing_seed_hex: typeof wasmMintSigningSeedHex;
  sign_receipt: typeof wasmSignReceipt;
  verify_capability: typeof wasmVerifyCapability;
  verify_receipt: typeof wasmVerifyReceipt;
};

let wasmReady: Promise<EdgeWasmBindings> | undefined;

export async function loadEdgeWasm(
  input: EdgeWasmInput = new URL('./web/chio_kernel_browser_bg.wasm', import.meta.url),
): Promise<EdgeWasmBindings> {
  if (wasmReady === undefined) {
    wasmReady = init({ module_or_path: input }).then(() => ({
      evaluate: wasmEvaluate,
      mint_signing_seed_hex: wasmMintSigningSeedHex,
      sign_receipt: wasmSignReceipt,
      verify_capability: wasmVerifyCapability,
      verify_receipt: wasmVerifyReceipt,
    }));
  }

  return wasmReady;
}

export async function evaluate(requestJson: string): Promise<unknown> {
  return (await loadEdgeWasm()).evaluate(requestJson);
}

export async function mint_signing_seed_hex(): Promise<string> {
  return (await loadEdgeWasm()).mint_signing_seed_hex();
}

export async function sign_receipt(bodyJson: string, signingSeedHex: string): Promise<unknown> {
  return (await loadEdgeWasm()).sign_receipt(bodyJson, signingSeedHex);
}

export async function verify_capability(tokenJson: string, authorityPubHex: string): Promise<unknown> {
  return (await loadEdgeWasm()).verify_capability(tokenJson, authorityPubHex);
}

export async function verify_receipt(
  envelope: Uint8Array,
  trustedIssuers?: string | string[],
): Promise<unknown> {
  return (await loadEdgeWasm()).verify_receipt(envelope, trustedIssuers);
}

export async function verifyReceiptHex(
  envelopeHex: string,
  trustedIssuers?: string | string[],
): Promise<unknown> {
  return verify_receipt(receiptHexToBytes(envelopeHex), trustedIssuers);
}

export default async function handler(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== '/__chio_edge_smoke') {
    return new Response('not found', { status: 404 });
  }

  const bindings = await loadEdgeWasm();
  return Response.json({
    package: '@chio-protocol/edge',
    runtime: config.runtime,
    wasmTarget: 'web',
    verifyReceipt: typeof bindings.verify_receipt === 'function',
  });
}
