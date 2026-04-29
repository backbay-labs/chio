import {
  resolveDenoWasmGlueUrl,
  resolveDenoWasmUrl,
  verifyReceiptHex,
} from '../src/index.ts';

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function assertEquals<T>(actual: T, expected: T): void {
  if (actual !== expected) {
    throw new Error(`expected ${String(expected)}, got ${String(actual)}`);
  }
}

async function assertRejects(fn: () => Promise<unknown>, expectedMessage: string): Promise<void> {
  try {
    await fn();
  } catch (error) {
    assert(error instanceof Error, 'expected Error rejection');
    assert(
      error.message.includes(expectedMessage),
      `expected rejection message to include ${expectedMessage}`,
    );
    return;
  }

  throw new Error('expected rejection');
}

Deno.test('resolves wasm-pack web artifacts relative to the package entrypoint', () => {
  const distEntrypoint = new URL('../dist/index.js', import.meta.url);
  assertEquals(
    resolveDenoWasmUrl(distEntrypoint).href,
    new URL('../dist/web/chio_kernel_browser_bg.wasm', import.meta.url).href,
  );
  assertEquals(
    resolveDenoWasmGlueUrl(distEntrypoint).href,
    new URL('../dist/web/chio_kernel_browser.js', import.meta.url).href,
  );
});

Deno.test('validates receipt hex before loading wasm', async () => {
  await assertRejects(
    () => verifyReceiptHex('abc'),
    'receipt hex must have an even number of characters',
  );
  await assertRejects(
    () => verifyReceiptHex('zz'),
    'receipt hex must contain only hexadecimal characters',
  );
});
