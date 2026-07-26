import assert from 'node:assert/strict';
import test from 'node:test';

import { receiptHexToBytes } from '../dist/index.js';

test('receiptHexToBytes decodes prefixed hexadecimal input', () => {
  assert.deepEqual(receiptHexToBytes('0x00ff'), new Uint8Array([0, 255]));
});

test('receiptHexToBytes rejects malformed input', () => {
  assert.throws(() => receiptHexToBytes('abc'), /even number/);
  assert.throws(() => receiptHexToBytes('zz'), /hexadecimal/);
});
