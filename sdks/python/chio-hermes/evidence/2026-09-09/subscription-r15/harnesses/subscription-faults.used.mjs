// Operator-only bounded fault injection. Never loaded in the protected child.
import http from 'node:http';
import fs, { appendFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { dirname, resolve } from 'node:path';

const mode = process.env.CHIO_SUBSCRIPTION_FAULT;
const log = process.env.CHIO_SUBSCRIPTION_FAULT_LOG;
const permitted = ['init-malformed', 'init-timeout', 'init-crash', 'hold-completed',
  'hold-before-dispatch', 'kernel-network-refused', 'journal-before-dispatch', 'journal-after-effect'];
if (!permitted.includes(mode) || !log) throw new Error('explicit bounded fault required');
let injected = false;
const record = (value) => appendFileSync(log, JSON.stringify({mode, at: new Date().toISOString(), parentPid: process.pid, ...value}) + '\n', {mode: 0o600});
if (mode === 'hold-before-dispatch' || mode === 'kernel-network-refused') {
  const endpoint = process.env.CHIO_SUBSCRIPTION_KERNEL_ENDPOINT;
  if (!endpoint?.startsWith('http://127.0.0.1:')) throw new Error('explicit isolated kernel endpoint required');
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async function(input, init) {
    let request;
    try { request = JSON.parse(init?.body); } catch {}
    const url = String(input instanceof Request ? input.url : input);
    if (url === endpoint && request?.method === 'tools/call' && ++calls === (mode === 'hold-before-dispatch' ? 1 : 2)) {
      injected = true;
      record({cutpoint: 'before-native-kernel-dispatch', requestId: request.params?._meta?.chioRequestId,
        transport: mode === 'kernel-network-refused' ? 'redirect-selected-request-to-explicit-refused-port' : 'hold-until-native-cancellation'});
      if (mode === 'kernel-network-refused') {
        const target = process.env.CHIO_SUBSCRIPTION_REFUSED_ENDPOINT;
        if (!target?.startsWith('http://127.0.0.1:') || target === endpoint) throw new Error('explicit different refused port required');
        return originalFetch(target, init);
      }
      if (!init?.signal) throw new Error('bounded transport cancellation signal required');
      return new Promise((_, reject) => {
        if (init.signal.aborted) reject(init.signal.reason);
        else init.signal.addEventListener('abort', () => reject(init.signal.reason), {once: true});
      });
    }
    return originalFetch(input, init);
  };
}
if (mode.startsWith('journal-')) {
  const journal = process.env.CHIO_SUBSCRIPTION_JOURNAL;
  if (!journal || resolve(journal) !== journal) throw new Error('explicit dedicated journal path required');
  const descriptors = new Set();
  const open = fs.openSync, write = fs.writeFileSync, close = fs.closeSync;
  fs.openSync = function(path, ...args) {
    const descriptor = open.call(this, path, ...args);
    if (typeof path === 'string' && dirname(path) === journal && path.endsWith('.tmp')) descriptors.add(descriptor);
    return descriptor;
  };
  fs.closeSync = function(descriptor) { descriptors.delete(descriptor); return close.call(this, descriptor); };
  fs.writeFileSync = function(descriptor, data, ...args) {
    if (!injected && descriptors.has(descriptor)) {
      let value;
      try { value = JSON.parse(String(data)); } catch {}
      const target = mode === 'journal-before-dispatch' ? 'pending' : 'completed';
      if (value?.state === target) {
        injected = true;
        record({cutpoint: target === 'pending' ? 'before-reservation-persistence-and-dispatch' : 'after-verified-effect-before-completion-persistence',
          requestId: value.requestId, attemptedState: value.state, errorCode: 'EIO'});
        throw Object.assign(new Error('designated operation journal write failure'), {code: 'EIO'});
      }
    }
    return write.call(this, descriptor, data, ...args);
  };
  syncBuiltinESMExports();
}
const originalEnd = http.ServerResponse.prototype.end;
http.ServerResponse.prototype.end = function (chunk, ...rest) {
  if (!injected && this.req?.url === '/mcp') {
    let body;
    try { body = JSON.parse(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)); } catch {}
    const initializing = body?.result?.serverInfo?.name === 'chio-protected-gateway';
    let completed = false;
    try {
      const outcome = JSON.parse(body?.result?.content?.[0]?.text);
      completed = outcome.state === 'completed' && outcome.evidence === 'verified';
    } catch {}
    if ((mode.startsWith('init-') && initializing) || (mode === 'hold-completed' && completed)) {
      injected = true;
      record({cutpoint: initializing ? 'before-initialize-response-delivery' : 'after-verified-effect-before-host-delivery'});
      if (mode === 'init-crash') process.exit(86);
      if (mode === 'init-malformed') return originalEnd.call(this, '{"invalid":', ...rest);
      return this; // Intentionally retain the response until the host times out or is interrupted.
    }
  }
  return originalEnd.call(this, chunk, ...rest);
};
