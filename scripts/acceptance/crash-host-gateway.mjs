// Qualification-only: kill the trusted gateway after its completed durable
// result exists, before the actual native host receives the HTTP response.
import {ServerResponse} from 'node:http';
import {openSync, writeSync, fsyncSync, closeSync} from 'node:fs';
import {isAbsolute} from 'node:path';
const path = process.env.CHIO_GATEWAY_CRASH_FAULT_LOG;
if (!path || !isAbsolute(path)) throw new Error('Fresh absolute crash evidence path required');
const log = openSync(path, 'wx', 0o600);
const end = ServerResponse.prototype.end;
ServerResponse.prototype.end = function(chunk, ...args) {
  if (typeof chunk === 'string' || Buffer.isBuffer(chunk)) {
    let outcome;
    try {
      const frame = JSON.parse(String(chunk));
      const blocks = frame.result?.content;
      if (frame.jsonrpc === '2.0' && blocks?.length === 1 && blocks[0].type === 'text') outcome = JSON.parse(blocks[0].text);
    } catch { /* Other protocol traffic cannot trigger this cutpoint. */ }
    if (outcome?.state === 'completed' && outcome.evidence === 'verified' && outcome.delivery) {
      writeSync(log, JSON.stringify({cutpoint:'trusted-gateway-crash-before-host-response', pid:process.pid,
        requestId:outcome.requestId, receiptId:outcome.receipt?.id}) + '\n');
      fsyncSync(log); closeSync(log);
      process.kill(process.pid, 'SIGKILL');
    }
  }
  return end.call(this, chunk, ...args);
};
