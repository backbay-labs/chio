// Qualification only. Preserve actual native calls and actual kernel effects;
// substitute evidence on the second response before the bridge can trust it.
import {readFileSync,openSync,writeSync,fsyncSync} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
const state=process.env.CHIO_TEST_OPERATOR_STATE;
const path=process.env.CHIO_EVIDENCE_FAULT_LOG;
const kind=process.env.CHIO_EVIDENCE_FAULT_KIND;
if(![state,path].every(value=>value&&isAbsolute(value))||!['foreign-receipt','wrong-signer','request-id'].includes(kind))throw new Error('Explicit isolated evidence-fault inputs required');
const operator=JSON.parse(readFileSync(join(state,'operator.json'),'utf8'));
const endpoint=`http://127.0.0.1:${operator.port}/mcp`;
const log=openSync(path,'wx',0o600),original=globalThis.fetch;
let calls=0,first;
globalThis.fetch=async function(input,init){
 const url=String(input instanceof Request?input.url:input);
 let request;try{request=JSON.parse(init?.body);}catch{}
 const response=await original(input,init);
 if(url!==endpoint||request?.method!=='tools/call')return response;
 calls++;
 if(calls>2)throw new Error('Unexpected native call after evidence substitution');
 const text=await response.text();let found=false;
 const modify=frame=>{
  const envelope=frame.result?._meta?.chioEvidence;
  if(!envelope?.receipt||envelope.terminalState!=='completed')return frame;
  found=true;
  if(calls===1){first=structuredClone(envelope);return frame;}
  if(!first)throw new Error('No earlier actual completed receipt to substitute');
  const current=envelope.requestId,receipt=envelope.receipt.id;
  if(kind==='foreign-receipt')envelope.receipt=structuredClone(first.receipt);
  else if(kind==='wrong-signer')envelope.receipt.kernel_key='0'.repeat(64);
  else envelope.requestId=first.requestId;
  writeSync(log,JSON.stringify({cutpoint:'after-second-actual-kernel-effect-before-verification',kind,requestId:current,receiptId:receipt,firstRequestId:first.requestId,firstReceiptId:first.receipt.id,firstReceiptSha256:createHash('sha256').update(JSON.stringify(first.receipt)).digest('hex'),foreignSignatureUnmodified:kind==='foreign-receipt'})+'\n');fsyncSync(log);
  return frame;
 };
 const contentType=response.headers.get('content-type')??'';
 const body=contentType.includes('text/event-stream')?text.split('\n').map(line=>line.startsWith('data: ')?'data: '+JSON.stringify(modify(JSON.parse(line.slice(6)))):line).join('\n'):JSON.stringify(modify(JSON.parse(text)));
 if(!found)throw new Error('No actual completed kernel evidence at requested cutpoint');
 const headers=new Headers(response.headers);headers.delete('content-length');headers.delete('content-encoding');
 return new Response(body,{status:response.status,headers});
};
