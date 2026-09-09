// Qualification only. Revoke retained authority after one actual native call
// has completed and before forwarding the next native call to the real kernel.
import {readFileSync,openSync,writeSync,fsyncSync} from 'node:fs';
import {join,isAbsolute} from 'node:path';
const state=process.env.CHIO_TEST_OPERATOR_STATE;
const configPath=process.env.CHIO_TEST_GATEWAY_CONFIG;
const logPath=process.env.CHIO_INFLIGHT_REVOCATION_LOG;
const kind=process.env.CHIO_INFLIGHT_REVOCATION_KIND;
if(![state,configPath,logPath].every(value=>value&&isAbsolute(value))||!['capability','credential'].includes(kind))throw new Error('Explicit private revocation test inputs required');
const operator=JSON.parse(readFileSync(join(state,'operator.json'),'utf8'));
const config=JSON.parse(readFileSync(configPath,'utf8'));
const endpoint=`http://127.0.0.1:${operator.port}`;
if(config.execution.endpoint.replace(/\/$/,'')!==endpoint)throw new Error('Test owner endpoint differs');
const log=openSync(logPath,'wx',0o600);
const original=globalThis.fetch;
let calls=0;
globalThis.fetch=async function(input,init){
 const url=String(input instanceof Request?input.url:input);
 let request;try{request=JSON.parse(init?.body);}catch{}
 if(url===endpoint+'/mcp'&&request?.method==='tools/call'){
  calls++;
  if(calls===2){
   const route=kind==='capability'?'/admin/revocations':`/admin/sessions/${config.execution.sessionId}/credential/revoke`;
   const body=kind==='capability'?{capability_id:config.execution.capabilityId}:{};
   const response=await original(endpoint+route,{method:'POST',headers:{Authorization:`Bearer ${operator.adminToken}`,'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(10000),redirect:'error'});
   if(!response.ok)throw new Error('Explicit test revocation failed');
   await response.json();
   writeSync(log,JSON.stringify({cutpoint:'before-second-native-kernel-call',kind,status:response.status,requestId:request.params?._meta?.chioRequestId,sessionId:config.execution.sessionId,capabilityId:config.execution.capabilityId})+'\n');fsyncSync(log);
  }
 }
 return original(input,init);
};
