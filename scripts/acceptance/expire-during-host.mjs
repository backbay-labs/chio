// Qualification only. Hold the second actual native request until its real
// owner-issued capability and bounded delegated credential expire together.
// The original fetch, body, headers and AbortSignal are preserved.
import {readFileSync,openSync,writeSync,fsyncSync} from 'node:fs';
import {isAbsolute,dirname,join} from 'node:path';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {subscribe} from 'node:diagnostics_channel';

const configPath=process.env.CHIO_TEST_GATEWAY_CONFIG;
const bindingPath=process.env.CHIO_INFLIGHT_EXPIRY_BINDING;
const logPath=process.env.CHIO_INFLIGHT_EXPIRY_LOG;
if(![configPath,bindingPath,logPath].every(value=>value&&isAbsolute(value)))throw Error('Explicit expiry fixture paths required');
const configBytes=readFileSync(configPath);
const config=JSON.parse(configBytes);
const binding=JSON.parse(readFileSync(bindingPath,'utf8'));
const cap=binding.capability;
const endpoint=config.execution.endpoint.replace(/\/$/,'');
const hash=value=>createHash('sha256').update(value).digest('hex');
if(binding.gatewayConfig!==configPath||binding.configurationSha256!==hash(configBytes)||cap.id!==config.execution.capabilityId||cap.subject!==config.execution.subjectKey||binding.sessionCredential.sessionId!==config.execution.sessionId||cap.expires_at!==config.sessionCredential.expiresAt)throw Error('Expiry fixture authority binding differs');
if(!(cap.expires_at>cap.issued_at&&cap.expires_at-cap.issued_at<=45))throw Error('Real short-lived capability required');
const fd=openSync(logPath,'wx',0o600);
function record(value){writeSync(fd,JSON.stringify(value)+'\n');fsyncSync(fd);}
if(binding.host==='openclaw'){
 // Observe the actual launcher's initialized HTTP session without reading or
 // consuming request/response bodies, changing headers, or logging bearer data.
 // https://nodejs.org/api/diagnostics_channel.html#event-httpserverresponsefinish
 const sessionFd=openSync(join(dirname(logPath),'openclaw-gateway-session.jsonl'),'wx',0o600);
 subscribe('http.server.response.finish',({request,response})=>{
  const sessionId=response.getHeader('mcp-session-id');
  const localPort=request.socket.localPort;
  if(request.method!=='POST'||request.url!=='/mcp'||response.statusCode!==200||request.headers['mcp-session-id']||request.headers.host!==`127.0.0.1:${localPort}`||typeof sessionId!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(sessionId))return;
  writeSync(sessionFd,JSON.stringify({event:'gateway-http-initialized',sessionId,localPort,method:request.method,path:request.url,status:response.statusCode,observedAtMs:Date.now()})+'\n');fsyncSync(sessionFd);
 });
}
const original=globalThis.fetch;
let calls=0,firstSucceeded=false;
globalThis.fetch=async function(input,init){
 const url=String(input instanceof Request?input.url:input);
 let frame;try{frame=JSON.parse(init?.body);}catch{}
 if(url!==endpoint+'/mcp'||frame?.method!=='tools/call')return original(input,init);
 calls++;
 const index=calls;
 const expected=binding.nativeRequests[index-1];
 const requestId=frame.params?._meta?.chioRequestId;
 const headers=new Headers(init?.headers);
 const headerSnapshot=Array.from(headers.entries()).sort(([a],[b])=>a.localeCompare(b));
 const observedSessionId=headers.get('mcp-session-id');
 const observedProtocolVersion=headers.get('mcp-protocol-version');
 if(init.method!=='POST'||observedSessionId!==config.execution.sessionId||observedProtocolVersion!=='2025-11-25'||!expected||frame.params?.name!==expected.tool||!isDeepStrictEqual(frame.params?.arguments,expected.arguments)||typeof requestId!=='string'||headers.get('authorization')!==`Bearer ${config.execution.bearerToken}`||!(init.signal instanceof AbortSignal))throw Error('Actual native request differs from bound expiry case');
 const originalSignal=init.signal;
 const requestBodySha256=hash(init.body);
 const identity={index,requestId,requestBodySha256,method:init.method,protocolVersion:observedProtocolVersion,tool:frame.params.name,arguments:frame.params.arguments,sessionId:observedSessionId,subjectKey:cap.subject,capabilityId:cap.id,capabilityExpiresAt:cap.expires_at,credentialExpiresAt:config.sessionCredential.expiresAt};
 const heldAtMs=Date.now();
 if(heldAtMs>=cap.expires_at*1000||init.signal?.aborted)throw Error('Native request missed its valid authority window');
 record({event:'native-request',...identity,heldAtMs,signalAborted:false,callerHeaderMatches:true,firstSucceeded});
 if(index===2){
  if(!firstSucceeded)throw Error('No healthy first native request before expiry hold');
  const releaseAtMs=cap.expires_at*1000+1000;
  if(releaseAtMs-heldAtMs>21000)throw Error('Expiry hold exceeds bounded unchanged transport window');
  while(Date.now()<releaseAtMs){
   if(init.signal?.aborted){record({event:'client-aborted',...identity,observedAtMs:Date.now()});throw Error('Client aborted before actual kernel expiry response');}
   await new Promise(resolve=>setTimeout(resolve,Math.min(25,releaseAtMs-Date.now())));
  }
  const releasedHeaders=Array.from(new Headers(init.headers).entries()).sort(([a],[b])=>a.localeCompare(b));
  if(init.method!=='POST'||init.signal!==originalSignal||init.signal.aborted||hash(init.body)!==requestBodySha256||!isDeepStrictEqual(releasedHeaders,headerSnapshot)||hash(readFileSync(configPath))!==binding.configurationSha256)throw Error('Original request signal or authority changed during hold');
  record({event:'released-to-kernel',...identity,releasedAtMs:Date.now(),holdMilliseconds:Date.now()-heldAtMs,signalAborted:false,originalTransportUnchanged:true});
 }
 let response;
 try{response=await original(input,init);}catch(error){record({event:'transport-error',...identity,observedAtMs:Date.now(),signalAborted:Boolean(init.signal?.aborted),errorName:error.name});throw error;}
 const body=await response.clone().text();
 record({event:'kernel-response',...identity,receivedAtMs:Date.now(),status:response.status,authenticateHeader:response.headers.get('www-authenticate'),body,bodySha256:hash(body),signalAborted:Boolean(init.signal?.aborted)});
 if(index===1)firstSucceeded=response.ok;
 return response;
};
