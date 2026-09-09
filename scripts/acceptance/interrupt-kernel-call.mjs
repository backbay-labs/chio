// Qualification only: interrupt the second actual host tool call at the
// trusted gateway's kernel transport boundary. Do not synthesize host calls.
import {readFileSync,openSync,writeSync,fsyncSync} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {execFileSync} from 'node:child_process';
const state=process.env.CHIO_TEST_OPERATOR_STATE;
const logPath=process.env.CHIO_KERNEL_FAULT_LOG;
const kind=process.env.CHIO_KERNEL_FAULT_KIND;
if(![state,logPath].every(value=>value&&isAbsolute(value))||!['killed','malformed','timeout'].includes(kind))throw new Error('Explicit private kernel-fault test inputs required');
const operator=JSON.parse(readFileSync(join(state,'operator.json'),'utf8'));
const endpoint=`http://127.0.0.1:${operator.port}/mcp`;
const log=openSync(logPath,'wx',0o600);
const original=globalThis.fetch;
let calls=0;
function record(value){writeSync(log,JSON.stringify(value)+'\n');fsyncSync(log);}
globalThis.fetch=async function(input,init){
 const url=String(input instanceof Request?input.url:input);
 let request;try{request=JSON.parse(init?.body);}catch{}
 if(url===endpoint&&request?.method==='tools/call'&&++calls===2){
  const event={cutpoint:'before-second-native-kernel-call',kind,requestId:request.params?._meta?.chioRequestId};
  if(kind==='killed'){
   const pid=Number(readFileSync(join(state,'kernel.pid'),'utf8').trim());
   const command=execFileSync('ps',['-p',String(pid),'-o','command='],{encoding:'utf8'});
   if(!Number.isSafeInteger(pid)||pid<=1||!command.includes(operator.command[0])||!command.includes(join(state,'sessions.sqlite')))throw new Error('Refuse to signal a different owner');
   process.kill(pid,'SIGKILL');record({...event,pid,signal:'SIGKILL'});
   // The recorded process is the isolated real kernel, not a mock endpoint.
   await new Promise(resolve=>setTimeout(resolve,100));
  }else if(kind==='malformed'){
   record({...event,injection:'invalid JSON response; original call not forwarded'});
   return new Response('{malformed kernel response',{status:200,headers:{'Content-Type':'application/json'}});
  }else{
   record({...event,injection:'no kernel response until configured transport deadline; original call not forwarded'});
   if(!init?.signal)throw new Error('No transport deadline signal');
   await new Promise((resolve,reject)=>{
    if(init.signal.aborted)reject(init.signal.reason);
    else init.signal.addEventListener('abort',()=>reject(init.signal.reason),{once:true});
   });
  }
 }
 return original(input,init);
};
