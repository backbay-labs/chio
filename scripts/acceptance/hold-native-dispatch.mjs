// Qualification only: pause the first actual native tools/call before transport.
// A second launcher must refuse the original journal while this owner is live.
import {existsSync,writeFileSync} from 'node:fs';
import {isAbsolute} from 'node:path';
const ready=process.env.CHIO_HOLD_READY,release=process.env.CHIO_HOLD_RELEASE;
if(!ready||!release||!isAbsolute(ready)||!isAbsolute(release))throw new Error('Explicit private hold paths required');
const fetch=globalThis.fetch;let held=false;
globalThis.fetch=async function(input,options){
 let frame;try{frame=JSON.parse(options?.body);}catch{}
 if(!held&&frame?.method==='tools/call'){
  held=true;writeFileSync(ready,JSON.stringify({pid:process.pid,method:frame.method,tool:frame.params?.name,cutpoint:'native-call-before-kernel-transport'})+'\n',{flag:'wx',mode:0o600});
  const deadline=Date.now()+60000;
  while(!existsSync(release)){
   if(Date.now()>deadline)throw new Error('operator concurrency barrier expired without release');
   await new Promise(resolve=>setTimeout(resolve,25));
  }
 }
 return fetch.call(this,input,options);
};
