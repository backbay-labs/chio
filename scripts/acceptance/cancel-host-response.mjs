// Qualification only: cancel the trusted launcher after a durable completed
// effect, before the native host receives its result. Preserve the original ID.
import {ServerResponse} from 'node:http';
import {openSync,writeSync,fsyncSync,closeSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import {execFileSync} from 'node:child_process';
const path=process.env.CHIO_HOST_RESPONSE_FAULT_LOG;
const kind=process.env.CHIO_CANCEL_HOST_KIND;
if(!path||!isAbsolute(path)||!['self','hermes'].includes(kind))throw new Error('Explicit isolated cancellation inputs required');
const log=openSync(path,'wx',0o600);
const target=kind==='hermes'?process.ppid:process.pid;
if(kind==='hermes'){
 const command=execFileSync('ps',['-p',String(target),'-o','command='],{encoding:'utf8'});
 if(!command.includes('-m chio_hermes.restricted'))throw new Error('Refuse to cancel a different launcher');
}
const end=ServerResponse.prototype.end;
let cancelled=false;
ServerResponse.prototype.end=function(chunk,...args){
 let outcome;
 try{const frame=JSON.parse(String(chunk));if(frame.jsonrpc==='2.0'&&frame.result?.content?.length===1)outcome=JSON.parse(frame.result.content[0].text);}catch{}
 if(!cancelled&&outcome?.state==='completed'&&outcome.evidence==='verified'&&outcome.delivery){
  cancelled=true;
  writeSync(log,JSON.stringify({cutpoint:'operator-cancel-before-host-response',signal:'SIGTERM',launcherPid:target,gatewayPid:process.pid,requestId:outcome.requestId,receiptId:outcome.receipt?.id})+'\n');fsyncSync(log);closeSync(log);
  this.destroy();process.kill(target,'SIGTERM');return this;
 }
 return end.call(this,chunk,...args);
};
