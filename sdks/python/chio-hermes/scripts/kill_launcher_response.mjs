// Qualification only: kill the isolated Hermes parent after a committed result.
import {ServerResponse} from 'node:http';
import {openSync,writeSync,fsyncSync,closeSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const target=process.ppid;
const command=execFileSync('ps',['-p',String(target),'-o','command='],{encoding:'utf8'}).trim();
if(!command.includes('-m chio_hermes.restricted'))throw new Error('Wrong isolated launcher');
const log=openSync(process.env.CHIO_HOST_RESPONSE_FAULT_LOG,'wx',0o600);
const end=ServerResponse.prototype.end;let used=false;
ServerResponse.prototype.end=function(chunk,...args){
 let o;try{const f=JSON.parse(String(chunk));if(f.result?.content?.length===1)o=JSON.parse(f.result.content[0].text);}catch{}
 if(!used&&o?.state==='completed'&&o.evidence==='verified'&&o.delivery){
  used=true;
  const all=execFileSync('ps',['-axo','pid=,ppid=,pgid=,command='],{encoding:'utf8'}).split('\n').map(l=>l.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/)).filter(Boolean).map(m=>({pid:+m[1],ppid:+m[2],pgid:+m[3],command:m[4]}));
  const ids=new Set([target]);let count;do{count=ids.size;for(const p of all)if(ids.has(p.ppid))ids.add(p.pid);}while(ids.size!==count);
  const children=all.filter(p=>ids.has(p.pid)&&p.pid!==target&&!p.command.startsWith('ps '));
  writeSync(log,JSON.stringify({signal:'SIGKILL',cutpoint:'launcher-killed-before-host-response',launcherPid:target,gatewayPid:process.pid,requestId:o.requestId,children})+'\n');fsyncSync(log);closeSync(log);
  this.destroy();process.kill(target,'SIGKILL');return this;
 }
 return end.call(this,chunk,...args);
};
