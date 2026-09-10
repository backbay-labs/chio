#!/usr/bin/env node
// The trusted launcher owns model credentials and the Chio HTTP gateway.
import {readFile,writeFile,mkdir,lstat,readdir} from "node:fs/promises";
import {resolve,join,isAbsolute} from "node:path";
import {randomUUID,createHash} from "node:crypto";
import {spawn,spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import {parseArgs} from "node:util";
import {startGatewayHttp} from "@chio/bridge";
import {startModelRelay,chatGptCredential} from "../src/model-relay.mjs";
import {restrictedTools,assertRestrictedProfile} from "../src/profile.mjs";
const {values} = parseArgs({options:Object.fromEntries(["gateway-config","image","state-dir","prompt","model-auth-file"].map(name=>[name,{type:"string"}]))});
for(const name of ["gateway-config","image","state-dir","prompt"])if(!values[name])throw new Error(`Required --${name}`);
if(!/^sha256:[a-f0-9]{64}$/.test(values.image))throw new Error("Explicit immutable host image SHA256 required");
let modelCredential=process.env.OPENAI_API_KEY;
if(values["model-auth-file"]){
 const authPath=values["model-auth-file"];
 if(!isAbsolute(authPath))throw new Error("Explicit absolute native ChatGPT cache path required");
 const authInfo=await lstat(authPath);
 if(!authInfo.isFile()||authInfo.isSymbolicLink()||authInfo.mode&0o077||authInfo.uid!==process.getuid?.()||authInfo.size>1024*1024)throw new Error("Private owned native ChatGPT cache required");
 try{modelCredential=chatGptCredential(JSON.parse(await readFile(authPath,"utf8")));}catch{throw new Error("Invalid native ChatGPT cache; authenticate or refresh with native Codex login");}
}
if(!modelCredential)throw new Error("Operator OPENAI_API_KEY or --model-auth-file native ChatGPT cache required");
const subscription=typeof modelCredential!=="string";
const modelId=subscription?"gpt-5.5":"gpt-4.1-mini",providerId=subscription?"openai-codex":"chio-model";
const configPath=resolve(values["gateway-config"]),state=resolve(values["state-dir"]);
const info=await lstat(configPath);
if(!info.isFile()||info.isSymbolicLink()||info.mode&0o077||info.size>1024*1024)throw new Error("Private prepared gateway configuration required");
const config=JSON.parse(await readFile(configPath,"utf8"));
await mkdir(state,{mode:0o700});
function docker(args,input){const result=spawnSync("docker",args,{encoding:"utf8",env:process.env,input});if(result.status!==0)throw new Error(`Docker operation failed: ${result.stderr}`);return result.stdout.trim();}
const image=JSON.parse(docker(["image","inspect",values.image]))[0];
if(image.Id!==values.image)throw new Error("Host image identity changed");
const id=randomUUID(),network=`chio-required-openclaw-${id}`,relayName=`chio-openclaw-relay-${id}`,agentName=`chio-openclaw-agent-${id}`,volume=`chio-required-openclaw-state-${id}`,controlVolume=`chio-required-openclaw-control-${id}`;
const transport=await startGatewayHttp(config);
let model,watchdog,watchdogFinished,networkCreated=false,relayCreated=false;
try{
 const manifest={schema:"chio.openclaw.protected-run.v1",image:values.image,network,relayName,agentName,volume,controlVolume,sessionId:id,model:{id:modelId,authMode:typeof modelCredential==="string"?"api-key":"chatgpt-native-cache",runtime:"pi"},gatewayConfigSha256:createHash("sha256").update(await readFile(configPath)).digest("hex"),kernelAuthority:{sessionId:config.execution.sessionId,capabilityId:config.execution.capabilityId,serverId:config.execution.serverId},acceptance:"unresolved"};
 await writeFile(join(state,"launch.json"),JSON.stringify(manifest,null,2)+"\n",{mode:0o600});
 const watchdogEnv=Object.fromEntries(Object.entries(process.env).filter(([key])=>["PATH","HOME","DOCKER_HOST","DOCKER_CONTEXT","DOCKER_CONFIG","LANG"].includes(key)));
 watchdog=spawn(process.execPath,[fileURLToPath(new URL("./cleanup-watchdog.mjs",import.meta.url)),state],{env:watchdogEnv,stdio:["pipe","pipe","inherit"]});
 watchdogFinished=new Promise(resolve=>{watchdog.once("error",()=>resolve(1));watchdog.once("close",code=>resolve(code??1));});
 // Establish cleanup ownership before creating any network, volume or relay.
 await new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>reject(new Error("Cleanup watchdog did not become ready")),5000);
  let ready="";
  watchdog.stdout.on("data",bytes=>{
   ready+=bytes.toString();
   if(ready==="chio-watchdog-ready\n"){clearTimeout(timer);resolve();}
   else if(ready.length>128){clearTimeout(timer);reject(new Error("Invalid cleanup watchdog readiness"));}
  });
  watchdog.once("error",error=>{clearTimeout(timer);reject(error);});
  watchdog.once("close",()=>{clearTimeout(timer);reject(new Error("Cleanup watchdog stopped before readiness"));});
 });
 const confirmed=new Set();let confirmations=Promise.resolve();
 model=await startModelRelay(modelCredential,modelId,async results=>{
  confirmations=confirmations.then(async()=>{
   for(const result of results){
    let outcome;try{outcome=JSON.parse(result.content);}catch{continue;}
    if(outcome?.state!=="completed"||outcome.evidence!=="verified"||typeof outcome.requestId!=="string")continue;
    const identity=createHash("sha256").update(JSON.stringify(outcome)).digest("hex");
    if(confirmed.has(identity))continue;
    const acknowledgement=await transport.acknowledgeReceivedOutcome(outcome);
    if(!acknowledgement.acknowledged)throw new Error("Native host delivery unconfirmed; no next model turn");
    confirmed.add(identity);
   }
  });await confirmations;
 });
 docker(["network","create","--internal","--label","chio.task=required-agent-integrations",network]);networkCreated=true;
 docker(["volume","create","--label","chio.task=required-agent-integrations",volume]);
 docker(["run","--rm","--network","none","--read-only","--cap-drop","ALL","--cap-add","CHOWN","--user","0","--mount",`type=volume,src=${volume},dst=/state`,"--entrypoint","node",values.image,"-e","const f=require('fs');f.chmodSync('/state',0o700);f.chownSync('/state',1000,1000)"]);
 docker(["run","-d","--name",relayName,"--network",network,"--network-alias","chio-transport","--read-only","--cap-drop","ALL","--security-opt","no-new-privileges","--user","1000:1000","--pids-limit","32","--memory","256m","--env","CHIO_RELAY_CONTAINER=1","--env",`CHIO_UPSTREAM_KERNEL_PORT=${transport.port}`,"--env",`CHIO_UPSTREAM_MODEL_PORT=${model.port}`,"--entrypoint","node",values.image,"/opt/chio/proxy.mjs"]);relayCreated=true;
 docker(["network","connect","bridge",relayName]);
 const cfg={agents:{defaults:{workspace:"/state/workspace",skipBootstrap:true,skills:[],model:`${providerId}/${modelId}`,models:{[`${providerId}/${modelId}`]:{params:{transport:"sse"}}},heartbeat:{every:"0m"},timeoutSeconds:150}},
  models:{mode:"replace",providers:{[providerId]:{baseUrl:`http://chio-transport:8787/v1${subscription?"/codex":""}`,apiKey:model.token,api:model.api,agentRuntime:{id:"pi"},models:[{id:modelId,name:modelId,input:["text"],reasoning:false,contextWindow:128000,maxTokens:4096}]}}},
  tools:restrictedTools(),plugins:{enabled:true,allow:subscription?["chio-kernel","openai"]:["chio-kernel"],slots:{memory:"none"},load:{paths:["/opt/chio/node_modules/@chio/openclaw-kernel"]},entries:{"chio-kernel":{enabled:true,config:{transport:"launcher-http-v1",endpoint:"http://chio-transport:8787/mcp",tokenEnv:"CHIO_GATEWAY_TOKEN",gatewaySessionId:config.sessionId,
   toolInventory:config.tools,allowedTools:[...config.tools.map(tool=>tool.name),...(config.approval?["chio_resume"]:[])],subjectKey:config.execution.subjectKey,capabilityId:config.execution.capabilityId,serverId:config.execution.serverId,sessionId:config.execution.sessionId,trustedSigners:config.execution.trustedSigners}}}},
  commands:Object.fromEntries(["native","nativeSkills","text","bash","config","restart","mcp","plugins","debug"].map(name=>[name,false])),browser:{enabled:false},cron:{enabled:false},channels:{},hooks:{enabled:false},acp:{enabled:false},gateway:{mode:"local",bind:"loopback"}};
 assertRestrictedProfile(cfg);
 const guestConfig=join(state,"openclaw.json");await writeFile(guestConfig,JSON.stringify(cfg,null,2)+"\n",{mode:0o644,flag:"wx"});
 docker(["volume","create","--label","chio.task=required-agent-integrations",controlVolume]);
 // Stream only guest configuration into an immutable Docker volume. This works
 // without any host filesystem share or unpublished sibling checkout.
 docker(["run","--rm","-i","--network","none","--read-only","--cap-drop","ALL","--user","0","--mount",`type=volume,src=${controlVolume},dst=/config`,"--entrypoint","node",values.image,"-e","const f=require('fs');const b=f.readFileSync(0);JSON.parse(b);f.writeFileSync('/config/openclaw.json',b,{mode:0o444,flag:'wx'});const fd=f.openSync('/config/openclaw.json','r');f.fsyncSync(fd);f.closeSync(fd)"],JSON.stringify(cfg));
 const args=["run","--rm","--name",agentName,"--network",network,"--dns","127.0.0.1","--read-only","--cap-drop","ALL","--security-opt","no-new-privileges","--user","1000:1000","--pids-limit","128","--memory","2g","--tmpfs","/tmp:rw,nosuid,nodev,size=256m","--mount",`type=volume,src=${volume},dst=/state`,"--mount",`type=volume,src=${controlVolume},dst=/config,readonly`,"--env","CHIO_GATEWAY_TOKEN",values.image,"agent","--local","--session-id",id,"--message",values.prompt,"--json"];
 const host=spawn("docker",args,{env:{...process.env,CHIO_GATEWAY_TOKEN:transport.token},stdio:["ignore","pipe","pipe"]});
 const stdout=[],stderr=[];host.stdout.on("data",bytes=>{stdout.push(bytes);process.stdout.write(bytes);});host.stderr.on("data",bytes=>{stderr.push(bytes);process.stderr.write(bytes);});
 const interrupt=()=>{try{docker(["kill",agentName]);}catch{}};process.once("SIGINT",interrupt);process.once("SIGTERM",interrupt);
 const deadline=setTimeout(interrupt,180000);
 const hostCode=await new Promise((resolve,reject)=>{host.once("error",reject);host.once("close",code=>resolve(code??1));});
 clearTimeout(deadline);process.off("SIGINT",interrupt);process.off("SIGTERM",interrupt);
 await writeFile(join(state,"host.stdout.json"),Buffer.concat(stdout));await writeFile(join(state,"host.stderr.txt"),Buffer.concat(stderr));
 const records=await Promise.all((await readdir(config.journalDir)).filter(name=>name.endsWith(".json")).map(async name=>JSON.parse(await readFile(join(config.journalDir,name),"utf8"))));
 let unresolved=records.some(record=>["pending","unknown"].includes(record.state)||record.state==="completed"&&(!record.acknowledged||!record.hostDeliveryConfirmed));
 let failed=records.some(record=>["denied","not_dispatched"].includes(record.state)||record.outcome?.result?.isError===true);
 for(const event of model.events)for(const result of event.results??[]){
  try{const outcome=JSON.parse(result.content);if(outcome.state==="unknown")unresolved=true;else if(["denied","not_dispatched"].includes(outcome.state)||outcome.result?.isError===true)failed=true;else if(!["completed","awaiting_approval"].includes(outcome.state))unresolved=true;}catch{unresolved=true;}
 }
 const pending=records.some(record=>record.state==="awaiting_approval");
 const exitCode=unresolved?2:pending?4:failed?3:hostCode;
 await writeFile(join(state,"terminal.json"),JSON.stringify({hostExitCode:hostCode,exitCode,outcome:unresolved?"unresolved":pending?"awaiting_approval":failed?"protected_work_incomplete":hostCode===0?"completed":"host_failed",confirmedDeliveries:records.filter(record=>record.hostDeliveryConfirmed).length})+"\n");
 process.exitCode=exitCode;
}finally{
 await transport.close();await model?.close();
 if(model)await writeFile(join(state,"model-relay.json"),JSON.stringify(model.events,null,2)+"\n",{mode:0o600});
 if(watchdog){
  watchdog.stdin.end();const cleanupCode=await watchdogFinished;
  if(cleanupCode!==0){
   process.exitCode=2;
   try{const terminalPath=join(state,"terminal.json"),terminal=JSON.parse(await readFile(terminalPath,"utf8"));await writeFile(terminalPath,JSON.stringify({...terminal,exitCode:2,cleanup:"unresolved"})+"\n");}catch{}
  }
 }
 if(relayCreated){try{docker(["rm","-f",relayName]);}catch{}}
 if(networkCreated){try{docker(["network","rm",network]);}catch{}}
 // Keep the host state volume and private records for operator recovery.
}
