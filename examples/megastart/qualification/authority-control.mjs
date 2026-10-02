import {readFileSync,writeFileSync,mkdirSync,existsSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {randomUUID,createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const [root,bridge,mode]=process.argv.slice(2);
const {createMcpExecutionClient}=await import(pathToFileURL(join(resolve(bridge),'dist/execution.js')));
const save=(path,value)=>writeFileSync(path,JSON.stringify(value,null,2)+'\n',{mode:0o600,flag:'wx'});
const output=join(root,'control-'+randomUUID());mkdirSync(output,{mode:0o700});
const clients=[];
for(const worker of ['research-0','research-1','review-0']){
 const operator=JSON.parse(readFileSync(join(root,worker,'operator.json')));
 const path=join(output,worker);mkdirSync(path,{mode:0o700});
 save(join(path,'prepare.json'),{endpoint:`http://127.0.0.1:${operator.port}`,bearerToken:operator.agentToken,adminToken:operator.adminToken,credentialTtlSeconds:900,trustedSigners:[operator.signer],serverId:'fs',sessionId:randomUUID(),journalDir:join(path,'journal'),allowedTools:['read_text_file','write_file','edit_file','list_directory']});
 const prepared=spawnSync(process.execPath,[join(bridge,'dist/prepare-gateway.js'),join(path,'prepare.json'),join(path,'gateway.json')],{encoding:'utf8',timeout:45000});
 writeFileSync(join(path,'prepare.stderr'),prepared.stderr??'',{mode:0o600});
 if(prepared.status!==0)throw Error('Preparation failed; preserve '+path);
 const config=JSON.parse(readFileSync(join(path,'gateway.json')));
 if(config.execution.capabilityId!==operator.capability)throw Error('Worker capability changed');
 clients.push({worker,path,client:createMcpExecutionClient({...config.execution,fetchImpl:async(input,init)=>{const response=await fetch(input,init);if(!response.ok)writeFileSync(join(path,'http-'+randomUUID()+'.json'),JSON.stringify({status:response.status,body:await response.clone().text()}),{mode:0o600});return response;}})});
}
const observations=[];
async function call(index,tool,args){
 const selected=clients[index],request={requestId:randomUUID(),tool,arguments:args};save(join(selected.path,request.requestId+'.request.json'),request);
 const outcome=await selected.client.execute(request);save(join(selected.path,request.requestId+'.outcome.json'),outcome);
 if(outcome.state==='completed') {const ack=await selected.client.acknowledge(outcome);save(join(selected.path,request.requestId+'.ack.json'),ack);if(!ack.acknowledged)throw Error('Direct-client delivery acknowledgement failed');}
 if(outcome.state==='unknown'||outcome.state==='not_dispatched')throw Error('Unresolved operation; preserve '+selected.path);
 const observation={worker:selected.worker,tool,state:outcome.state,evidence:outcome.evidence,receipt:outcome.receipt?.id,reason:outcome.reason};observations.push(observation);console.log(JSON.stringify(observation));return outcome;
}
if(mode==='recovered') {
 const results=await Promise.all([call(0,'read_text_file',{path:'/workspace/source/lib.rs'}),call(1,'read_text_file',{path:'/workspace/source/tests.rs'})]);
 if(results.some(result=>result.state!=='denied'||result.evidence!=='verified'||!result.reason?.includes('invocation budget exhausted')))throw Error('Restart replenished shared capacity');
 save(join(output,'observations.json'),{evidence_class:'DIRECT_BRIDGE_REAL_KERNEL_RESOURCE',recovered_without_new_allowance:true,observations});
 process.exit(0);
}
const protectedPath=join(root,'resource/source/lib.rs');const before=createHash('sha256').update(readFileSync(protectedPath)).digest('hex');
// The restricted transport deliberately fences a denied session. Keep the
// authority exercise separate from the two sessions competing for capacity.
const refusal=await call(2,'write_file',{path:'/workspace/source/lib.rs',content:'UNAUTHORIZED'});
if(refusal.state!=='denied'||refusal.evidence!=='verified')throw Error('Expected a signed scope refusal');
if(createHash('sha256').update(readFileSync(protectedPath)).digest('hex')!==before)throw Error('Protected source changed');
await Promise.all([call(0,'read_text_file',{path:'/workspace/source/lib.rs'}),call(1,'read_text_file',{path:'/workspace/source/tests.rs'})]);
await Promise.all([call(0,'write_file',{path:'/workspace/outputs/research-0/quota.txt',content:'first'}),call(1,'write_file',{path:'/workspace/outputs/research-1/quota.txt',content:'second'})]);
const completed=observations.filter(item=>item.state==='completed');
const denied=observations.filter(item=>item.state==='denied');
if(completed.length!==3||denied.length!==2)throw Error('Shared three-call allowance did not hold');
const writes=['research-0','research-1'].filter(worker=>existsSync(join(root,'resource/outputs',worker,'quota.txt')));
if(writes.length!==1)throw Error('Exactly one competing write must reach the resource');
save(join(output,'observations.json'),{evidence_class:'DIRECT_BRIDGE_REAL_KERNEL_RESOURCE',protected_source_unchanged:true,observations});
