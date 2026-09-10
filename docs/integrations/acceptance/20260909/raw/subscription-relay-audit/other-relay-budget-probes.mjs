import http from 'node:http';
import fs from 'node:fs/promises';
import * as claude from './claude-relay-source.mjs';
import * as codex from './codex-relay-source.ts';
import * as pi from './pi-relay-source.ts';
const results=[];
function request(port,path,headers,body,hold=false){
 let req;
 const promise=new Promise((resolve,reject)=>{
  req=http.request({hostname:'127.0.0.1',port,path,method:'POST',headers:{...headers,'content-type':'application/json','content-length':Buffer.byteLength(body)}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});
  req.on('error',reject);if(hold)req.flushHeaders();else req.end(body);
 });return {req,promise};
}
for(const name of ['claude','codex','pi']){
 let forwarded=0, observedBeta=null,maxRequestedOutput=0;
 globalThis.fetch=async(url,init)=>{
  forwarded++; observedBeta=init.headers['anthropic-beta']??null;
  const v=JSON.parse(init.body);maxRequestedOutput=Math.max(maxRequestedOutput,v.max_tokens??v.max_output_tokens??0);
  return new Response('{}',{status:200,headers:{'content-type':'application/json'}});
 };
 let relay,path,headers,body;
 if(name==='claude'){
  relay=await claude.startModelRelay({oauth:{authorization:'Bearer AUDIT_ONLY_FAKE',beta:'audit-required'},model:'audit-model',toolNames:[]});
  path='/v1/messages';headers={'x-api-key':relay.token,'anthropic-beta':'audit-guest-chosen'};
  body={model:'audit-model',max_tokens:1_000_000_000,messages:[{role:'user',content:'local fake upstream only'}]};
 } else {
  relay=name==='codex'?await codex.startModelRelay({kind:'chatgpt',secret:'AUDIT_ONLY_FAKE',accountId:'audit'},'audit-model'):await pi.startModelRelay({provider:'openai-codex',accessToken:'AUDIT_ONLY_FAKE',accountId:'audit'},'audit-model');
  path=name==='codex'?'/v1/responses':'/v1/codex/responses';headers={authorization:`Bearer ${relay.token}`};
  body={model:'audit-model',store:false,stream:true,input:[{role:'user',content:'local fake upstream only'}],max_output_tokens:1_000_000_000};
 }
 const payload=JSON.stringify(body);const calls=Array.from({length:110},()=>request(relay.port,path,headers,payload,true));
 await new Promise(resolve=>setTimeout(resolve,200));for(const c of calls)c.req.end(payload);
 const statuses=await Promise.all(calls.map(c=>c.promise));
 const burstForwarded=forwarded;
 const invalidControls=[];
 const variants=name==='claude'?[
  ['hosted_web_search',{...body,tools:[{type:'web_search_20250305',name:'web_search'}]}],
  ['remote_file_reference',{...body,messages:[{role:'user',content:[{type:'document',source:{type:'file',file_id:'file-audit'}}]}]}],
  ['arbitrary_url_image',{...body,messages:[{role:'user',content:[{type:'image',source:{type:'url',url:'https://example.invalid'}}]}]}]
 ]:[
  ['hosted_web_search',{...body,tools:[{type:'web_search'}]}],
  ['remote_item_reference',{...body,input:[{type:'item_reference',id:'audit-id'}]}],
  ['remote_mcp',{...body,tools:[{type:'mcp',server_url:'https://example.invalid'}]}],
  ['background_job',{...body,background:true}],
  ['previous_response_id',{...body,previous_response_id:'audit-id'}]
 ];
 for(const [control,value] of variants){const before=forwarded;const status=await request(relay.port,path,headers,JSON.stringify(value)).promise;invalidControls.push({control,status,forwarded:forwarded-before});}
 const routeBefore=forwarded;const routeStatus=await request(relay.port,'/v1/files',headers,payload).promise;
 results.push({host:name,scope:'local fake upstream only; no host inference/provider network',configuredLocalRequestBudget:null,burstRequests:110,burstForwarded,statuses:statuses.reduce((a,k)=>(a[k]=(a[k]??0)+1,a),{}),maxRequestedOutput,guestBetaObserved:observedBeta,invalidControls,arbitraryRoute:{status:routeStatus,forwarded:forwarded-routeBefore}});
 await relay.close();
}
await fs.writeFile('/tmp/chio-subscription-relay-audit-20260909/other-relay-budget-results.json',JSON.stringify(results,null,2)+'\n');
console.log(JSON.stringify(results,null,2));
