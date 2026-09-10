import http from 'node:http';
const {startModelRelay}=await import(process.argv[2]);
let forwarded=0;globalThis.fetch=async()=>{forwarded++;return new Response('{"choices":[]}',{status:200,headers:{'content-type':'application/json'}});};
const relay=await startModelRelay('audit-dummy-secret');
const body=JSON.stringify({model:'gpt-4.1-mini',messages:[{role:'user',content:'local audit only'}],max_tokens:1});
const pending=[];
for(let i=0;i<110;i++){
 let request;const result=new Promise((resolve,reject)=>{
  request=http.request({hostname:'127.0.0.1',port:relay.port,path:'/v1/chat/completions',method:'POST',headers:{Authorization:`Bearer ${relay.token}`,'content-type':'application/json','content-length':Buffer.byteLength(body)}},response=>{response.resume();response.on('end',()=>resolve(response.statusCode));});request.on('error',reject);request.flushHeaders();
 });pending.push({request,result});
}
await new Promise(resolve=>setTimeout(resolve,400));for(const item of pending)item.request.end(body);
const statuses=await Promise.all(pending.map(x=>x.result));
console.log(JSON.stringify({probe:'overlapping request bodies; local fake upstream only',expectedBudget:100,requests:pending.length,forwarded,statuses:statuses.reduce((a,k)=>(a[k]=(a[k]??0)+1,a),{})}));await relay.close();
