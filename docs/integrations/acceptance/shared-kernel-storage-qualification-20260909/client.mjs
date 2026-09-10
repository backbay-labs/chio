import {readFileSync, writeFileSync} from 'node:fs';
import {createMcpExecutionClient} from '/Users/connor/.local/share/chio-required-candidates/20260909/install/operator-bridge/node_modules/@chio/bridge/dist/execution.js';
const [configPath,id,path,output,ack] = process.argv.slice(2);
const config=JSON.parse(readFileSync(configPath,'utf8'));
const responses=[];
const fetchImpl=async (url,init)=>{
 const response=await fetch(url,init);
 const request=init?.body?JSON.parse(init.body):undefined;
 responses.push({url:String(url),method:init?.method,status:response.status,request,body:await response.clone().text(),observedAt:Date.now()});
 return response;
};
const client=createMcpExecutionClient({...config.execution,timeoutMs:45000,fetchImpl});
const request={tool:'write_file',arguments:{path,content:'kernel storage fault '+id+'\n'},requestId:id};
const result=await client.execute(request);
writeFileSync(output,JSON.stringify({request,result,responses},null,2)+'\n');
if(ack&&result.delivery){const acknowledged=await client.acknowledge(result);writeFileSync(output+'.ack',JSON.stringify(acknowledged,null,2)+'\n');}
console.log(JSON.stringify({state:result.state,evidence:result.evidence,reason:result.reason,output}));
