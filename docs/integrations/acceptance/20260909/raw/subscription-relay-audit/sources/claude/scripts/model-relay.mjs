import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
const object=value=>Boolean(value)&&typeof value==="object"&&!Array.isArray(value);
const keys=(value,allowed)=>Object.keys(value).every(key=>allowed.includes(key));
const cache=value=>value===undefined || object(value)&&keys(value,["type","ttl"])&&value.type==="ephemeral"&&[undefined,"5m","1h"].includes(value.ttl);
function text(value) {
  return typeof value==="string" || Array.isArray(value)&&value.every(block=>object(block)&&keys(block,["type","text","cache_control"])&&block.type==="text"&&typeof block.text==="string"&&cache(block.cache_control));
}
export function validateModelRequest(body,model,toolNames) {
  if (!object(body) || !keys(body,["model","max_tokens","messages","system","stream","tools","tool_choice","temperature","top_p","top_k","stop_sequences","metadata","thinking","output_config","cache_control"]) || body.model!==model || !Array.isArray(body.messages) || !text(body.system??"") || !cache(body.cache_control)) throw new Error("request exceeds selected Messages mode");
  if (body.tools!==undefined && (!Array.isArray(body.tools) || body.tools.some(tool=>!object(tool)||!keys(tool,["name","description","input_schema","cache_control","type","defer_loading","strict"])||![undefined,"custom"].includes(tool.type)||!toolNames.has(tool.name)||!object(tool.input_schema)||!cache(tool.cache_control)))) throw new Error("hosted or alternate tools are unavailable");
  if (body.tool_choice!==undefined && (!object(body.tool_choice)||!keys(body.tool_choice,["type","name","disable_parallel_tool_use"])||!["auto","none","any","tool"].includes(body.tool_choice.type)||body.tool_choice.type==="tool"&&!toolNames.has(body.tool_choice.name))) throw new Error("alternate tool choice is unavailable");
  for (const message of body.messages) {
    if (!object(message)||!keys(message,["role","content"])||!["user","assistant"].includes(message.role)) throw new Error("only inline message history is supported");
    if (typeof message.content==="string") continue;
    if (!Array.isArray(message.content)) throw new Error("inline content is required");
    for (const block of message.content) {
      if (!object(block)) throw new Error("invalid inline content");
      if (block.type==="text"&&text([block])) continue;
      if (block.type==="tool_use"&&keys(block,["type","id","name","input","cache_control"])&&typeof block.id==="string"&&typeof block.name==="string"&&/^[A-Za-z0-9_.-]{1,160}$/.test(block.name)&&object(block.input)&&cache(block.cache_control)) continue;
      if (block.type==="tool_result"&&keys(block,["type","tool_use_id","content","is_error","cache_control"])&&typeof block.tool_use_id==="string"&&text(block.content??"")&&cache(block.cache_control)) continue;
      throw new Error("only inline text and configured client tool history are supported");
    }
  }
  if (body.thinking!==undefined && (!object(body.thinking)||body.thinking.type!=="disabled"||!keys(body.thinking,["type"]))) throw new Error("this text-only mode requires thinking disabled");
  if (body.output_config!==undefined && (!object(body.output_config)||!keys(body.output_config,["effort"])||!["low","medium","high","max"].includes(body.output_config.effort))) throw new Error("unsupported output configuration");
  // These values cannot authorize remote tools, references, files or background work.
  if (body.metadata!==undefined && (!object(body.metadata)||!keys(body.metadata,["user_id"]))) throw new Error("unsupported metadata");
}
export async function startModelRelay({upstreamBaseUrl="https://api.anthropic.com",apiKey,oauth,model,toolNames,onToolResults}) {
  const upstream=new URL(upstreamBaseUrl);
  if (oauth && upstream.origin!=="https://api.anthropic.com") throw new Error("Native subscription authentication requires the fixed Anthropic origin");
  if ((!apiKey && !oauth) || (apiKey && oauth) || (oauth && (!oauth.authorization?.startsWith("Bearer ") || !oauth.beta)) || upstream.username || upstream.password || upstream.search || upstream.hash || upstream.pathname!=="/" || !(upstream.origin==="https://api.anthropic.com" || upstream.protocol==="http:"&&upstream.hostname==="127.0.0.1"&&upstream.port)) throw new Error("explicit API or native subscription credential and qualified provider or localhost fixture origin required");
  const token=randomBytes(32).toString("hex"),events=[];
  const server=createServer(async (request,response)=>{
    const controller=new AbortController();response.on("close",()=>controller.abort());
    const event={method:request.method,path:request.url,forwarded:false};events.push(event);
    try {
      const target=new URL(request.url,"http://127.0.0.1");
      if (request.method!=="POST" || !["/v1/messages","/v1/messages/count_tokens"].includes(target.pathname) || [...target.searchParams].some(([key,value])=>key!=="beta"||value!=="true") || request.headers["x-api-key"]!==token) throw new Error("model route refused");
      let size=0;const chunks=[];
      for await (const chunk of request) {size+=chunk.length;if(size>8*1024*1024) throw new Error("model request too large");chunks.push(chunk);}
      const body=JSON.parse(Buffer.concat(chunks).toString());validateModelRequest(body,model,new Set(toolNames));
      if(onToolResults) await onToolResults(body.messages);
      event.topLevelKeys=Object.keys(body);event.toolNames=body.tools?.map(tool=>tool.name)??[];event.forwarded=true;
      const headers={"anthropic-version":"2023-06-01","content-type":"application/json"};
      if (oauth) {
        headers.authorization=oauth.authorization;
        headers["anthropic-beta"]=[...new Set([...oauth.beta.split(","),...(request.headers["anthropic-beta"]??"").split(",")].filter(Boolean))].join(",");
      } else {
        headers["x-api-key"]=apiKey;
        if (typeof request.headers["anthropic-beta"]==="string") headers["anthropic-beta"]=request.headers["anthropic-beta"];
      }
      const result=await fetch(new URL(target.pathname+target.search,upstream),{method:"POST",redirect:"error",signal:controller.signal,headers,body:JSON.stringify(body)});
      event.status=result.status;
      response.writeHead(result.status,{"content-type":result.headers.get("content-type")??"application/json"});
      if(result.body) for await(const data of result.body) response.write(data);
      response.end();
    } catch(error) {
      event.failure=error.message;
      if(!response.headersSent) response.writeHead(403,{"content-type":"application/json"});
      response.end(JSON.stringify({type:"error",error:{type:"permission_error",message:"Operator model relay refused or failed"}}));
    }
  });
  await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);});
  return {port:server.address().port,token,events,fixture:upstream.protocol==="http:",async close(){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}};
}
