// Qualification-only driver: ask the real provider for one declared client tool.
// It never fabricates assistant output, tool arguments, host events or receipts.
import {appendFileSync} from 'node:fs';
const original=globalThis.fetch;
globalThis.fetch=async (input,options)=>{
  const url=typeof input==='string'?input:input instanceof URL?input.href:input.url;
  if(url==='https://api.anthropic.com/v1/messages?beta=true' && typeof options?.body==='string'){
    const body=JSON.parse(options.body),tool=process.env.CHIO_TEST_FORCE_DECLARED_TOOL;
    const messages=body.messages??[];
    if(tool && messages.length===1 && body.tools?.some(value=>value.name===tool)){
      body.tool_choice={type:'tool',name:tool,disable_parallel_tool_use:true};
      options={...options,body:JSON.stringify(body)};
      appendFileSync(process.env.CHIO_TEST_FORCE_TOOL_LOG,JSON.stringify({kind:'real-provider-declared-tool-choice',tool,argumentsModified:false,assistantOutputFabricated:false})+'\n',{mode:0o600});
    }
  }
  return original(input,options);
};
