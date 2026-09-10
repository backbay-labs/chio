#!/usr/bin/env node
// Candidate MCP-only launch mode. Resource isolation and I01-I08 acceptance
// remain mandatory at the kernel endpoint; this launcher cannot supply them.
import { readFileSync, readdirSync, writeFileSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, lstatSync, existsSync } from "node:fs";
import { resolve, join, relative, isAbsolute, dirname, basename, sep } from "node:path";
import { createHash } from "node:crypto";
import { StringDecoder } from "node:string_decoder";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
const scriptDirectory=dirname(realpathSync(fileURLToPath(import.meta.url)));
const {buildSandboxPolicy,requireSessionCredential}=await import(pathToFileURL(join(scriptDirectory,"sandbox.mjs")).href);
const {startModelRelay}=await import(pathToFileURL(join(scriptDirectory,"model-relay.mjs")).href);

export function canonicalLocation(path) {
  let parent=resolve(path);
  const suffix=[];
  while (!existsSync(parent)) {
    suffix.unshift(basename(parent));
    const next=dirname(parent);
    if (next===parent) throw new Error("path has no existing filesystem ancestor");
    parent=next;
  }
  return join(realpathSync(parent),...suffix);
}
export function isWithin(workspace,path) {
  const rel=relative(workspace,canonicalLocation(path));
  return rel==="" || (!isAbsolute(rel) && rel!==".." && !rel.startsWith(`..${sep}`));
}

export function makeArguments({ settingsPath, mcpPath, model, sessionId }) {
  return ["--print", "--bare", "--restricted", "--tools", "", "--strict-mcp-config", "--mcp-config", mcpPath,
    "--setting-sources", "", "--settings", settingsPath, "--disable-slash-commands", "--no-chrome",
    "--permission-mode", "dontAsk", "--allowedTools", "mcp__chio__*", "--output-format", "stream-json",
    "--verbose", "--no-session-persistence", "--session-id", sessionId, "--model", model];
}

async function main() {
  const args = process.argv.slice(2);
  const allowed = new Set(["--host", "--host-sha256", "--profile", "--workspace", "--gateway-config", "--gateway-sha256", "--model"]);
  const opts = {};
  const optional = new Set(["--model-auth"]);
  for (let i=0; i<args.length; i+=2) {
    if ((!allowed.has(args[i]) && !optional.has(args[i])) || !args[i+1] || Object.hasOwn(opts,args[i])) throw new Error("expected unique --host, --host-sha256, --profile, --workspace, --gateway-config, --gateway-sha256 and --model options");
    opts[args[i]] = args[i+1];
  }
  for (const key of allowed) if (!opts[key]) throw new Error(`${key} is required`);
  if (!/^[0-9a-f]{64}$/.test(opts["--host-sha256"])) throw new Error("invalid host SHA-256");
  const host = realpathSync(opts["--host"]);
  if (createHash("sha256").update(readFileSync(host)).digest("hex") !== opts["--host-sha256"]) throw new Error("host artifact identity differs from the qualified pin");
  const gateway = realpathSync(join(scriptDirectory, "..", "dist", "gateway-http.js"));
  const gatewaySha256 = createHash("sha256").update(readFileSync(gateway)).digest("hex");
  if (gatewaySha256 !== opts["--gateway-sha256"]) throw new Error("bundled gateway differs from the qualified pin");
  let configPath = resolve(opts["--gateway-config"]);
  const configStat = lstatSync(configPath);
  if (!configStat.isFile() || configStat.isSymbolicLink() || (configStat.mode & 0o077) !== 0 || configStat.size > 1024*1024) throw new Error("gateway configuration must be a private regular file");
  configPath=realpathSync(configPath);
  const config = requireSessionCredential(JSON.parse(readFileSync(configPath,"utf8")));
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(config.sessionId ?? "")) throw new Error("prepare the gateway with the exact UUID used for the host session");
  if (!config.execution?.sessionId || !config.journalDir || !Array.isArray(config.tools) || !config.tools.length) throw new Error("prepared gateway context, private journal and bounded tools are required");
  const workspace = realpathSync(opts["--workspace"]);
  if (!statSync(workspace).isDirectory()) throw new Error("workspace must be a directory");
  for (const privatePath of [configPath, resolve(config.journalDir), gateway]) {
    if (isWithin(workspace,privatePath)) throw new Error("gateway, config and journal must be outside the resource workspace");
  }
  const profile = canonicalLocation(opts["--profile"]);
  if (isWithin(workspace,profile)) throw new Error("profile must be outside the resource workspace");
  // Refuse existing profiles so user, project, plugin and resumed state cannot
  // be silently inherited. Supported restart/resume will need separate gates.
  mkdirSync(profile, { mode: 0o700 });
  const temporary=mkdtempSync("/private/tmp/cc-");
  const journal=canonicalLocation(config.journalDir);
  if (isWithin(profile,journal) || isWithin(journal,profile)) throw new Error("profile and journal must be separate private trees");
  for (const privatePath of [configPath,gateway,host,realpathSync(process.execPath)]) {
    if (isWithin(profile,privatePath) || isWithin(journal,privatePath)) throw new Error("configuration and code cannot be inside writable guest trees");
  }
  mkdirSync(journal,{mode:0o700,recursive:true});
  const journalStat=lstatSync(journal);
  if (!journalStat.isDirectory() || (journalStat.mode&0o077)!==0) throw new Error("journal must be a private directory");
  const endpoint=new URL(config.execution.endpoint);
  if (endpoint.protocol!=="http:" || endpoint.hostname!=="127.0.0.1" || !endpoint.port || endpoint.pathname!=="/" || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error("qualified mode requires an exact localhost kernel origin");
  // The control directory is outside both writable guest trees. The host cannot
  // replace settings, MCP routing or the already applied sandbox policy.
  const control=mkdtempSync(join(dirname(profile),".chio-claude-control-"));
  const settingsPath=join(control,"settings.json"),mcpPath=join(control,"mcp-session.json"),sandboxPath=join(control,"host.sb");
  writeFileSync(settingsPath,JSON.stringify({disableAllHooks:true,enabledPlugins:{},permissions:{defaultMode:"dontAsk"}}),{mode:0o600,flag:"wx"});
  const toolNames=[...config.tools.map(tool=>`mcp__chio__${tool.name}`),...(config.approval?["mcp__chio__chio_resume"]:[])];
  let transport,delivered=0,deliveryFailed=false;
  let acknowledgements=Promise.resolve();
  const confirmed=new Set();
  function receiveHostResults(messages) {
    for(const message of messages) {
      if(message.role!=="user"||!Array.isArray(message.content))continue;
      for(const block of message.content) {
        if(block.type!=="tool_result")continue;
        const content=block.content;
        let outcome;
        try{outcome=JSON.parse(typeof content==="string"?content:Array.isArray(content)&&content.length===1&&content[0].type==="text"?content[0].text:"");}catch{continue;}
        if(outcome.state!=="completed"||outcome.evidence!=="verified"||!outcome.delivery)continue;
        acknowledgements=acknowledgements.then(async()=>{
          const proof=createHash("sha256").update(JSON.stringify(outcome)).digest("hex");
          if(confirmed.has(proof))return;
          const receipt=await transport.acknowledgeReceivedOutcome(outcome);
          if(!receipt.acknowledged){deliveryFailed=true;throw new Error("Host delivery remains unresolved");}
          confirmed.add(proof);delivered++;
        });
      }
    }
    return acknowledgements;
  }
  const modelAuth=opts["--model-auth"]??"api-key";
  if (!["api-key","claude-login"].includes(modelAuth)) throw new Error("model auth must be api-key or claude-login");
  if (modelAuth==="claude-login" && process.env.ANTHROPIC_BASE_URL && process.env.ANTHROPIC_BASE_URL!=="https://api.anthropic.com") throw new Error("Native subscription authentication cannot use an alternate upstream");
  const oauth=modelAuth==="claude-login" ? await (await import(pathToFileURL(join(scriptDirectory,"native-login.mjs")).href)).nativeLogin(host,workspace) : undefined;
  // A Messages request is actual host delivery evidence. Confirm it before
  // returning the next model turn so fast providers cannot outrun kernel ACK.
  const relay=await startModelRelay({upstreamBaseUrl:process.env.ANTHROPIC_BASE_URL??"https://api.anthropic.com",apiKey:oauth?undefined:process.env.ANTHROPIC_API_KEY,oauth,model:opts["--model"],toolNames,onToolResults:receiveHostResults});
  try {
    const {startGatewayHttp}=await import(pathToFileURL(gateway).href);
    transport=await startGatewayHttp(config);
    if(typeof transport.acknowledgeReceivedOutcome!=="function")throw new Error("Host delivery acknowledgement transport is required");
    writeFileSync(mcpPath,JSON.stringify({mcpServers:{chio:{type:"http",url:transport.url,headers:{Authorization:`Bearer ${transport.token}`}}}}),{mode:0o600,flag:"wx"});
    const policy=buildSandboxPolicy({host,node:process.execPath,gateway,config:configPath,profile,journal,workspace,temporary,controlFiles:[settingsPath,mcpPath],kernelPort:transport.port,modelPort:relay.port,operatorTransport:true});
    writeFileSync(sandboxPath,policy,{mode:0o600,flag:"wx"});
    const sessionId=config.sessionId;
    const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>["LANG","LC_ALL","TERM"].includes(key)));
    Object.assign(env,{PATH:`${dirname(realpathSync(process.execPath))}:${dirname(host)}:/usr/bin:/bin`,HOME:profile,CLAUDE_CONFIG_DIR:profile,XDG_CONFIG_HOME:profile,TMPDIR:temporary,CLAUDE_CODE_TMPDIR:temporary,BUN_TMPDIR:temporary,XDG_RUNTIME_DIR:temporary,
      ANTHROPIC_API_KEY:relay.token,ANTHROPIC_BASE_URL:`http://127.0.0.1:${relay.port}`,MAX_THINKING_TOKENS:"0",CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:"1",DISABLE_AUTOUPDATER:"1",OPENSSL_CONF:"/dev/null"});
    const command=["-f",sandboxPath,host,...makeArguments({settingsPath,mcpPath,model:opts["--model"],sessionId}),"--debug-file",join(profile,"host-debug.log")];
    writeFileSync(join(profile,"launch.json"),JSON.stringify({schema:"chio.claude.restricted-launch.v2",host,hostSha256:opts["--host-sha256"],gatewaySha256,workspace,temporary,sessionId,sandboxPath,sandboxSha256:createHash("sha256").update(policy).digest("hex"),control,modelAuth,modelTransport:relay.fixture?"localhost-fixture-unaccepted":"operator-messages-relay",acceptance:"unverified"},null,2),{mode:0o600,flag:"wx"});
    const supervisorConfig=join(control,"host-supervisor.json");
    writeFileSync(supervisorConfig,JSON.stringify({command:"/usr/bin/sandbox-exec",args:command,cwd:workspace,env}),{mode:0o600,flag:"wx"});
    const supervisor=join(scriptDirectory,"host-supervisor.mjs");
    const child=spawn(process.execPath,[supervisor,supervisorConfig],{cwd:workspace,
      env:{PATH:process.env.PATH,LANG:"en_US.UTF-8",OPENSSL_CONF:"/dev/null"},stdio:["inherit","pipe","inherit","pipe"]});
    const decoder=new StringDecoder("utf8");
    let hostLines="";
    child.stdout.on("data",data=>{
      process.stdout.write(data);hostLines+=decoder.write(data);
      if(Buffer.byteLength(hostLines)>16*1024*1024){deliveryFailed=true;child.kill("SIGTERM");return;}
      let end;
      while((end=hostLines.indexOf("\n"))>=0){
        const line=hostLines.slice(0,end);hostLines=hostLines.slice(end+1);
        try{
          const event=JSON.parse(line);
          if(event.type!=="user"||event.message?.role!=="user"||!Array.isArray(event.message.content))continue;
          void receiveHostResults([event.message]).catch(()=>{deliveryFailed=true;});
        }catch{/* Missing host proof leaves the operation fenced. */}
      }
    });
    const forward=signal=>child.kill(signal);
    const onInt=()=>forward("SIGINT"),onTerm=()=>forward("SIGTERM");
    process.on("SIGINT",onInt);process.on("SIGTERM",onTerm);
    const state=await new Promise(resolve=>{
      child.once("error",error=>resolve({code:1,signal:null,error:error.message}));
      child.once("close",(code,signal)=>resolve({code,signal}));
    });
    await acknowledgements.catch(()=>{deliveryFailed=true;});
    process.off("SIGINT",onInt);process.off("SIGTERM",onTerm);
    let records=[];
    try{records=readdirSync(journal).filter(name=>name.endsWith(".json")).map(name=>JSON.parse(readFileSync(join(journal,name),"utf8")));}catch{deliveryFailed=true;}
    const unresolved=deliveryFailed||records.some(record=>["pending","unknown"].includes(record.state)||record.state==="completed"&&(!record.acknowledged||!record.hostDeliveryConfirmed));
    const unsuccessful=records.some(record=>record.state==="denied"||record.state==="not_dispatched"||record.outcome?.result?.isError===true);
    const pending=records.some(record=>record.state==="awaiting_approval");
    const executionOutcome=unresolved?"unresolved":pending?"awaiting-approval":unsuccessful?"protected-work-incomplete":state.code===0?"completed":"host-failed";
    const exitCode=unresolved?2:pending?4:unsuccessful?3:state.code??1;
    writeFileSync(join(profile,"exit.json"),JSON.stringify({...state,exitCode,hostDelivery:{confirmed:delivered,failed:deliveryFailed},executionOutcome,retry:"never-automatic"}),{mode:0o600});
    process.exitCode=exitCode;
  } finally {
    await transport?.close();
    await relay.close();
    writeFileSync(join(control,"model-relay.json"),JSON.stringify(relay.events,null,2)+"\n",{mode:0o600});
    rmSync(mcpPath,{force:true});
  }

}
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) main().catch(error=>{console.error(`[chio restricted] ${error.message}`);process.exitCode=1;});
