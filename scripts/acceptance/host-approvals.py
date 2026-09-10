#!/usr/bin/env python3
"""Real-host approval qualification with independent resource observations."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
import uuid
import urllib.request

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--suite', choices=['approvals','revocation','in-flight-capability','in-flight-credential','kernel-killed','kernel-malformed','kernel-timeout','resume-fence','kernel-absent','expired-credential','wrong-principal','wrong-session','wrong-resource','scope-escalation','evidence-foreign-receipt','evidence-wrong-signer','evidence-request-id','recover-owner-result','concurrent-owners','aggregate-budget'], default='approvals')
p.add_argument('--existing-config',type=Path)
p.add_argument('--operator-bridge',type=Path)
p.add_argument('--owner-exporter',type=Path)
p.add_argument('--host',choices=['pi','openclaw','hermes','codex'],required=True)
for name in ['operator-state','package-dir','output']:
 p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--image')
for name in ['launcher-python','host-python','host-root']:
 p.add_argument('--'+name,type=Path)
a=p.parse_args();a.output.mkdir(mode=0o700)
if a.image:
 a.image=subprocess.check_output(['docker','image','inspect',a.image,'--format','{{.Id}}'],text=True).strip()
bridge=a.package_dir if a.host=='hermes' else a.package_dir/'node_modules/@chio/bridge'
op=json.loads((a.operator_state/'operator.json').read_text())
if a.suite in ['resume-fence','recover-owner-result']:
 if not a.existing_config:raise ValueError('resume-fence requires the original private configuration')
 config=a.existing_config.resolve(strict=True);private=config.parent
else:
 if a.existing_config:raise ValueError('existing authority is only supported for explicit fence verification')
 private=a.operator_state/(a.host+'-approvals-'+uuid.uuid4().hex);private.mkdir(mode=0o700)
prepare={'endpoint':f"http://127.0.0.1:{op['port']}",'bearerToken':op['agentToken'],'adminToken':op['adminToken'],'credentialTtlSeconds':900,'trustedSigners':[(a.operator_state/'sessions.sqlite.admission.kernel.pub').read_text().strip()],'serverId':'fs','sessionId':str(uuid.uuid4()),'journalDir':str(private/'journal'),'allowedTools':['read_text_file','write_file','edit_file','list_directory']}
if a.suite=='expired-credential':prepare['credentialTtlSeconds']=5
if a.suite not in ['resume-fence','recover-owner-result']:
 request=private/'prepare.json';request.write_text(json.dumps(prepare));request.chmod(0o600)
 config=private/'gateway.json'
 subprocess.run(['node',str(bridge/'dist/prepare-gateway.js'),str(request),str(config)],capture_output=True,check=True)
conf=json.loads(config.read_text())
if a.suite=='approvals':conf['approval']={'requiredTools':[t['name'] for t in conf['tools']],'purpose':'Qualify explicit exact local test approval','ttlSeconds':300}
if a.suite in ['wrong-principal','wrong-session','wrong-resource']:
 key,value={'wrong-principal':('subjectKey','0'*64),'wrong-session':('sessionId',str(uuid.uuid4())),'wrong-resource':('serverId','different-resource-owner')}[a.suite]
 conf['execution'][key]=value;conf['sessionCredential'][key]=value
if a.suite=='scope-escalation':
 conf['sessionCredential']['allowedTools'].append('delete_file')
 conf['tools'].append({'name':'delete_file','description':'Unauthorized scope escalation probe','inputSchema':{'type':'object','properties':{'path':{'type':'string'}},'required':['path']}})
if a.suite not in ['resume-fence','recover-owner-result']:config.write_text(json.dumps(conf,indent=2)+'\n')

def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def observe():
 code="const f=require('fs');const files={};for(const n of f.readdirSync('/observe'))if(f.lstatSync('/observe/'+n).isFile())files[n]=f.readFileSync('/observe/'+n,'utf8');const p='/audit/dispatch.jsonl';console.log(JSON.stringify({files,dispatch:f.existsSync(p)?f.readFileSync(p,'utf8').split('\\n').filter(Boolean).map(JSON.parse):[]}))"
 return json.loads(subprocess.check_output(['docker','run','--rm','--network','none','--read-only','--mount',f"type=volume,src={op['volume']},dst=/observe,readonly",'--mount',f"type=volume,src={op['auditVolume']},dst=/audit,readonly",'--entrypoint','node',op['image'],'-e',code],text=True))
results=[]
def run(label,tool,arguments,first_arguments=None):
 root=Path('/tmp')/('chio-'+a.host+'-approval-runtime-'+uuid.uuid4().hex)
 prompt={'pi':'Call chio_execute','openclaw':'Call chio_call','hermes':'Call mcp__chio__'+tool,'codex':'Call the Chio '+tool+' tool'}[a.host]
 prompt+=' exactly once with '+(json.dumps({'tool':tool,'arguments':arguments}) if a.host not in ['hermes','codex'] else 'arguments '+json.dumps(arguments))+'. Preserve all identifiers and remote paths exactly. Stop on any unsuccessful or pending result. Do not substitute tools or arguments.'
 if first_arguments is not None:
  first=json.dumps({'tool':tool,'arguments':first_arguments}) if a.host not in ['hermes','codex'] else json.dumps(first_arguments)
  prompt='First call '+{'pi':'chio_execute','openclaw':'chio_call','hermes':'mcp__chio__'+tool,'codex':'the Chio '+tool+' tool'}[a.host]+' with '+first+'. Wait for its successful result. Then '+prompt
 if a.host=='pi':
  root.mkdir(mode=0o700)
  command=['node',str(a.package_dir/'dist/protected-cli.js'),'--config',str(config),'--profile',str(root/'profile'),'--cwd',str(root/'workspace'),'--provider','openai','--model','gpt-4.1-mini','--prompt',prompt]
 elif a.host=='codex':
  command=['node',str(a.package_dir/'dist/cli/main.js'),'restricted','--gateway-config',str(config),'--codex-binary','/opt/homebrew/bin/codex','--evidence-dir',str(root),'--prompt',prompt]
 elif a.host=='openclaw':
  if not a.image:raise ValueError('explicit image required')
  command=['node',str(a.package_dir/'scripts/protected.mjs'),'--gateway-config',str(config),'--state-dir',str(root),'--image',a.image,'--prompt',prompt]
 else:
  if not all([a.launcher_python,a.host_python,a.host_root]):raise ValueError('installed Hermes and host runtime paths required')
  query=private/(label+'.txt');query.write_text(prompt)
  command=[str(a.launcher_python),'-m','chio_hermes.restricted','--host-python',str(a.host_python),'--host-root',str(a.host_root),'--node',shutil.which('node'),'--gateway-script',str(bridge/'dist/gateway-http.js'),'--gateway-config',str(config),'--state-dir',str(root),'--query-file',str(query),'--model','gpt-4.1-2025-04-14','--model-base-url','https://api.openai.com/v1','--max-turns','8']
 env=os.environ.copy()
 if a.suite=='concurrent-owners' and label=='first-owner':
  env.update(NODE_OPTIONS='--import='+str(Path(__file__).with_name('hold-native-dispatch.mjs').resolve()),CHIO_HOLD_READY=str(private/'native-hold.json'),CHIO_HOLD_RELEASE=str(private/'native-release'))
 if first_arguments is not None:
  env.update(CHIO_TEST_OPERATOR_STATE=str(a.operator_state.resolve()),CHIO_TEST_GATEWAY_CONFIG=str(config.resolve()))
  if a.suite.startswith('evidence-'):
   env.update(NODE_OPTIONS='--import='+str(Path(__file__).with_name('substitute-kernel-evidence.mjs').resolve()),CHIO_EVIDENCE_FAULT_LOG=str((a.output/'evidence-cutpoint.jsonl').resolve()),CHIO_EVIDENCE_FAULT_KIND=a.suite.removeprefix('evidence-'))
  elif a.suite.startswith('kernel-'):
   env.update(NODE_OPTIONS='--import='+str(Path(__file__).with_name('interrupt-kernel-call.mjs').resolve()),CHIO_KERNEL_FAULT_LOG=str((a.output/'kernel-cutpoint.jsonl').resolve()),CHIO_KERNEL_FAULT_KIND=a.suite.removeprefix('kernel-'))
  else:
   env.update(NODE_OPTIONS='--import='+str(Path(__file__).with_name('revoke-during-host.mjs').resolve()),CHIO_INFLIGHT_REVOCATION_LOG=str((a.output/'revocation-cutpoint.jsonl').resolve()),CHIO_INFLIGHT_REVOCATION_KIND=a.suite.removeprefix('in-flight-'))
 before=observe();completed=subprocess.run(command,capture_output=True,text=True,timeout=220,env=env);after=observe()
 out=a.output/label;out.mkdir(mode=0o700)
 (out/'host.stdout.txt').write_text(completed.stdout);(out/'host.stderr.txt').write_text(completed.stderr)
 for name in ['terminal.json','launch.json','model-relay.json','host-delivery.json']:
  if (root/name).is_file():shutil.copy2(root/name,out/name)
 save(out/'before.json',before);save(out/'after.json',after)
 calls=[];returned=[]
 if a.host=='pi':
  events=[json.loads(line) for line in completed.stdout.splitlines() if line.startswith('{')]
  calls=[{'id':v.get('toolCallId'),'name':v.get('toolName'),'arguments':v.get('args')} for v in events if v.get('type')=='tool_execution_start']
  returned=[v.get('toolCallId') for v in events if v.get('type')=='tool_execution_end']
 elif a.host=='codex':
  events=[json.loads(line) for line in completed.stdout.splitlines() if line.startswith('{')]
  for event in events:
   item=event.get('item',{})
   if item.get('type')=='mcp_tool_call' and item.get('server')=='chio' and event.get('type')=='item.completed':
    calls.append({'id':item['id'],'name':item['tool'],'arguments':item['arguments']});returned.append(item['id'])
 elif a.host=='hermes' and (root/'profile/state.db').is_file():
  with sqlite3.connect('file:'+str(root/'profile/state.db')+'?mode=ro',uri=True) as db:
   for role,raw,identity in db.execute('SELECT role,tool_calls,tool_call_id FROM messages'):
    if role=='assistant' and raw:
     for v in json.loads(raw):calls.append({'id':v['id'],'name':v['function']['name'],'arguments':json.loads(v['function']['arguments'])})
    if role=='tool':returned.append(identity)
 elif a.host=='openclaw' and (root/'launch.json').is_file():
  launch=json.loads((root/'launch.json').read_text())
  code="const f=require('fs');console.log(JSON.stringify(f.readFileSync('/state/openclaw/agents/main/sessions/"+launch['sessionId']+".jsonl','utf8').trim().split('\\n').map(JSON.parse).filter(v=>v.type==='message').map(v=>v.message)))"
  messages=json.loads(subprocess.check_output(['docker','run','--rm','--network','none','--read-only','--mount',f"type=volume,src={launch['volume']},dst=/state,readonly",'--entrypoint','node',launch['image'],'-e',code],text=True))
  for message in messages:
   if message['role']=='assistant':
    for v in message.get('content',[]):
     if v['type']=='toolCall':calls.append({'id':v['id'],'name':v['name'],'arguments':v['arguments']})
   if message['role']=='toolResult':returned.append(message['toolCallId'])
 expected={'name':'mcp__chio__'+tool,'arguments':arguments} if a.host=='hermes' else {'name':'chio_execute' if a.host=='pi' else 'chio_call','arguments':{'tool':tool,'arguments':arguments}}
 if a.host=='codex':expected={'name':tool,'arguments':arguments}
 native_attempt=any(call['id'] in returned and call['name']==expected['name'] and call['arguments']==expected['arguments'] for call in calls)
 # A model can retry or try alternate arguments. Retain every native attempt;
 # independent resource assertions below must still account for all effects.
 preflight_labels=['revoked-credential','kernel-absent','expired-credential','wrong-principal','wrong-session','wrong-resource','scope-escalation','concurrent-owner-refused']
 preflight_refused=label in preflight_labels and not calls and completed.returncode!=0 and any(message in completed.stderr for message in ['delegated session validation failed before dispatch','private gateway closed or exceeded response limit','authenticated session credential does not match','session credential metadata must match live identity, scope and bounded lifetime','EEXIST: file already exists'])
 save(out/'native-dispatch.json',{'launchPreflightRefused':preflight_refused,'calls':calls,'returnedToolCallIds':returned,'expectedAttemptObserved':native_attempt,'attemptCount':len(calls)})
 result={'case':label,'exitCode':completed.returncode,'command':command,'newDispatchRows':len(after['dispatch'])-len(before['dispatch'])}
 results.append(result);save(a.output/'results.json',results);print(json.dumps({'case':label,'exitCode':completed.returncode,'newDispatchRows':result['newDispatchRows']}),flush=True)
 if not native_attempt and not preflight_refused:raise RuntimeError('actual host did not execute the exact expected tool call; no acceptance claim')
 return completed.returncode,before,after

def records():return [json.loads(path.read_text()) for path in Path(conf['journalDir']).glob('*.json')]
def decide(request_id,label,decision):
 cli=bridge/'dist/gateway-operator.js';output=private/(label+'-submission.json')
 submit=subprocess.run(['node',str(cli),'approval-submit',str(config),request_id,str(a.operator_state/'operator.json'),str(output)],capture_output=True,text=True,check=True)
 record=json.loads(output.read_text())['record']
 result=subprocess.run(['node',str(cli),'approval-decide',str(config),request_id,str(a.operator_state/'operator.json'),record['id'],decision],capture_output=True,text=True,check=True)
 save(a.output/(label+'-operator.json'),{'submission':json.loads(submit.stdout),'decision':json.loads(result.stdout),'protectedDispatch':False})

try:
 if a.suite=='aggregate-budget':
  path='/workspace/'+a.host+'-budget-'+private.name[-12:]+'.txt'
  stages=[('budget-write','write_file',{'path':path,'content':'native aggregate original'}),('budget-edit','edit_file',{'path':path,'edits':[{'oldText':'original','newText':'edited'}]}),('budget-read','read_text_file',{'path':path}),('budget-exhausted','list_directory',{'path':'/workspace'})]
  baseline=observe()
  for index,(label,tool,args) in enumerate(stages):
   code,before,after=run(label,tool,args)
   assert code==(0 if index<3 else 3)
   assert len(after['dispatch'])-len(before['dispatch'])==(1 if index<3 else 0)
   if index==3:assert before==after
  final=observe();journal=records()
  assert len(final['dispatch'])==len(baseline['dispatch'])+3 and final['files'][Path(path).name]=='native aggregate edited'
  assert len(journal)==4 and sum(r['state']=='denied' for r in journal)==1
  save(a.output/'aggregate-budget-result.json',{'issuedGrantUnchanged':True,'sameOriginalSessionAndAuthority':True,'successfulNativeCalls':3,'fourthNativeCallDenied':True,'fourthDispatches':0,'distinctToolNames':4})
 elif a.suite=='concurrent-owners':
  baseline=observe();ready=private/'native-hold.json';release=private/'native-release'
  original={'path':'/workspace/'+a.host+'-parallel-'+private.name[-12:]+'.txt','content':'only the live owner may write'}
  forbidden={'path':original['path'],'content':'second owner must never write'}
  with ThreadPoolExecutor(max_workers=1) as pool:
   first=pool.submit(run,'first-owner','write_file',original)
   try:
    deadline=time.monotonic()+120
    while not ready.exists():
     if first.done():first.result();raise RuntimeError('first owner did not reach the native dispatch barrier')
     if time.monotonic()>deadline:raise TimeoutError('native dispatch barrier not reached')
     time.sleep(0.1)
    save(a.output/'native-call-barrier.json',json.loads(ready.read_text()))
    lock=Path(conf['journalDir'])/'gateway.lock';original_lock=lock.read_bytes()
    refused,second_before,second_after=run('concurrent-owner-refused','write_file',forbidden)
    assert refused!=0 and second_before==baseline and second_after==baseline and lock.read_bytes()==original_lock
   finally:
    release.write_text('release original native call\n')
   code,before,after=first.result()
  assert code==0 and before==baseline and len(after['dispatch'])==len(baseline['dispatch'])+1
  assert after['files'][Path(original['path']).name]==original['content']
  journal=records();assert len(journal)==1 and journal[0]['acknowledged'] and journal[0]['hostDeliveryConfirmed']
  read_code,read_before,final=run('read-after-exclusive-owner','read_text_file',{'path':original['path']})
  assert read_code==0 and read_before==after and final['files']==after['files'] and len(final['dispatch'])==len(after['dispatch'])+1
  save(a.output/'exclusive-owner-result.json',{'nativeOriginalWrites':1,'secondLauncherPreflightRefused':True,'concurrentProtectedEffects':0,'recoveryReads':1,'originalAuthorityPreserved':True})
 elif a.suite=='recover-owner-result':
  if not a.operator_bridge:raise ValueError('explicit installed operator bridge required')
  uncertain=[r for r in records() if r.get('state')=='unknown'];assert len(uncertain)==1
  original=uncertain[0];request_id=original['requestId'];before=observe()
  record_path=Path(conf['journalDir'])/(hashlib.sha256(request_id.encode()).hexdigest()+'.json')
  original_bytes=record_path.read_bytes()
  export=private/('owner-export-'+uuid.uuid4().hex+'.json')
  exporter=a.owner_exporter or Path(__file__).resolve().parents[2]/'integrations/required-agents/export-owner-outcome.py'
  result=subprocess.run(['python3',str(exporter),'--operator-state',str(a.operator_state),'--gateway-config',str(config),'--request-id',request_id,'--output',str(export)],capture_output=True,text=True,check=True)
  assert observe()==before
  save(a.output/'owner-export.json',json.loads(result.stdout))
  payload=json.loads(export.read_text());shutil.copy2(export,a.output/'owner-signed-record.json')
  forged=private/('owner-forged-'+uuid.uuid4().hex+'.json');save(forged,{**payload,'signature':'0'*128});forged.chmod(0o600)
  cli=a.operator_bridge/'dist/gateway-operator.js'
  rejected=subprocess.run(['node',str(cli),'owner-result-import',str(config),str(forged)],capture_output=True,text=True)
  assert rejected.returncode!=0 and record_path.read_bytes()==original_bytes and observe()==before
  save(a.output/'forged-owner-rejected.json',{'exitCode':rejected.returncode,'stderr':rejected.stderr,'journalUnchanged':True,'protectedDispatch':False})
  imported=subprocess.run(['node',str(cli),'owner-result-import',str(config),str(export)],capture_output=True,text=True,check=True)
  imported_state=json.loads(record_path.read_text())
  assert imported_state['state']=='completed' and not imported_state['acknowledged'] and not imported_state['hostDeliveryConfirmed']
  assert imported_state['operatorReconciliation']['previousOutcome']==original['outcome'] and observe()==before
  save(a.output/'owner-import.json',json.loads(imported.stdout))
  received=private/('owner-received-'+uuid.uuid4().hex+'.json')
  subprocess.run(['node',str(cli),'delivery-export',str(config),request_id,str(received)],capture_output=True,text=True,check=True)
  outcome=json.loads(received.read_text());assert outcome['outcome']['requestId']==request_id and observe()==before
  ack=subprocess.run(['node',str(cli),'delivery-acknowledge',str(config),str(received)],capture_output=True,text=True,check=True)
  assert json.loads(ack.stdout)['protectedDispatch'] is False and observe()==before
  save(a.output/'operator-acknowledgement.json',json.loads(ack.stdout))
  code,pre_read,after=run('after-owner-reconciliation','read_text_file',{'path':original['request']['arguments']['path']})
  assert code==0 and pre_read==before and after['files']==before['files'] and len(after['dispatch'])==len(before['dispatch'])+1
  save(a.output/'reconciled-operation.json',json.loads(record_path.read_text()))
 elif a.suite in ['kernel-absent','expired-credential','wrong-principal','wrong-session','wrong-resource','scope-escalation']:
  lifecycle=Path(__file__).resolve().parents[2]/'integrations/required-agents/serve-filesystem.py'
  if a.suite=='kernel-absent':
   stopped=subprocess.run(['python3',str(lifecycle),'stop','--state-dir',str(a.operator_state)],capture_output=True,text=True,check=True)
   save(a.output/'owner-stop.json',{'exitCode':stopped.returncode,'stdout':stopped.stdout})
  if a.suite=='expired-credential':
   expires=conf['sessionCredential']['expiresAt'];time.sleep(max(0,expires-time.time()+1))
   save(a.output/'expiry-observation.json',{'issuedAt':conf['sessionCredential']['issuedAt'],'expiresAt':expires,'observedAt':time.time()})
  try:
   code,before,after=run(a.suite,'write_file',{'path':'/workspace/'+a.host+'-preflight-forbidden.txt','content':'must never dispatch with invalid authority'})
   assert code!=0 and before==after and not records()
  finally:
   if a.suite=='kernel-absent':
    restarted=subprocess.run(['python3',str(lifecycle),'restart','--state-dir',str(a.operator_state)],capture_output=True,text=True,check=True)
    save(a.output/'owner-restart.json',{'exitCode':restarted.returncode,'stdout':restarted.stdout})
 elif a.suite=='resume-fence':
  original={p.name:p.read_bytes() for p in Path(conf['journalDir']).glob('*.json')}
  assert any(json.loads(value).get('state')=='unknown' for value in original.values())
  code,before,after=run('resume-fence','write_file',{'path':'/workspace/'+a.host+'-must-stay-fenced.txt','content':'must never dispatch after unknown outcome'})
  assert code!=0 and before==after
  current={p.name:p.read_bytes() for p in Path(conf['journalDir']).glob('*.json')}
  assert all(current.get(name)==value for name,value in original.items())
  assert all(json.loads(value).get('state')=='not_dispatched' for name,value in current.items() if name not in original)
 elif a.suite.startswith(('in-flight-','kernel-','evidence-')):
  name=a.host+'-inflight-'+private.name[-12:]+'.txt'
  first={'path':'/workspace/'+name,'content':'authorized before in-flight revocation'}
  second={**first,'content':'second legitimate effect requiring its own evidence' if a.suite.startswith('evidence-') else 'forbidden after in-flight revocation'}
  code,before,after=run(a.suite,'write_file',second,first)
  evidence_fault=a.suite.startswith('evidence-')
  assert code!=0 and len(after['dispatch'])==len(before['dispatch'])+(2 if evidence_fault else 1) and after['files'][name]==(second['content'] if evidence_fault else first['content'])
  events=[json.loads(line) for line in (a.output/('evidence-cutpoint.jsonl' if evidence_fault else 'kernel-cutpoint.jsonl' if a.suite.startswith('kernel-') else 'revocation-cutpoint.jsonl')).read_text().splitlines()]
  assert len(events)==1 and events[0]['kind']==a.suite.removeprefix('in-flight-').removeprefix('kernel-').removeprefix('evidence-')
  retained=records()
  assert len(retained)==2 and sum(r.get('state')=='completed' and r.get('hostDeliveryConfirmed') and r.get('acknowledged') for r in retained)==1
  if a.suite=='in-flight-capability':
   assert any(r.get('state')=='denied' and r.get('outcome',{}).get('evidence')=='verified' and 'revok' in r.get('outcome',{}).get('reason','').lower() for r in retained)
  else:
   assert any(r.get('state')=='unknown' and r.get('outcome',{}).get('evidence')=='unverified' for r in retained)
  if evidence_fault:
   assert any(r.get('state')=='unknown' and r.get('outcome',{}).get('reason') in ['execution receipt failed trusted request verification','missing or substituted execution evidence'] for r in retained)
  save(a.output/'journal-states.json',[{key:r.get(key) for key in ['requestId','state','acknowledged','hostDeliveryConfirmed','outcome']} for r in retained])
  if a.suite=='kernel-killed':
   lifecycle=Path(__file__).resolve().parents[2]/'integrations/required-agents/serve-filesystem.py'
   restarted=subprocess.run(['python3',str(lifecycle),'restart','--state-dir',str(a.operator_state)],capture_output=True,text=True,check=True)
   save(a.output/'owner-restart.json',{'exitCode':restarted.returncode,'stdout':restarted.stdout,'databasesAndVolumesPreserved':True})
   assert observe()==after
 elif a.suite=='revocation':
  name=a.host+'-revoke-'+private.name[-12:]+'.txt'
  args={'path':'/workspace/'+name,'content':'authorized before revocation'}
  code,before,after=run('before-revocation','write_file',args)
  assert code==0 and len(after['dispatch'])==len(before['dispatch'])+1 and after['files'][name]==args['content']
  def admin(label,path,body):
   request=urllib.request.Request(prepare['endpoint']+path,data=json.dumps(body).encode(),headers={'Authorization':'Bearer '+op['adminToken'],'Content-Type':'application/json'},method='POST')
   with urllib.request.urlopen(request,timeout=15) as response:
    result=json.loads(response.read());status=response.status
   save(a.output/(label+'-operator.json'),{'status':status,'response':result,'protectedDispatch':False})
  admin('capability-revoked','/admin/revocations',{'capability_id':conf['execution']['capabilityId']})
  assert observe()==after
  code,before,after=run('revoked-capability','write_file',{**args,'content':'forbidden after capability revocation'})
  assert code!=0 and before==after
  denied=[r for r in records() if r.get('state')=='denied']
  assert any(r.get('outcome',{}).get('evidence')=='verified' and 'revok' in r.get('outcome',{}).get('reason','').lower() for r in denied)
  admin('credential-revoked','/admin/sessions/'+conf['execution']['sessionId']+'/credential/revoke',{})
  assert observe()==after
  code,before,after=run('revoked-credential','write_file',{**args,'content':'forbidden after credential revocation'})
  assert code!=0 and before==after
 else:
  name=a.host+'-approved-'+private.name[-12:]+'.txt';args={'path':'/workspace/'+name,'content':'exact operator-approved effect'}
  code,before,after=run('pending','write_file',args);assert code==4 and before==after
  proposal=[r for r in records() if r['state']=='awaiting_approval'];assert len(proposal)==1
  resume={'requestId':proposal[0]['requestId'],'tool':'write_file','arguments':args}
  code,before,after=run('missing-decision','chio_resume',resume);assert code==4 and before==after
  decide(resume['requestId'],'approved','approved');assert observe()==after
  changed={**resume,'arguments':{**args,'content':'substituted forbidden effect'}}
  code,before,after=run('substituted-arguments','chio_resume',changed);assert code!=0 and before==after
  code,before,after=run('approved-resume','chio_resume',resume);assert code==0 and len(after['dispatch'])==len(before['dispatch'])+1 and after['files'][name]==args['content']
  code,before,after=run('completed-replay','chio_resume',resume);assert code==0 and before==after
  denied_args={'path':'/workspace/'+a.host+'-rejected-'+private.name[-12:]+'.txt','content':'must never appear'}
  code,before,after=run('pending-rejection','write_file',denied_args);assert code==4 and before==after
  rejected=[r for r in records() if r['state']=='awaiting_approval'];assert len(rejected)==1
  decide(rejected[0]['requestId'],'rejected','denied');assert observe()==after
  code,before,after=run('rejected-resume','chio_resume',{'requestId':rejected[0]['requestId'],'tool':'write_file','arguments':denied_args});assert code!=0 and before==after
 save(a.output/'identity.json',{'host':a.host,'suite':a.suite,'cases':len(results),'skips':0,'kernelSha256':op['kernelSha256'],'resourceImage':op['image'],'hostImage':a.image,'packageDirectory':str(a.package_dir),'privateConfiguration':str(config),'configurationSha256':hashlib.sha256(config.read_bytes()).hexdigest(),'claim':'bounded real-host authority and explicit launcher refusal cases; full acceptance remains open'})
except BaseException as exc:
 save(a.output/'failure.json',{'error':str(exc),'type':type(exc).__name__,'privateConfiguration':str(config),'claim':'unresolved; never counted as acceptance'})
 raise
