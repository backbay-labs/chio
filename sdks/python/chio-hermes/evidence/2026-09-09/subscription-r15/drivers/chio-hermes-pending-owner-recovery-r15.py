from pathlib import Path
import hashlib,json,os,shutil,subprocess,uuid
base=Path('/tmp/chio-hermes-dispatch-cutpoints-r15-20260909')
case=next(r for r in json.loads((base/'results.json').read_text()) if r['case']=='journal-after-effect')
config=Path(case['privateConfiguration']);private=config.parent
conf=json.loads(config.read_text());opdir=private.parent;op=json.loads((opdir/'operator.json').read_text())
out=Path('/tmp/chio-hermes-pending-owner-recovery-r15-20260909');out.mkdir(mode=0o700)
def save(name,value):(out/name).write_text(json.dumps(value,indent=2)+'\n')
def observe():
 code="const f=require('fs');const files={};for(const n of f.readdirSync('/observe'))if(f.lstatSync('/observe/'+n).isFile())files[n]=f.readFileSync('/observe/'+n,'utf8');console.log(JSON.stringify({files,dispatch:f.readFileSync('/audit/dispatch.jsonl','utf8').split('\\n').filter(Boolean).map(JSON.parse)}))"
 return json.loads(subprocess.check_output(['docker','run','--rm','--network','none','--read-only','--mount',f"type=volume,src={op['volume']},dst=/observe,readonly",'--mount',f"type=volume,src={op['auditVolume']},dst=/audit,readonly",'--entrypoint','node',op['image'],'-e',code],text=True))
records=[(p,json.loads(p.read_text())) for p in Path(conf['journalDir']).glob('*.json')]
pending=[r for r in records if r[1]['state']=='pending'];assert len(pending)==1
path,original=pending[0];original_bytes=path.read_bytes();request_id=original['requestId']
assert 'outcome' not in original
before=observe();save('before.json',before)
export=private/'owner-recovery-signed.json'
exporter=Path('/Users/connor/Medica/backbay/standalone/arc/.worktrees/required-agent-integrations-20260909/integrations/required-agents/export-owner-outcome.py')
export_command=['python3',str(exporter),'--operator-state',str(opdir),'--gateway-config',str(config),'--request-id',request_id,'--output',str(export)]
r=subprocess.run(export_command,capture_output=True,text=True,check=True);save('owner-export.json',json.loads(r.stdout));assert observe()==before
payload=json.loads(export.read_text());shutil.copy2(export,out/'owner-signed-record.json')
forged=private/'owner-recovery-forged.json';forged.write_text(json.dumps({**payload,'signature':'0'*128}));forged.chmod(0o600)
cli=Path('/Users/connor/.local/share/chio-required-candidates/20260909/install/operator-bridge/node_modules/@chio/bridge/dist/gateway-operator.js')
r=subprocess.run(['node',str(cli),'owner-result-import',str(config),str(forged)],capture_output=True,text=True)
assert r.returncode!=0 and 'owner record lacks a trusted valid signature' in r.stderr and path.read_bytes()==original_bytes and observe()==before
save('forged-owner-rejected.json',{'exitCode':r.returncode,'stderr':r.stderr,'journalUnchanged':True,'protectedDispatch':False})
r=subprocess.run(['node',str(cli),'owner-result-import',str(config),str(export)],capture_output=True,text=True,check=True);save('owner-import.json',json.loads(r.stdout))
state=json.loads(path.read_text());assert state['state']=='completed' and not state['acknowledged'] and not state['hostDeliveryConfirmed']
assert state['operatorReconciliation']['previousState']=='pending' and state['operatorReconciliation']['previousOutcome'] is None and observe()==before
received=private/'owner-recovery-received.json'
subprocess.run(['node',str(cli),'delivery-export',str(config),request_id,str(received)],capture_output=True,text=True,check=True)
r=subprocess.run(['node',str(cli),'delivery-acknowledge',str(config),str(received)],capture_output=True,text=True,check=True)
save('operator-acknowledgement.json',json.loads(r.stdout));assert json.loads(r.stdout)['protectedDispatch'] is False and observe()==before
command=json.loads((base/'journal-after-effect/initial/command.json').read_text())
runtime=Path('/tmp')/('chio-hermes-pending-recovery-'+uuid.uuid4().hex)
query=private/'owner-recovery-native-read.txt';query.write_text('The operator reconciled and acknowledged the original signed result. Call mcp__chio__read_text_file exactly once for '+original['request']['arguments']['path']+'. Report the verified content. Do not write.')
command[command.index('--state-dir')+1]=str(runtime);command[command.index('--query-file')+1]=str(query)
env=os.environ.copy();env.pop('NODE_OPTIONS',None)
with (out/'host.stdout.txt').open('w') as stdout,(out/'host.stderr.txt').open('w') as stderr:r=subprocess.run(command,env=env,stdout=stdout,stderr=stderr,timeout=180)
after=observe();save('after.json',after)
for name in ['launch.json','terminal.json','model-relay.json','host-delivery.json','host.sb']:shutil.copy2(runtime/name,out/name)
assert r.returncode==0 and before['files']==after['files'] and len(after['dispatch'])==len(before['dispatch'])+1
save('reconciled-operation.json',json.loads(path.read_text()))
save('result.json',{'passed':True,'previousState':'pending','previousOutcome':None,'forgedOwnerRejected':True,'explicitOriginalDeliveryAcknowledged':True,'nativeReadDispatches':1,'newWrites':0,'nativeExitCode':r.returncode,'originalAuthorityPreserved':True})
save('identity.json',{'config':str(config),'configurationSha256':hashlib.sha256(config.read_bytes()).hexdigest(),'exporterSha256':hashlib.sha256(exporter.read_bytes()).hexdigest(),'operatorCliSha256':hashlib.sha256(cli.read_bytes()).hexdigest(),'harnessSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'exportCommand':export_command,'nativeCommand':command})
print('Pending completion journal record: signed owner reconciliation and actual native read passed')
