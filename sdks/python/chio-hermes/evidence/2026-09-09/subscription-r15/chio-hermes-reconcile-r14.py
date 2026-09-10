import hashlib,json,subprocess,shutil
from pathlib import Path
root=Path('/Users/connor/.local/share/chio-required-operators/hermes-cancellation-r10-20260909')
private=root/'hermes-useful-0c0757000e304ddaa4e05142ae90333f'
config=private/'gateway.json'; conf=json.loads(config.read_text());op=json.loads((root/'operator.json').read_text())
bridge=Path('/tmp/chio-bridge-host-delivery-cold-consumer-r2-20260909/node_modules/@chio/bridge')
cli=bridge/'dist/gateway-operator.js'
out=Path('/tmp/chio-hermes-subscription-reconcile-r14-20260909');out.mkdir(mode=0o700)
def save(name,value):(out/name).write_text(json.dumps(value,indent=2)+'\n')
def observe():
 code="const f=require('fs');const files={};for(const n of f.readdirSync('/observe'))if(f.lstatSync('/observe/'+n).isFile())files[n]=f.readFileSync('/observe/'+n,'utf8');console.log(JSON.stringify({files,dispatch:f.readFileSync('/audit/dispatch.jsonl','utf8').trim().split('\\n').filter(Boolean).map(JSON.parse)}))"
 return json.loads(subprocess.check_output(['docker','run','--rm','--network','none','--read-only','--mount',f"type=volume,src={op['volume']},dst=/observe,readonly",'--mount',f"type=volume,src={op['auditVolume']},dst=/audit,readonly",'--entrypoint','node',op['image'],'-e',code],text=True))
records=[json.loads(p.read_text()) for p in (private/'journal').glob('*.json')]
assert len(records)==1
record=records[0]
assert record['state']=='completed' and not record.get('acknowledged') and not record.get('hostDeliveryConfirmed')
before=observe();save('before.json',before)
path=record['request']['arguments']['path'];expected=record['request']['arguments']['content']
assert before['files'][Path(path).name]==expected
received=private/'subscription-operator-received.json'
exported=subprocess.run(['node',str(cli),'delivery-export',str(config),record['requestId'],str(received)],capture_output=True,text=True,check=True)
value=json.loads(received.read_text())
assert value['outcome']['requestId']==record['requestId'] and value['outcome']['state']=='completed' and value['outcome']['evidence']=='verified'
assert observe()==before
ack=subprocess.run(['node',str(cli),'delivery-acknowledge',str(config),str(received)],capture_output=True,text=True,check=True)
assert json.loads(ack.stdout)['protectedDispatch'] is False and observe()==before
save('operator-acknowledgement.json',json.loads(ack.stdout))
query=private/'subscription-recovered-read.txt';query.write_text(f'The operator explicitly reconciled the original write and acknowledged its verified delivery without redispatch. Call mcp__chio__read_text_file exactly once for {path}. Report the contents. Do not write or edit anything.')
state=Path('/tmp/chio-hermes-subscription-reconciled-state-r14-20260909')
command=['/tmp/chio-hermes-subscription-consumer-r15-20260909/bin/python','-m','chio_hermes.restricted','--host-python','/tmp/chio-hermes-20260909/clean-host-venv/bin/python','--host-root','/tmp/chio-hermes-20260909/public-upstream-source','--node',shutil.which('node'),'--gateway-script',str(bridge/'dist/gateway-http.js'),'--gateway-config',str(config),'--state-dir',str(state),'--query-file',str(query),'--model','gpt-5.5','--model-auth','codex-subscription','--codex-auth-file','/Users/connor/.local/share/chio-required-operators/native-subscription-auth-20260909/codex/profile/auth.json','--max-turns','5']
r=subprocess.run(command,capture_output=True,text=True,timeout=160)
(out/'host.stdout.txt').write_text(r.stdout);(out/'host.stderr.txt').write_text(r.stderr)
for name in ['terminal.json','host-delivery.json','model-relay.json','launch.json','host.sb']:
 if(state/name).exists():shutil.copy2(state/name,out/name)
terminal=json.loads((state/'terminal.json').read_text());after=observe();save('after.json',after)
save('result.json',{'sameAuthority':True,'originalRequestId':record['requestId'],'readExitCode':r.returncode,'originalEffectMatchedIndependentObserver':True,'operatorAcknowledgementDidNotDispatch':True,'newReadDispatches':len(after['dispatch'])-len(before['dispatch']),'resourceBytesUnchanged':after['files']==before['files'],'command':command})
assert r.returncode==0 and terminal['confirmedDeliveries']==1 and after['files']==before['files'] and len(after['dispatch'])==len(before['dispatch'])+1
print('original r14 effect reconciled and explicitly acknowledged; one native read, zero repeated writes')
