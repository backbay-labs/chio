import subprocess,json,hashlib
from pathlib import Path
owned=Path('/Users/connor/Medica/backbay/standalone/arc/.worktrees/hermes-required-integration-20260909/sdks/python/chio-hermes')
shared=Path('/Users/connor/Medica/backbay/standalone/arc/.worktrees/required-agent-integrations-20260909/scripts/acceptance')
python='/tmp/chio-hermes-subscription-consumer-r15-20260909/bin/python'
bridge='/tmp/chio-bridge-host-delivery-cold-consumer-r2-20260909/node_modules/@chio/bridge'
auth='/Users/connor/.local/share/chio-required-operators/native-subscription-auth-20260909/codex/profile/auth.json'
owner='/Users/connor/.local/share/chio-required-operators/hermes-cancellation-r10-20260909'
base=['--operator-state',owner,'--launcher-python',python,'--host-python','/tmp/chio-hermes-20260909/clean-host-venv/bin/python','--host-root','/tmp/chio-hermes-20260909/public-upstream-source']
root=Path('/tmp/chio-hermes-subscription-matrix-r15-20260909');root.mkdir(mode=0o700)
records=[]
def run(label,command):
 path=root/label
 with (root/(label+'.driver.log')).open('w') as log:
  r=subprocess.run(command+['--output',str(path)],stdout=log,stderr=subprocess.STDOUT,timeout=1000)
 record={'case':label,'exitCode':r.returncode,'command':command+['--output',str(path)],'harnessSha256':hashlib.sha256(Path(command[1]).read_bytes()).hexdigest()}
 records.append(record);(root/'runs.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps({'case':label,'exitCode':r.returncode}),flush=True)
 if r.returncode:raise RuntimeError('qualification failure: '+label)
for label,case,injector in [
 ('launcher-crash','launcher-crash',owned/'scripts/kill_launcher_response.mjs'),
 ('response-loss','host-response-loss',shared/'drop-host-response.mjs'),
 ('gateway-crash','gateway-crash',shared/'crash-host-gateway.mjs'),
 ('operator-cancellation','host-response-loss',shared/'cancel-host-response.mjs')]:
 run(label,[python,str(owned/'scripts/qualify_http_host.py'),*base,'--bridge',bridge,'--model','gpt-5.5','--model-auth','codex-subscription','--codex-auth-file',auth,'--cases',case,'--fault-injector',str(injector)])
for suite in ['concurrent-owners','evidence-foreign-receipt','evidence-wrong-signer','evidence-request-id','kernel-timeout']:
 common=[python,str(shared/'host-approvals.py'),'--host','hermes',*base,'--package-dir',bridge,'--model-auth-file',auth]
 run(suite,common+['--suite',suite])
 if suite.startswith('evidence-') or suite=='kernel-timeout':
  identity=json.loads((root/suite/'identity.json').read_text())
  private_config=Path(identity['privateConfig']) if 'privateConfig' in identity else None
  if private_config is None:
   # The harness retains the exact original private authority in identity.json.
   raise RuntimeError('inspect original authority identity before recovery')
  run(suite+'-fenced',common+['--suite','resume-fence','--existing-config',str(private_config)])
