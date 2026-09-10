import subprocess,json,hashlib
from pathlib import Path
root=Path('/tmp/chio-hermes-subscription-authority-r15-20260909');root.mkdir(mode=0o700)
script=Path('/Users/connor/Medica/backbay/standalone/arc/.worktrees/required-agent-integrations-20260909/scripts/acceptance/host-approvals.py')
python='/tmp/chio-hermes-subscription-consumer-r15-20260909/bin/python'
common=[python,str(script),'--host','hermes','--operator-state','/Users/connor/.local/share/chio-required-operators/hermes-cancellation-r10-20260909','--package-dir','/tmp/chio-bridge-host-delivery-cold-consumer-r2-20260909/node_modules/@chio/bridge','--launcher-python',python,'--host-python','/tmp/chio-hermes-20260909/clean-host-venv/bin/python','--host-root','/tmp/chio-hermes-20260909/public-upstream-source','--model-auth-file','/Users/connor/.local/share/chio-required-operators/native-subscription-auth-20260909/codex/profile/auth.json']
records=[]
def run(label,extra):
 command=common+extra+['--output',str(root/label)]
 digest=hashlib.sha256(script.read_bytes()).hexdigest()
 with(root/(label+'.driver.log')).open('w') as f:r=subprocess.run(command,stdout=f,stderr=subprocess.STDOUT,timeout=1100)
 records.append({'case':label,'exitCode':r.returncode,'command':command,'harnessSha256AtStart':digest,'harnessUnchangedDuringRun':hashlib.sha256(script.read_bytes()).hexdigest()==digest})
 (root/'runs.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps({'case':label,'exitCode':r.returncode}),flush=True)
 if r.returncode:raise RuntimeError('case failed: '+label)
for suite in ['kernel-absent','expired-credential','wrong-principal','wrong-session','wrong-resource','scope-escalation','revocation','in-flight-capability','in-flight-credential','kernel-malformed','kernel-killed','approvals']:
 run(suite,['--suite',suite])
 if suite in ['in-flight-credential','kernel-malformed','kernel-killed']:
  identity=json.loads((root/suite/'identity.json').read_text())
  run(suite+'-fenced',['--suite','resume-fence','--existing-config',identity['privateConfiguration']])
