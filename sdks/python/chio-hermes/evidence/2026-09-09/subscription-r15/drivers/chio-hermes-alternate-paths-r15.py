from pathlib import Path
import hashlib,json,subprocess
root=Path('/Users/connor/Medica/backbay/standalone/arc/.worktrees/required-agent-integrations-20260909')
harness=root/'scripts/acceptance/host-approvals.py'
out=Path('/tmp/chio-hermes-alternate-paths-r15-20260909');out.mkdir(mode=0o700)
python='/tmp/chio-hermes-subscription-consumer-r15-20260909/bin/python'
base=[python,str(harness),'--host','hermes','--operator-state','/Users/connor/.local/share/chio-required-operators/hermes-cancellation-r10-20260909','--package-dir','/tmp/chio-bridge-host-delivery-cold-consumer-r2-20260909/node_modules/@chio/bridge','--launcher-python',python,'--host-python','/tmp/chio-hermes-20260909/clean-host-venv/bin/python','--host-root','/tmp/chio-hermes-20260909/public-upstream-source','--model-auth-file','/Users/connor/.local/share/chio-required-operators/native-subscription-auth-20260909/codex/profile/auth.json']
runs=[]
for case in ['forbidden-edit','secret-dry-run','secret-list','secret-path-alias','forbidden-write-alias']:
 command=base+['--suite',case,'--output',str(out/case)]
 digest=hashlib.sha256(harness.read_bytes()).hexdigest()
 with (out/(case+'.driver.log')).open('w') as log:completed=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
 runs.append({'case':case,'exitCode':completed.returncode,'harnessSha256AtStart':digest,'harnessUnchangedDuringRun':digest==hashlib.sha256(harness.read_bytes()).hexdigest(),'command':command})
 (out/'runs.json').write_text(json.dumps(runs,indent=2)+'\n')
 print(json.dumps({'case':case,'harnessExitCode':completed.returncode}),flush=True)
 if completed.returncode:raise SystemExit(completed.returncode)
