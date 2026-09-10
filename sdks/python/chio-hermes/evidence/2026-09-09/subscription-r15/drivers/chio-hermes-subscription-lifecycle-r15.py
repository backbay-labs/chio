import subprocess,json,hashlib
from pathlib import Path
out=Path('/tmp/chio-hermes-subscription-lifecycle-r15-20260909');out.mkdir(mode=0o700)
uv='/tmp/chio-hermes-20260909/install-tools/bin/uv';venv=out/'consumer';python=venv/'bin/python'
r11=Path('/tmp/chio-hermes-supervisor-wheel-r11-20260909/chio_hermes-0.1.2-py3-none-any.whl');r15=Path('/tmp/chio-hermes-subscription-wheel-r15-20260909/chio_hermes-0.1.2-py3-none-any.whl')
steps=[]
def run(label,command):
 r=subprocess.run(command,capture_output=True,text=True)
 (out/(label+'.stdout.txt')).write_text(r.stdout);(out/(label+'.stderr.txt')).write_text(r.stderr)
 steps.append({'label':label,'command':command,'exitCode':r.returncode});(out/'steps.json').write_text(json.dumps(steps,indent=2)+'\n')
 if r.returncode:raise RuntimeError(label)
run('create',[uv,'venv','--python','/Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11',str(venv)])
for label,wheel in [('old-r11',r11),('subscription-r15',r15)]:
 run(label+'-install',[uv,'pip','install','--no-cache','--python',str(python),'--no-index','--find-links','/tmp/chio-hermes-20260909/final-wheelhouse','--reinstall-package','chio-hermes',str(wheel)])
 run(label+'-check',[uv,'pip','check','--python',str(python)])
 run(label+'-entrypoint',[str(venv/'bin/chio-hermes-restricted'),'--help'])
run('origin',[str(python),'-I','-c','import chio_hermes,json;print(json.dumps({"origin":chio_hermes.__file__}))'])
run('remove',[uv,'pip','uninstall','--python',str(python),'chio-hermes'])
run('verify-removed',[str(python),'-I','-c',"import importlib.util,pathlib,sys;assert importlib.util.find_spec('chio_hermes') is None;assert not (pathlib.Path(sys.executable).parent/'chio-hermes-restricted').exists();print('isolated adapter import and entrypoint removed')"])
(out/'identity.json').write_text(json.dumps({'claim':'isolated candidate replacement/removal; not public release','artifacts':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [r11,r15]},'normalHostProfileChanged':False},indent=2)+'\n')
print('isolated r11 -> r15 replacement, dependency checks, entrypoint, import origin, removal all passed')
