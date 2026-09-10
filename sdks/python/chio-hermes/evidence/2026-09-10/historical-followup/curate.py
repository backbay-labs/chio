"""Retain omitted historical bytes without publishing private profile configuration."""
from pathlib import Path
import ast,gzip,hashlib,json,re,subprocess
import yaml
source=Path('/Users/connor/Medica/backbay/standalone/arc/.worktrees/hermes-required-integration-20260909/sdks/python/chio-hermes')
base=source/'evidence/2026-09-09/final-candidate/followup'
target=Path('/Users/connor/Medica/backbay/standalone/arc/.worktrees/hermes-omitted-program-work-20260910/sdks/python/chio-hermes/evidence/2026-09-10/historical-followup')
raw=target/'raw';raw.mkdir(mode=0o700,exist_ok=False)
namespace={};exec(Path('/tmp/chio-root-evidence-scan-20260909.py').read_text().split('files = 0\n')[0],namespace)
secrets=namespace['secrets'];private=[];files={};existing=[]
def add_config_secrets(v):
 if isinstance(v,dict):
  for k,c in v.items():
   key=re.sub('[^a-z]','',str(k).lower())
   if isinstance(c,str) and len(c)>=16 and (key in namespace['KEYS'] or re.search(r'(?:token|secret|password|apikey)$',key)):
    if not c.startswith('${'):secrets.add(c.encode())
   add_config_secrets(c)
 elif isinstance(v,list):
  for c in v:add_config_secrets(c)
for p in base.glob('packed-fault-interrupted-result/run-*/profile/config.yaml'):
 data=p.read_bytes();add_config_secrets(yaml.safe_load(data));private.append({'originalPath':str(p),'logicalPath':str(p.relative_to(base)),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'reason':'private historical runtime profile configuration; original preserved, raw bytes excluded'})
patterns=[rb'sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}',rb'gh[pousr]_[A-Za-z0-9]{30,}',rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----']
def export(p,name):
 data=p.read_bytes()
 if any(s in data for s in secrets) or any(re.search(pattern,data) for pattern in patterns):raise ValueError('credential exclusion match at '+name)
 enc=gzip.compress(data,mtime=0);dest=raw/(name+'.gz');dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(enc)
 assert gzip.decompress(dest.read_bytes())==data
 files[name]={'originalPath':str(p),'originalBytes':len(data),'originalSha256':hashlib.sha256(data).hexdigest(),'gzip':str(dest.relative_to(target)),'gzipSha256':hashlib.sha256(enc).hexdigest()}
for p in sorted(base.rglob('*')):
 if not p.is_file() or p.is_symlink():continue
 name=str(p.relative_to(base))
 if p.name=='config.yaml':continue
 if p.name.startswith('public-'):
  match=source/'evidence/2026-09-10/public-host-install/raw/prior-relocation'/(p.name+'.gz')
  assert match.is_file() and gzip.decompress(match.read_bytes())==p.read_bytes()
  existing.append({'originalPath':str(p),'trackedRelativePath':str(match.relative_to(source)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()});continue
 export(p,'followup/'+name)
for rel in ['scripts/probe_execution_fault.py','ACTION_INVENTORY.md']:
 p=source/rel;export(p,'omitted-source/'+rel)
 if p.suffix=='.py':ast.parse(p.read_text(),filename=rel)
(target/'files.json').write_text(json.dumps(files,indent=2)+'\n')
(target/'excluded-private-configurations.json').write_text(json.dumps(private,indent=2)+'\n')
(target/'already-retained.json').write_text(json.dumps(existing,indent=2)+'\n')
report={'sourceWorktreeHead':subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip(),'selectedBase':'7255e7aedcab8d36e99e459345f3edde55dc58a5','rawFilesExported':len(files),'knownPrivateValuesCompared':len(secrets),'privateOperatorSourcesRead':namespace['sources'],'privateProfileConfigurationsExcluded':len(private),'existingPublicInstallCopiesVerified':len(existing),'credentialMatches':0,'additionalProviderAndPrivateKeyPatternsChecked':True,'historicalHelperSyntaxParsed':True,'historicalHelperExecuted':False,'newHostTestsRun':False,'claim':'lossless curation of historical observations and omitted source; no current host or artifact acceptance'}
(target/'curation.json').write_text(json.dumps(report,indent=2)+'\n')
(target/'curate.py').write_bytes(Path(__file__).read_bytes());print(report)
