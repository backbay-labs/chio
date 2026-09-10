from pathlib import Path
import datetime,gzip,hashlib,json,subprocess,tempfile,zipfile
root=Path('/Users/connor/Medica/backbay/standalone/arc/.worktrees/required-agent-integrations-20260909/docs/integrations/acceptance/20260909')
bundle=Path('/Users/connor/.local/share/chio-required-candidates/20260909')
# Reuse the exact designated-source collector; do not export its values or paths.
ns={};exec(Path('/tmp/chio-root-evidence-scan-20260909.py').read_text().split('files = 0\n')[0],ns)
patterns=b'\n'.join(sorted(ns['secrets']))+b'\n'
manifest=json.loads((bundle/'manifest.json').read_text());assert len(manifest['entries'])==48
files=[bundle/e['path'] for e in manifest['entries']]+[bundle/'manifest.json',bundle/'SHA256SUMS']
files += [p for p in root.rglob('*') if p.is_file() and not p.is_symlink()]
# ripgrep decompresses top-level gzip/tar-gzip logs and packages. ZIP payloads
# are scanned as numbered regular files so archive member names cannot escape.
staging=Path(tempfile.mkdtemp(prefix='chio-bundle-public-payload-scan-',dir='/tmp'));zip_members=0
for f in list(files):
 if f.suffix not in {'.whl','.vsix'}:continue
 with zipfile.ZipFile(f) as archive:
  for member in archive.infolist():
   if member.is_dir():continue
   target=staging/str(zip_members);target.write_bytes(archive.read(member));files.append(target);zip_members+=1
result=subprocess.run(['rg','--no-config','--text','--search-zip','--files-with-matches','--fixed-strings','--file','-','--',*[str(p) for p in files]],input=patterns,capture_output=True)
if result.returncode not in (0,1):raise RuntimeError('Credential scan command failed; diagnostics retained privately only')
report={'capturedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'passed':result.returncode==1,'selectedManifestArtifacts':48,'regularFilesScanned':len(files),'zipPayloadMembersScanned':zip_members,'privateSourcesRead':ns['sources'],'distinctSecretValuesCompared':len(ns['secrets']),'matches':len(result.stdout.splitlines()),'scope':'Exact designated provider/operator/npm credential values, held in memory and passed to ripgrep on stdin only. Selected bundle files plus the complete 20260909 acceptance tree; top-level gzip/tar-gzip and ZIP members decompressed. No install/cache/profile directories scanned or copied. Opaque nested compressed payloads inside Docker image archives are scanned only as their retained bytes. This is an exclusion check, not a generic secret detector.'}
(root/'raw/publication-and-ci/bundle-credential-exclusion.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report));assert report['passed']
verified=[]
for e in manifest['entries']:
 p=bundle/e['path'];actual=hashlib.sha256(p.read_bytes()).hexdigest();assert actual==e['sha256'] and p.stat().st_size==e['bytes'];verified.append({'path':e['path'],'sha256':actual,'bytes':p.stat().st_size,'verified':True})
previous=json.loads((root/'raw/publication-and-ci/bundle-before-manifest.json').read_text())
record={'capturedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'selectedEntries':48,'allVerified':True,'manifestSha256':hashlib.sha256((bundle/'manifest.json').read_bytes()).hexdigest(),'checksumsSha256':hashlib.sha256((bundle/'SHA256SUMS').read_bytes()).hexdigest(),'archivesPromoted':False,'artifactEntriesOtherThanReadmeUnchanged':[e for e in manifest['entries'] if e['path']!='README.md']==[e for e in previous['entries'] if e['path']!='README.md'],'entries':verified}
(root/'raw/publication-and-ci/bundle-verification.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({k:v for k,v in record.items() if k!='entries'}))
