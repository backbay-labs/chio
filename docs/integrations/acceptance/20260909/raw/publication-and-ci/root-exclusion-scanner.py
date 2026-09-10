from pathlib import Path
import hashlib, json, os, re

ROOT = Path('/Users/connor/Medica/backbay/standalone/arc/.worktrees/required-agent-integrations-20260909')
BASE = Path('/Users/connor/.local/share/chio-required-operators')
EVIDENCE = ROOT / 'docs/integrations/acceptance/20260909'
KEYS = {'accesstoken', 'refreshtoken', 'idtoken', 'bearertoken', 'admintoken', 'agenttoken', 'authorization', 'apikey', 'accountid'}
secrets = set()
sources = 0
def collect(value):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub('[^a-z]', '', key.lower())
            if normalized in KEYS and isinstance(child, str) and len(child) >= 16:
                secrets.add(child.encode())
                if child.lower().startswith('bearer '):
                    secrets.add(child[7:].encode())
            collect(child)
    elif isinstance(value, list):
        for child in value:
            collect(child)
for path in BASE.rglob('*.json'):
    if path.name not in {'operator.json', 'gateway.json', 'prepare.json', 'auth.json', 'capture.private.json'} or path.is_symlink():
        continue
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        continue
    sources += 1
    collect(data)
for key in ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN']:
    value = os.environ.get(key)
    if value and len(value) >= 16:
        secrets.add(value.encode())
rc = BASE / 'npm-publisher-auth-20260909/npmrc'
if rc.is_file():
    for line in rc.read_text().splitlines():
        if '_authToken=' in line:
            secrets.add(line.split('=', 1)[1].strip().encode())
files = 0
leaks = []
for path in EVIDENCE.rglob('*'):
    if not path.is_file() or path.is_symlink():
        continue
    body = path.read_bytes()
    files += 1
    if any(secret in body for secret in secrets):
        leaks.append(str(path.relative_to(EVIDENCE)))
report = {'passed': not leaks, 'filesScanned': files, 'privateSourcesRead': sources, 'distinctSecretValuesCompared': len(secrets), 'matchingPaths': leaks, 'scope': 'Exact provider, npm, designated operator and delegated session credentials; values are never exported. Public signatures and identity descriptors are not bearer credentials.'}
(EVIDENCE / 'raw/native-subscription-auth/root-credential-exclusion.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
if leaks:
    raise SystemExit(1)
for name in ['local-delivery-final-native', 'actual-capability-expiry', 'subscription-relay-audit']:
    base = EVIDENCE / 'raw' / name
    lines = []
    for path in sorted(base.rglob('*')):
        if path.is_file() and path.name != 'SHA256SUMS' and not path.is_symlink():
            lines.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + str(path.relative_to(base)))
    (base / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
