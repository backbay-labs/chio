"""Install the checksum-pinned Envoy executable used by this example's Linux checks."""
import hashlib
from pathlib import Path
import platform
import urllib.request

VERSION = '1.39.1'
SHA256 = '002c6e1c69ed0fa0ea381887247cadadfaec9481375fa8d8d2b1731eeabf40b8'
if platform.system() != 'Linux' or platform.machine() != 'x86_64':
    raise SystemExit('This download is for Linux x86_64. Use your platform\'s Envoy installation and set ENVOY_BIN.')
root = Path(__file__).resolve().parent / '.bin'; root.mkdir(exist_ok=True)
target = root / 'envoy'
if target.exists():
    if hashlib.sha256(target.read_bytes()).hexdigest() != SHA256:
        raise SystemExit('Existing .bin/envoy differs from the pinned executable. Inspect it before replacing it.')
else:
    temporary = root / 'envoy.download'
    try:
        with urllib.request.urlopen(f'https://github.com/envoyproxy/envoy/releases/download/v{VERSION}/envoy-{VERSION}-linux-x86_64', timeout=120) as response, temporary.open('xb') as output:
            digest = hashlib.sha256()
            while chunk := response.read(1024*1024):
                digest.update(chunk); output.write(chunk)
        if digest.hexdigest() != SHA256: raise RuntimeError('Envoy checksum mismatch')
        temporary.chmod(0o755); temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
print(target)
