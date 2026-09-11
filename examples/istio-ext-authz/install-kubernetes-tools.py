"""Install the example's checksum-pinned cluster tools into .tools/.

Uses official kind, Kubernetes and Istio releases. Does not change PATH,
system installations, Docker configuration or any existing cluster.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent


def main():
    system = platform.system().lower()
    architecture = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    releases = json.loads((ROOT / "kubernetes-tools.json").read_text())
    selection = releases.get(f"{system}-{architecture}")
    if selection is None:
        raise SystemExit("This installer supports Linux and macOS on x86_64 or arm64.")
    destination = ROOT / ".tools"
    destination.mkdir(exist_ok=True)
    for name, release in selection.items():
        print(f"Downloading {name} from {release['url']}", flush=True)
        with urllib.request.urlopen(release["url"], timeout=120) as response:
            content = response.read(200 * 1024 * 1024 + 1)
        if hashlib.sha256(content).hexdigest() != release["sha256"]:
            raise SystemExit(f"{name}: release checksum does not match; nothing installed.")
        if name == "istioctl":
            # Read the exact regular-file member, never extract archive paths.
            with tarfile.open(fileobj=io.BytesIO(content)) as archive:
                member = archive.getmember("istio-1.31.0/bin/istioctl")
                if not member.isfile() or member.size > 200 * 1024 * 1024:
                    raise SystemExit("The Istio archive does not contain the expected binary.")
                source = archive.extractfile(member)
                if source is None:
                    raise SystemExit("The Istio binary could not be read.")
                content = source.read()
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=destination, delete=False) as output:
                temporary = Path(output.name)
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            temporary.chmod(0o755)
            os.replace(temporary, destination / name)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    print("Installed kind 0.33.0, Kubernetes CLI 1.36.4 and Istio 1.31.0 into .tools/.")


if __name__ == "__main__":
    main()
