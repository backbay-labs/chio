"""Real process lifecycle regression; this is not native-host acceptance."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import pytest


@pytest.mark.parametrize("interruption", [signal.SIGTERM, signal.SIGKILL])
def test_cancellation_reaps_group_when_leader_exits_before_descendant(tmp_path: Path, interruption: int) -> None:
    marker = tmp_path / "started.json"
    child = tmp_path / "child.py"
    child.write_text(
        "import json,os,subprocess,sys,time\n"
        "p=subprocess.Popen([sys.executable,'-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)'])\n"
        "time.sleep(0.2)\n"
        f"open({str(marker)!r},'w').write(json.dumps([os.getpid(),p.pid]))\n"
        "time.sleep(60)\n"
    )
    command = (
        "import json,os,sys;from pathlib import Path;from chio_hermes.restricted import run_host;"
        "print(json.dumps(run_host([sys.executable,sys.argv[1]],dict(os.environ),Path(sys.argv[2]))),flush=True)"
    )
    runner = subprocess.Popen([sys.executable, "-c", command, str(child), str(tmp_path)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if marker.exists():
                break
            assert runner.poll() is None
            time.sleep(0.05)
        assert marker.exists()
        leader, descendant = json.loads(marker.read_text())
        runner.send_signal(interruption)
        stdout, stderr = runner.communicate(timeout=10)
        if interruption == signal.SIGKILL:
            assert runner.returncode == -signal.SIGKILL, stderr
            assert not stdout
        else:
            assert runner.returncode == 0, stderr
            assert json.loads(stdout) == [-signal.SIGTERM, signal.SIGTERM]
        for pid in (leader, descendant):
            result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True)
            assert result.returncode != 0 or result.stdout.strip().startswith("Z")
    finally:
        if runner.poll() is None:
            runner.kill()
            runner.wait(timeout=5)
        if marker.exists():
            try:
                os.killpg(json.loads(marker.read_text())[0], signal.SIGKILL)
            except ProcessLookupError:
                pass
