"""Trusted standalone supervisor. Its stdin pipe belongs only to the launcher.

The native host receives neither this pipe nor the launch specification. EOF
after launcher death stops the entire isolated host process group. This module
uses only the standard library and runs with Python isolated mode.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time


def main() -> int:
    line = sys.stdin.buffer.readline(1024 * 1024 + 1)
    if len(line) > 1024 * 1024 or not line.endswith(b"\n"):
        raise ValueError("missing bounded private host launch specification")
    spec = json.loads(line)
    stopping = threading.Event()
    interruption = signal.SIGTERM

    def interrupt(signum: int, _frame: object) -> None:
        nonlocal interruption
        interruption = signum
        stopping.set()

    def lifeline() -> None:
        # Any unexpected additional input also terminates the one-shot host.
        os.read(sys.stdin.fileno(), 1)
        stopping.set()

    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    threading.Thread(target=lifeline, daemon=True).start()
    if stopping.is_set():
        return 143
    child = subprocess.Popen(spec["command"], env=spec["env"], cwd=spec["cwd"],
                             stdin=subprocess.DEVNULL, start_new_session=True,
                             close_fds=True)

    def forward(signum: int) -> None:
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass

    deadline = None
    try:
        while child.poll() is None:
            if stopping.is_set():
                if deadline is None:
                    forward(interruption)
                    deadline = time.monotonic() + 5
                elif time.monotonic() >= deadline:
                    forward(signal.SIGKILL)
            time.sleep(0.05)
        result = child.wait()
    finally:
        # A leader can exit while a descendant ignores termination. Background
        # work is unsupported, including descendants left after normal exit.
        forward(signal.SIGKILL)
        child.wait(timeout=5)
    if result < 0:
        # Preserve the native signal status for the launcher terminal record.
        if -result not in (signal.SIGKILL, signal.SIGSTOP):
            signal.signal(-result, signal.SIG_DFL)
        os.kill(os.getpid(), -result)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
