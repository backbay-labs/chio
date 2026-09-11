#!/usr/bin/env python3
"""Run the current delegated work-order application."""
import shutil
import subprocess
import sys
from pathlib import Path

if not shutil.which("uv"):
    raise SystemExit("Install uv before running this application.")
application = Path(__file__).resolve().parent / "application"
raise SystemExit(subprocess.call(["uv", "run", "--locked", "run.py", *sys.argv[1:]], cwd=application))
