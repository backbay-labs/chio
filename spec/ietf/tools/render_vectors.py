#!/usr/bin/env python3
"""Placeholder until the vector renderer lands: writes empty appendix fragments."""
import argparse, pathlib, sys
p = argparse.ArgumentParser()
p.add_argument("--vectors", required=True)
p.add_argument("--out", required=True)
p.add_argument("--check", action="store_true")
a = p.parse_args()
out = pathlib.Path(a.out)
if a.check:
    sys.exit(0)
out.mkdir(parents=True, exist_ok=True)
(out / "appendix-a.md").write_text("This appendix is being written.\n")
(out / "appendix-b.md").write_text("This appendix is being written.\n")
