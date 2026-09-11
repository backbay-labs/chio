"""Check the newest retained run using its separately selected auditor key."""

import json
import os
import unittest
from pathlib import Path

from evidence import read
from verify import verify


def main():
    root = Path(__file__).resolve().parent
    runs = list((root / ".state").glob("*/execution.json"))
    if not runs:
        raise SystemExit("Run the work-order application before checking its capture")
    capture = max(runs, key=lambda path: path.stat().st_mtime_ns)
    # The operator provisioned this kernel identity before the audited work.
    key = read(capture.parent / "meridian/config.json")["trusted_kernel"]
    os.environ["WORK_ORDER_CAPTURE"] = str(capture)
    os.environ["WORK_ORDER_AUDITOR_KEY"] = key
    result = verify(read(capture), key)
    print(json.dumps(result, indent=2))
    suite = unittest.defaultTestLoader.discover(str(root), pattern="test_evidence.py")
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
