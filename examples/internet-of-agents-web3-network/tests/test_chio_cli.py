import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from internet_web3 import chio_cli


class ChioCliCommandProvenanceTest(unittest.TestCase):
    def test_run_chio_records_portable_command_name(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({"accepted": True}),
            stderr="",
        )
        local_bin = "/tmp/chio-worktree/target/debug/chio"

        with patch.dict("os.environ", {"CHIO_BIN": local_bin}, clear=False):
            with patch("subprocess.run", return_value=completed) as run:
                result = chio_cli._run_chio(["passport", "verify"], cwd=Path.cwd())

        self.assertEqual(run.call_args.args[0][0], local_bin)
        self.assertEqual(result["command"], ["chio", "--format", "json", "passport", "verify"])


if __name__ == "__main__":
    unittest.main()
