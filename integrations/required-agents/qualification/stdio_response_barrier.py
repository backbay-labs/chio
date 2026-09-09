#!/usr/bin/env python3
"""Retain an actual resource reply at an explicitly selected dispatch cutpoint."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    requests = {}

    def read_responses():
        for line in child.stdout:
            response = json.loads(line)
            request = requests.get(str(response.get("id")), {})
            path = request.get("params", {}).get("arguments", {}).get("path", "")
            if path.endswith("/uncertain.txt") and request.get("method") == "tools/call":
                marker = args.directory / "resource-replied.json"
                if not marker.exists():
                    marker.write_text(json.dumps({"request": request, "response": response}))
                    while not (args.directory / "release").exists():
                        time.sleep(0.01)
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    reader = threading.Thread(target=read_responses, daemon=True)
    reader.start()
    try:
        for line in sys.stdin.buffer:
            request = json.loads(line)
            if "id" in request:
                requests[str(request["id"])] = request
            child.stdin.write(line)
            child.stdin.flush()
    finally:
        child.stdin.close()
        child.wait(timeout=10)


if __name__ == "__main__":
    main()
