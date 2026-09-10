#!/usr/bin/env python3
"""Operator fault harness for the installed restricted launcher's plugin dependency.

This executes the installed launcher and real Hermes. It deliberately removes
host wiring or substitutes failed startup modules. It is not a hook verdict
simulation. Independent resource observations distinguish startup refusals from
native tool-call denials; none of these fault cases qualifies useful operation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import uuid
from pathlib import Path

from chio_hermes import restricted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fault", choices=["omitted-profile", "missing", "crash", "timeout"], required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--operator-state", type=Path, required=True)
    args, launcher_args = parser.parse_known_args()
    if launcher_args[:1] == ["--"]:
        launcher_args = launcher_args[1:]
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    operator = json.loads((args.operator_state / "operator.json").read_text())

    def observe():
        code = "const f=require('fs');const files={};for(const n of f.readdirSync('/observe'))if(f.lstatSync('/observe/'+n).isFile())files[n]=f.readFileSync('/observe/'+n,'utf8');console.log(JSON.stringify({files,dispatch:f.readFileSync('/audit/dispatch.jsonl','utf8').split('\\n').filter(Boolean).map(JSON.parse)}))"
        return json.loads(subprocess.check_output(["docker", "run", "--rm", "--network", "none", "--read-only", "--mount", f"type=volume,src={operator['volume']},dst=/observe,readonly", "--mount", f"type=volume,src={operator['auditVolume']},dst=/audit,readonly", "--entrypoint", "node", operator["image"], "-e", code], text=True))

    record = {"fault": args.fault, "claim": "bounded current artifact plugin dependency fault, not useful-work acceptance", "nativeHostStarted": False,
              "installedLauncher": restricted.__file__, "launcherSha256": hashlib.sha256(Path(restricted.__file__).read_bytes()).hexdigest()}
    original_prepare, original_run = restricted.prepare, restricted.run_host

    def prepare(namespace):
        command, env, workspace = original_prepare(namespace)
        if args.fault == "omitted-profile":
            path = namespace.state_dir / "profile/config.yaml"
            config = json.loads(path.read_text())
            record["configurationBeforeSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            config["mcp_servers"] = {}
            path.write_text(json.dumps(config, indent=2) + "\n")
            record["configurationAfterSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        return command, env, workspace

    def run_host(command, env, workspace):
        record["nativeHostStarted"] = True
        return original_run(command, env, workspace)

    if args.fault != "omitted-profile":
        index = launcher_args.index("--gateway-script") + 1
        installed = Path(launcher_args[index]).resolve()
        private = args.operator_state / ("hermes-plugin-startup-" + uuid.uuid4().hex)
        private.mkdir(mode=0o700)
        replacement = private / "gateway-http.mjs"
        (private / "execution.js").write_text("export {verifyCompletedOutcome} from " + json.dumps((installed.parent / "execution.js").as_uri()) + ";\n")
        if args.fault == "crash":
            replacement.write_text('export async function startGatewayHttp(){throw new Error("injected plugin startup failure");}\n')
        elif args.fault == "timeout":
            replacement.write_text('export async function startGatewayHttp(){process.stdin.resume();process.stdin.once("end",()=>process.exit(0));await new Promise(()=>{});}\n')
        launcher_args[index] = str(replacement)
        record["failureModule"] = str(replacement)
        if replacement.exists():
            record["failureModuleSha256"] = hashlib.sha256(replacement.read_bytes()).hexdigest()
    restricted.prepare, restricted.run_host = prepare, run_host
    before = observe()
    (args.evidence / "before.json").write_text(json.dumps(before, indent=2) + "\n")
    sys.argv = ["chio-hermes-restricted", *launcher_args]
    try:
        record["launcherExitCode"] = restricted.main()
    except SystemExit as exc:
        record["launcherExitCode"] = exc.code
    after = observe()
    (args.evidence / "after.json").write_text(json.dumps(after, indent=2) + "\n")
    record["resourceUnchanged"] = before == after
    record["newDispatchRows"] = len(after["dispatch"]) - len(before["dispatch"])
    if args.fault != "omitted-profile":
        passed = record["launcherExitCode"] != 0 and not record["nativeHostStarted"] and before == after
    else:
        # Either a detected unavailable toolset or an empty-tool conversation
        # may be legitimate. Inspect actual registry/logs; never call this a
        # native blocked tool invocation when the host didn't dispatch one.
        passed = record["nativeHostStarted"] and before == after
    record["passedBoundedFaultObservation"] = passed
    (args.evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
