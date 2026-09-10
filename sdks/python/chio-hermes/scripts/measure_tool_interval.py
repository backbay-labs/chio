#!/usr/bin/env python3
"""Three paired reads through direct bridge and native Hermes, not a benchmark."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
import time
import uuid
from pathlib import Path

BASELINE = """
import fs from 'node:fs';import {pathToFileURL} from 'node:url';import {randomUUID} from 'node:crypto';
const [modulePath,configPath,resource,recordDir]=process.argv.slice(1);
const {createMcpExecutionClient}=await import(pathToFileURL(modulePath));
const config=JSON.parse(fs.readFileSync(configPath));const client=createMcpExecutionClient(config.execution);
const checked=await client.validateSession({allowedTools:config.tools.map(t=>t.name)});if(!checked.ok)throw Error('invalid baseline session');
fs.mkdirSync(recordDir,{mode:0o700});
function persist(name,value){const fd=fs.openSync(recordDir+'/'+name,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify(value));fs.fsyncSync(fd)}finally{fs.closeSync(fd)}const d=fs.openSync(recordDir,'r');try{fs.fsyncSync(d)}finally{fs.closeSync(d)}}
const request={tool:'read_text_file',arguments:{path:resource},requestId:'hermes-timing:'+randomUUID()};persist('pending.json',request);
const start=process.hrtime.bigint();const outcome=await client.execute(request);const elapsedMs=Number(process.hrtime.bigint()-start)/1e6;
persist('outcome.json',outcome);if(outcome.state!=='completed'||outcome.evidence!=='verified'||outcome.result?.isError)throw Error('baseline not a verified successful result; do not retry');
const acknowledgement=await client.acknowledge(outcome);persist('acknowledgement.json',acknowledgement);if(!acknowledgement.acknowledged)throw Error('baseline ACK failed');
console.log(JSON.stringify({elapsedMs,state:outcome.state,evidence:outcome.evidence,acknowledged:true,requestId:request.requestId}));
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["operator-state", "bridge", "launcher-python", "host-python", "host-root", "model-auth-file", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--resource", required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    operator = json.loads((args.operator_state / "operator.json").read_text())
    samples = []

    def save(path, value):
        path.write_text(json.dumps(value, indent=2) + "\n")

    def observe():
        code = "const f=require('fs'),c=require('crypto');const files={};for(const n of f.readdirSync('/observe'))if(f.lstatSync('/observe/'+n).isFile())files[n]=c.createHash('sha256').update(f.readFileSync('/observe/'+n)).digest('hex');console.log(JSON.stringify({files,dispatch:f.readFileSync('/audit/dispatch.jsonl','utf8').split('\\n').filter(Boolean).map(JSON.parse)}))"
        return json.loads(subprocess.check_output(["docker", "run", "--rm", "--network", "none", "--read-only", "--mount", f"type=volume,src={operator['volume']},dst=/observe,readonly", "--mount", f"type=volume,src={operator['auditVolume']},dst=/audit,readonly", "--entrypoint", "node", operator["image"], "-e", code], text=True))

    def prepare(label):
        private = args.operator_state / ("hermes-timing-" + label + "-" + uuid.uuid4().hex)
        private.mkdir(mode=0o700)
        request, config = private / "prepare.json", private / "gateway.json"
        save(request, {"endpoint": f"http://127.0.0.1:{operator['port']}", "bearerToken": operator["agentToken"], "adminToken": operator["adminToken"], "credentialTtlSeconds": 900,
            "trustedSigners": [(args.operator_state / "sessions.sqlite.admission.kernel.pub").read_text().strip()], "serverId": "fs", "sessionId": str(uuid.uuid4()),
            "journalDir": str(private / "journal"), "allowedTools": ["read_text_file", "write_file", "edit_file", "list_directory"]})
        request.chmod(0o600)
        start = time.monotonic_ns()
        subprocess.run(["node", str(args.bridge / "dist/prepare-gateway.js"), str(request), str(config)], capture_output=True, check=True)
        return private, config, (time.monotonic_ns() - start) / 1e6

    before = observe()
    save(args.output / "before.json", before)
    assert Path(args.resource).name in before["files"]
    for index in range(3):
        folder = args.output / str(index)
        folder.mkdir(mode=0o700)
        direct_private, direct_config, direct_preparation = prepare("direct")
        direct_command = ["node", "--input-type=module", "-e", BASELINE, str(args.bridge / "dist/index.js"), str(direct_config), args.resource, str(direct_private / "timing-records")]
        direct = subprocess.run(direct_command, capture_output=True, text=True, timeout=60)
        (folder / "direct.stdout.json").write_text(direct.stdout)
        (folder / "direct.stderr.txt").write_text(direct.stderr)
        assert direct.returncode == 0
        baseline = json.loads(direct.stdout)
        for filename in ["pending.json", "outcome.json", "acknowledgement.json"]:
            shutil.copy2(direct_private / "timing-records" / filename, folder / ("direct-" + filename))
        private, config, native_preparation = prepare("native")
        state = Path("/tmp") / ("chio-hermes-timing-" + uuid.uuid4().hex)
        query = private / "query.txt"
        query.write_text(f"Call mcp__chio__read_text_file exactly once with path {args.resource}. Report the returned content. Do not use any other tool.")
        command = [str(args.launcher_python), "-m", "chio_hermes.restricted", "--host-python", str(args.host_python), "--host-root", str(args.host_root), "--node", shutil.which("node"), "--gateway-script", str(args.bridge / "dist/gateway-http.js"), "--gateway-config", str(config), "--state-dir", str(state), "--query-file", str(query), "--model", "gpt-5.5", "--model-auth", "codex-subscription", "--codex-auth-file", str(args.model_auth_file), "--max-turns", "5"]
        env = os.environ.copy()
        env.pop("NODE_OPTIONS", None)
        wall_start = time.monotonic_ns()
        native = subprocess.run(command, capture_output=True, text=True, timeout=220, env=env)
        wall_end = time.monotonic_ns()
        (folder / "native.stdout.txt").write_text(native.stdout)
        (folder / "native.stderr.txt").write_text(native.stderr)
        for filename in ["launch.json", "terminal.json", "model-relay.json", "host-delivery.json", "host.sb"]:
            shutil.copy2(state / filename, folder / filename)
        log = (state / "profile/logs/agent.log").read_text()
        (folder / "agent.log").write_text(log)
        intervals = re.findall(r"tool mcp__chio__read_text_file completed \(([0-9.]+)s,", log)
        assert native.returncode == 0 and len(intervals) == 1
        native_ms = float(intervals[0]) * 1000
        records = [json.loads(path.read_text()) for path in (private / "journal").glob("*.json")]
        assert len(records) == 1 and records[0]["acknowledged"] and records[0]["hostDeliveryConfirmed"]
        assert records[0]["request"]["tool"] == "read_text_file" and records[0]["request"]["arguments"] == {"path": args.resource}
        save(folder / "native-journal.json", records[0])
        sample = {"pair": index, "directBridgeExecuteMs": baseline["elapsedMs"], "nativeHermesLoggedToolMs": native_ms, "differenceMs": native_ms - baseline["elapsedMs"],
                  "nativeLoggedResolutionMs": 10, "nativeProcessStartMonotonicNs": wall_start, "nativeProcessEndMonotonicNs": wall_end,
                  "nativeProcessWallMs": (wall_end - wall_start) / 1e6, "directPreparationMs": direct_preparation, "nativePreparationMs": native_preparation,
                  "nativeCommand": command, "directConfigurationSha256": hashlib.sha256(direct_config.read_bytes()).hexdigest(), "nativeConfigurationSha256": hashlib.sha256(config.read_bytes()).hexdigest(),
                  "directPrivateState": str(direct_private), "nativePrivateState": str(private)}
        samples.append(sample)
        save(args.output / "samples.json", samples)
    after = observe()
    save(args.output / "after.json", after)
    delta = after["dispatch"][len(before["dispatch"]):]
    assert before["files"] == after["files"] and len(delta) == 6 and all(row["tool"] == "read_text_file" and row["path"] == args.resource for row in delta)
    save(args.output / "summary.json", {"pairedSamples": 3, "nativeReads": 3, "directOperatorBaselineReads": 3, "observedDispatches": 6, "filesUnchanged": True,
        "medianDirectBridgeExecuteMs": statistics.median(row["directBridgeExecuteMs"] for row in samples), "medianNativeLoggedToolMs": statistics.median(row["nativeHermesLoggedToolMs"] for row in samples),
        "medianPairedDifferenceMs": statistics.median(row["differenceMs"] for row in samples), "model": "gpt-5.5", "kernelSha256": operator["kernelSha256"],
        "harnessSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "nativeTimingSourceSha256": hashlib.sha256((args.host_root / "agent/tool_executor.py").read_bytes()).hexdigest(),
        "interventions": "One operator session preparation for each native or baseline run; native reads require no manual approval, retries or repair.",
        "scope": "Three sequential paired read-only observations on a separate healthy owner. Both paths include the same bridge verification, kernel and resource. Native logged interval includes host dispatch, HTTP gateway and gateway journal; it uses host time.time rounded to 10ms. Baseline execute excludes its reservation/completion writes, preparation and later ACK. Native total process wall time includes startup, model traffic, later delivery ACK and shutdown; startup/model latency are not separately measured. These noisy differences do not isolate kernel cost or establish a latency guarantee. Direct calls are a timing baseline only, not native acceptance or recovery of any storage-fault authority."})
    print((args.output / "summary.json").read_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
