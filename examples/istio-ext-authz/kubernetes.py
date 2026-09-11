# /// script
# requires-python = ">=3.11"
# dependencies = ["chio-sdk"]
# [tool.uv.sources]
# chio-sdk = { path = "../../sdks/python/chio-py" }
# ///
"""Qualify the supplied Istio deployment in an owned, temporary kind cluster.

Requires Docker, kind, kubectl and istioctl. Keeps evidence under .kubernetes/;
removes only the cluster and registry created by this invocation. Every kubectl
and Istio command uses this run's separate kubeconfig.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from chio.invariants import (
    canonicalize_json,
    sha256_hex_utf8,
    verify_http_receipt_with_trusted_signers,
)
from deploy import resources

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[1]
PYTHON_IMAGE = "python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2"
NODE_IMAGE = (
    "kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed"
)
REGISTRY_IMAGE = (
    "registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    installed = ROOT / ".tools"
    os.environ["PATH"] = str(installed) + os.pathsep + os.environ.get("PATH", "")
    for program in ("docker", "kind", "kubectl", "istioctl"):
        if not shutil.which(program):
            raise SystemExit(f"Install {program} using the prerequisites in README.md")
    os.umask(0o077)
    name = "chio-notes-" + uuid.uuid4().hex[:12]
    registry = name + "-registry"
    state = ROOT / ".kubernetes" / name
    state.mkdir(parents=True)
    kubeconfig = str(state / "kubeconfig")
    children = []
    forward_log = None
    cluster_created = registry_created = False
    observations = []
    with (state / "commands.log").open("w") as log:

        def run(command, *, data=None, capture=False, check=True, timeout=900):
            result = subprocess.run(
                command,
                cwd=REPOSITORY,
                input=data,
                text=True,
                stdout=subprocess.PIPE if capture else log,
                stderr=log,
                timeout=timeout,
                check=check,
            )
            return result.stdout.strip() if capture else result.returncode

        def kube(*arguments, **options):
            return run(["kubectl", "--kubeconfig", kubeconfig, *arguments], **options)

        def apply(value):
            kube("apply", "-f", "-", data=json.dumps(value))

        def rollout(namespace, deployment):
            kube("-n", namespace, "rollout", "status", "deployment/" + deployment, "--timeout=300s")

        def authority(path, body=None):
            request = urllib.request.Request(
                "http://127.0.0.1:" + local_port + path,
                data=None if body is None else json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.load(response)

        def client(path="/notes", body=None, grant=None, expected=200):
            # The request originates in a separate pod and enters the notes
            # pod through its actual Istio inbound proxy. Port-forwarding the
            # notes container would bypass that interception boundary.
            request = {"path": path, "body": body, "grant": grant}
            program = """import json,sys,urllib.request,urllib.error
p=json.load(sys.stdin);headers={'Content-Type':'application/json'}
if p['grant'] is not None: headers['X-Chio-Capability']=json.dumps(p['grant'],separators=(',',':'))
r=urllib.request.Request('http://demo-tool.agent-tools.svc.cluster.local'+p['path'],data=None if p['body'] is None else json.dumps(p['body']).encode(),headers=headers)
try: response=urllib.request.urlopen(r,timeout=15)
except urllib.error.HTTPError as error: response=error
with response:
 raw=response.read()
 try: body=json.loads(raw)
 except ValueError: body=raw.decode()
 print(json.dumps({'status':response.status,'receipt_id':response.headers.get('x-chio-receipt-id'),'body':body}))
"""
            response = json.loads(
                kube(
                    "-n",
                    "chio-system",
                    "exec",
                    "-i",
                    "client",
                    "--",
                    "python3",
                    "-c",
                    program,
                    data=json.dumps(request),
                    capture=True,
                )
            )
            if response["status"] != expected:
                raise AssertionError(f"Expected {expected}: {response}")
            if path != "/healthz" and expected in (200, 201, 403) and not response["receipt_id"]:
                raise AssertionError("Protected request is missing its admission receipt ID")
            observations.append(
                {
                    "path": path,
                    "request_body": body,
                    "capability_id": None if grant is None else grant["id"],
                    **response,
                }
            )
            return response["body"]

        try:
            print("Building the authorization and authority images", flush=True)
            for target in ("runtime", "authority"):
                run(
                    [
                        "docker",
                        "build",
                        "--target",
                        target,
                        "-f",
                        str(ROOT / "Dockerfile"),
                        "-t",
                        name + ":" + target,
                        ".",
                    ],
                    timeout=7200,
                )
            run(
                ["docker", "run", "-d", "--name", registry, "-p", "127.0.0.1::5000", REGISTRY_IMAGE]
            )
            registry_created = True
            port_mapping = json.loads(
                run(
                    ["docker", "inspect", registry, "--format", "{{json .NetworkSettings.Ports}}"],
                    capture=True,
                )
            )
            registry_port = port_mapping["5000/tcp"][0]["HostPort"]
            deadline = time.monotonic() + 30
            while True:
                try:
                    with urllib.request.urlopen(
                        f"http://127.0.0.1:{registry_port}/v2/", timeout=2
                    ) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError) as error:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "The owned image registry did not become ready"
                        ) from error
                    time.sleep(0.2)
            image_references = {}
            for target in ("runtime", "authority"):
                tag = f"localhost:{registry_port}/chio-{target}:{name}"
                run(["docker", "tag", name + ":" + target, tag])
                run(["docker", "push", tag])
                refs = json.loads(
                    run(
                        ["docker", "image", "inspect", tag, "--format", "{{json .RepoDigests}}"],
                        capture=True,
                    )
                )
                image_references[target] = next(
                    ref
                    for ref in refs
                    if ref.startswith(f"localhost:{registry_port}/chio-{target}@sha256:")
                )
            (state / "images.json").write_text(json.dumps(image_references, indent=2) + "\n")
            print("Creating an isolated kind cluster and installing Istio", flush=True)
            # Register ownership before creation so failed bootstrap is cleaned.
            cluster_created = True
            run(
                [
                    "kind",
                    "create",
                    "cluster",
                    "--name",
                    name,
                    "--kubeconfig",
                    kubeconfig,
                    "--image",
                    NODE_IMAGE,
                    "--wait",
                    "180s",
                ]
            )
            run(["docker", "network", "connect", "kind", registry])
            nodes = run(["kind", "get", "nodes", "--name", name], capture=True).splitlines()
            for node in nodes:
                registry_directory = f"/etc/containerd/certs.d/localhost:{registry_port}"
                run(["docker", "exec", node, "mkdir", "-p", registry_directory])
                run(
                    [
                        "docker",
                        "exec",
                        "-i",
                        node,
                        "cp",
                        "/dev/stdin",
                        registry_directory + "/hosts.toml",
                    ],
                    data=f'[host."http://{registry}:5000"]\n  capabilities = ["pull", "resolve"]\n',
                )
            run(
                [
                    "istioctl",
                    "--kubeconfig",
                    kubeconfig,
                    "install",
                    "-y",
                    "--set",
                    "profile=minimal",
                    "-f",
                    str(ROOT / "01-meshconfig-patch.yaml"),
                ]
            )
            apply(
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {"name": "chio-system", "labels": {"istio-injection": "disabled"}},
                }
            )
            kube("apply", "-f", str(ROOT / "03-demo-workload.yaml"))
            rollout("agent-tools", "demo-tool")
            apply(
                {
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {"name": "notes-api-contract", "namespace": "chio-system"},
                    "data": {"openapi.yaml": (ROOT / "local/openapi.yaml").read_text()},
                }
            )
            apply(
                {
                    "apiVersion": "v1",
                    "kind": "PersistentVolumeClaim",
                    "metadata": {"name": "notes-authority", "namespace": "chio-system"},
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": "128Mi"}},
                    },
                }
            )
            apply(
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "notes-authority", "namespace": "chio-system"},
                    "spec": {
                        "replicas": 1,
                        "strategy": {"type": "Recreate"},
                        "selector": {"matchLabels": {"app": "notes-authority"}},
                        "template": {
                            "metadata": {"labels": {"app": "notes-authority"}},
                            "spec": {
                                "automountServiceAccountToken": False,
                                "securityContext": {
                                    "runAsNonRoot": True,
                                    "runAsUser": 65532,
                                    "runAsGroup": 65532,
                                    "fsGroup": 65532,
                                },
                                "containers": [
                                    {
                                        "name": "authority",
                                        "workingDir": "/data",
                                        "image": image_references["authority"],
                                        "args": [
                                            "--authority-seed-file",
                                            "/data/authority.hex",
                                            "api",
                                            "protect",
                                            "--upstream",
                                            "http://demo-tool.agent-tools.svc.cluster.local",
                                            "--spec",
                                            "/contract/openapi.yaml",
                                            "--listen",
                                            "0.0.0.0:9097",
                                            "--receipt-store",
                                            "/data/receipts.db",
                                        ],
                                        "ports": [{"name": "http", "containerPort": 9097}],
                                        "readinessProbe": {
                                            "httpGet": {"path": "/chio/health", "port": "http"}
                                        },
                                        "volumeMounts": [
                                            {"name": "data", "mountPath": "/data"},
                                            {
                                                "name": "contract",
                                                "mountPath": "/contract",
                                                "readOnly": True,
                                            },
                                        ],
                                    }
                                ],
                                "volumes": [
                                    {
                                        "name": "data",
                                        "persistentVolumeClaim": {"claimName": "notes-authority"},
                                    },
                                    {
                                        "name": "contract",
                                        "configMap": {"name": "notes-api-contract"},
                                    },
                                ],
                            },
                        },
                    },
                }
            )
            apply(
                {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {"name": "notes-authority", "namespace": "chio-system"},
                    "spec": {
                        "selector": {"app": "notes-authority"},
                        "ports": [{"port": 9097, "targetPort": "http"}],
                    },
                }
            )
            rollout("chio-system", "notes-authority")
            # Let kubectl choose an available loopback port; its diagnostic is
            # read only from this owned subprocess, never an unrelated listener.
            forward_log = (state / "authority-forward.log").open("w")
            forwarding = subprocess.Popen(
                [
                    "kubectl",
                    "--kubeconfig",
                    kubeconfig,
                    "-n",
                    "chio-system",
                    "port-forward",
                    "service/notes-authority",
                    ":9097",
                    "--address",
                    "127.0.0.1",
                ],
                stdout=forward_log,
                stderr=forward_log,
            )
            children.append(forwarding)
            deadline = time.monotonic() + 30
            while True:
                lines = (state / "authority-forward.log").read_text().splitlines()
                found = next(
                    (line for line in lines if line.startswith("Forwarding from 127.0.0.1:")), None
                )
                if found:
                    local_port = found.split(":")[1].split()[0]
                    break
                if forwarding.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("Authority port forwarding did not become ready")
                time.sleep(0.1)
            issuance = {
                "subject": "istio-notes-writer",
                "job_uid": name,
                "ttl_seconds": 300,
                "scopes": ["tool:chio_http_authority:authorize_http_request:invoke"],
            }
            token = authority("/v1/capabilities/mint", issuance)["capability"]
            signer = token["issuer"]
            (state / "trusted-kernel-key.txt").write_text(signer + "\n")
            config = {
                "image": image_references["runtime"],
                "authority_url": "http://notes-authority.chio-system.svc.cluster.local:9097",
                "trusted_kernel_key": signer,
            }
            (state / "deployment.json").write_text(json.dumps(config, indent=2) + "\n")
            apply(resources(config))
            rollout("chio-system", "chio-sidecar")
            kube("apply", "-f", str(ROOT / "02-authorization-policy.yaml"))
            apply(
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "client", "namespace": "chio-system"},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "containers": [
                            {
                                "name": "client",
                                "image": PYTHON_IMAGE,
                                "command": ["python3", "-c", "import time; time.sleep(3600)"],
                            }
                        ],
                    },
                }
            )
            kube(
                "-n", "chio-system", "wait", "--for=condition=Ready", "pod/client", "--timeout=180s"
            )
            run(["istioctl", "--kubeconfig", kubeconfig, "proxy-status"], capture=False)
            # Establish policy propagation with a read-only request. A 200 from
            # an unprotected route is insufficient: admission must supply its ID.
            deadline = time.monotonic() + 60
            while True:
                try:
                    client()
                    break
                except AssertionError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.5)
            print("Testing the actual Istio request path", flush=True)
            client("/healthz")
            before = client()["notes"]
            client(body={"text": "ungranted write must not appear"}, expected=403)
            created = client(
                body={"text": "Review the Istio deployment"}, grant=token, expected=201
            )
            after = client()["notes"]
            assert len(after) == len(before) + 1 and any(
                note["id"] == created["id"] for note in after
            )
            authority("/v1/capabilities/release", {"capability_id": token["id"]})
            client(body={"text": "revoked write must not appear"}, grant=token, expected=403)
            assert client()["notes"] == after
            # Export current records through SQLite itself, including committed
            # WAL data; copying a live database file would lose that consistency.
            export = "import sqlite3,json; c=sqlite3.connect('file:/data/receipts.db?mode=ro',uri=True); print(json.dumps([json.loads(r[0]) for r in c.execute('SELECT receipt_json FROM http_receipts')]))"
            records = json.loads(
                kube(
                    "-n",
                    "chio-system",
                    "exec",
                    "deployment/notes-authority",
                    "--",
                    "python3",
                    "-c",
                    export,
                    capture=True,
                )
            )
            by_id = {record["id"]: record for record in records}
            for observation in observations:
                if observation["path"] == "/healthz":
                    continue
                receipt = by_id[observation["receipt_id"]]
                assert verify_http_receipt_with_trusted_signers(receipt, [signer])["ok"]
                body = observation["request_body"]
                binding = {
                    "method": "GET" if body is None else "POST",
                    "route_pattern": "/notes",
                    "path": "/notes",
                    "query": {},
                    "body_hash": None,
                }
                if body is not None:
                    binding["body_hash"] = hashlib.sha256(json.dumps(body).encode()).hexdigest()
                assert receipt["content_hash"] == sha256_hex_utf8(canonicalize_json(binding)), {
                    "receipt_id": receipt["id"],
                    "expected_binding": binding,
                    "observed_hash": receipt["content_hash"],
                }
                expected_verdict = "deny" if observation["status"] == 403 else "allow"
                assert receipt["verdict"]["verdict"] == expected_verdict
                assert receipt.get("capability_id") == observation["capability_id"]
                assert receipt["method"] == binding["method"]
                assert receipt["route_pattern"] == "/notes"
                assert receipt.get("metadata", {}).get("chio_http_status_scope") == "decision"
                observation["receipt"] = receipt
            kube("-n", "chio-system", "scale", "deployment/notes-authority", "--replicas=0")
            kube(
                "-n",
                "chio-system",
                "wait",
                "--for=delete",
                "pod",
                "-l",
                "app=notes-authority",
                "--timeout=90s",
            )
            client(body={"text": "outage write must not appear"}, grant=token, expected=503)
            client("/healthz")
            # Read the data in the owning workload, without asserting that an
            # unavailable authorization service should admit a diagnostic read.
            check = "import sqlite3,json; c=sqlite3.connect('file:/data/notes.db?mode=ro',uri=True); print(json.dumps([{'id':r[0],'text':r[1]} for r in c.execute('SELECT id,text FROM notes ORDER BY id')]))"
            retained = json.loads(
                kube(
                    "-n",
                    "agent-tools",
                    "exec",
                    "deployment/demo-tool",
                    "-c",
                    "notes",
                    "--",
                    "python3",
                    "-c",
                    check,
                    capture=True,
                )
            )
            assert retained == after
            (state / "verification.json").write_text(
                json.dumps(
                    {
                        "ok": True,
                        "kubernetes_image": NODE_IMAGE,
                        "images": image_references,
                        "trusted_kernel_key": signer,
                        "observations": observations,
                        "retained_notes": retained,
                    },
                    indent=2,
                )
                + "\n"
            )
            print(
                "Passed: Istio allow, missing grant, revocation, exact signed bodies, and outage without another effect.",
                flush=True,
            )
            print("Evidence:", state.relative_to(ROOT), flush=True)
        finally:
            for process in children:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            if forward_log is not None:
                forward_log.close()
            if cluster_created:
                kube("get", "pods", "-A", check=False, timeout=30)
                run(
                    ["kind", "export", "logs", "--name", name, str(state / "cluster-logs")],
                    check=False,
                    timeout=120,
                )
                run(
                    ["kind", "delete", "cluster", "--name", name, "--kubeconfig", kubeconfig],
                    check=False,
                    timeout=120,
                )
            if registry_created:
                run(["docker", "rm", "-f", registry], check=False, timeout=30)


if __name__ == "__main__":
    main()
