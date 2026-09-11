"""Native passports, bilateral evidence exchange and federated capability issuance.

All history comes from the serving kernel's actual receipt database. The operator
selects source keys and verifier policy before any presentation is accepted.
"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from evidence import digest, read, write


def cli(*arguments, cwd, endpoint=None, token=None):
    binary = os.environ.get("CHIO_WORK_ORDER_CLI") or shutil.which("chio")
    if not binary:
        raise ValueError("Install the Chio source candidate documented in README.md")
    command = [binary, "--json"]
    if endpoint:
        command += ["--control-url", endpoint, "--control-token", token]
    command += [str(value) for value in arguments]
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=30)
    if result.returncode:
        # Do not print commands: the service credential is a private argument.
        raise ValueError("Native Chio operation failed: " + result.stderr[-1500:])
    return json.loads(result.stdout) if result.stdout.strip() else None


def seed(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(value + "\n")


class NativeTrust:
    def __init__(self, app):
        self.app = app
        self.root = app.directory
        self.directory = self.root / "meridian/native"
        self.directory.mkdir(mode=0o700)
        (self.directory / "challenges").mkdir(mode=0o700)
        self.credentials = read(self.root / "credentials/provider.json")
        self.subject = self.credentials["capability"]["subject"]
        self.token = read(self.root / "operator/meridian.json")["token"]
        self.issuer_seed = self.root / "operator/federation.seed"
        self.holder_seed = self.root / "credentials/provider.seed"
        seed(self.issuer_seed, read(self.root / "operator/issuer.json")["seed"])
        seed(self.holder_seed, self.credentials["seed"])
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            address = "127.0.0.1:" + str(listener.getsockname()[1])
        self.endpoint = "http://" + address
        log = (self.root / "federation.log").open("a")
        app.logs.append(log)
        command = [
            os.environ["CHIO_WORK_ORDER_CLI"],
            "trust",
            "serve",
            "--listen",
            address,
            "--advertise-url",
            self.endpoint,
            "--service-token",
            self.token,
            "--receipt-db",
            str(self.directory / "evidence.db"),
            "--authority-seed-file",
            str(self.issuer_seed),
            "--verifier-challenge-db",
            str(self.directory / "service-challenges.db"),
        ]
        child = subprocess.Popen(
            command, cwd=self.directory, stdin=subprocess.DEVNULL, stdout=log, stderr=log
        )
        app.children["federation"] = child
        for _ in range(300):
            if child.poll() is not None:
                raise RuntimeError("Federation service stopped; inspect " + log.name)
            try:
                with urllib.request.urlopen(self.endpoint + "/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except (urllib.error.URLError, TimeoutError):
                time.sleep(0.1)
        else:
            raise RuntimeError("Federation did not become ready; inspect " + log.name)

    def establish(self, history):
        passport = self.directory / "passport.json"
        self.run(
            "--receipt-db",
            self.root / "proofworks/receipts.db",
            "passport",
            "create",
            "--subject-public-key",
            self.subject,
            "--output",
            passport,
            "--signing-seed-file",
            self.issuer_seed,
            "--trusted-kernel-key",
            read(self.root / "proofworks/config.json")["trusted_kernel"],
            "--validity-days",
            1,
        )
        document = read(passport)
        # This one fresh work result is an observed sample, not long-term history.
        evidence = document["credentials"][0]["evidence"]
        if evidence["receiptIds"] != [history["receipt"]["id"]]:
            raise ValueError("Passport evidence differs from the actual qualification work")
        policy = {
            "issuerAllowlist": [
                "did:chio:" + read(self.root / "capabilities.json")["root"]["issuer"]
            ],
            "minReceiptCount": 1,
            "minLineageRecords": 1,
            "maxAttestationAgeDays": 1,
        }
        write(self.directory / "verifier-policy.json", policy)
        sharing = self.directory / "sharing-policy.json"
        export = self.directory / "evidence-package"
        self.run(
            "evidence",
            "federation-policy",
            "create",
            "--output",
            sharing,
            "--signing-seed-file",
            self.issuer_seed,
            "--issuer",
            "ProofWorks",
            "--partner",
            "Meridian",
            "--agent-subject",
            self.subject,
            "--admin-all",
            "--expires-at",
            int(time.time()) + 1800,
            "--purpose",
            "work-order-admission",
        )
        self.run(
            "--receipt-db",
            self.root / "proofworks/receipts.db",
            "evidence",
            "export",
            "--output",
            export,
            "--federation-policy",
            sharing,
            "--admin-all",
        )
        verified = self.run("evidence", "verify", "--input", export)
        imported = self.run("evidence", "import", "--input", export, remote=True)
        write(
            self.directory / "membership.json",
            {
                "subject": self.subject,
                "passport_hash": digest(document),
                "receipt_ids": evidence["receiptIds"],
                "evidence_verification": verified,
                "import": imported,
                "sharing_policy": read(sharing),
            },
        )
        return document

    def run(self, *arguments, remote=False):
        return cli(
            *arguments,
            cwd=self.directory,
            endpoint=self.endpoint if remote else None,
            token=self.token if remote else None,
        )

    def presentation(self, order_id, *, remote=False):
        challenge = self.directory / "challenges" / (order_id + ".json")
        if challenge.exists():
            raise ValueError("A challenge already exists for this order")
        arguments = [
            "passport",
            "challenge",
            "create",
            "--output",
            challenge,
            "--verifier",
            self.endpoint if remote else "Meridian work-order admission",
            "--policy",
            self.directory / "verifier-policy.json",
        ]
        if not remote:
            arguments += ["--verifier-challenge-db", self.directory / "admission-challenges.db"]
        self.run(*arguments, remote=remote)
        response = challenge.with_suffix(".response.json")
        self.run(
            "passport",
            "challenge",
            "respond",
            "--input",
            self.directory / "passport.json",
            "--challenge",
            challenge,
            "--holder-seed-file",
            self.holder_seed,
            "--output",
            response,
        )
        return read(response)

    def issue(self, order_id):
        self.presentation(order_id, remote=True)
        policy = self.directory / "capability-policy.json"
        write(
            policy,
            {
                "kernel": {"max_capability_ttl": 3600},
                "capabilities": {
                    "default": {
                        "tools": [
                            {
                                "server": "proofworks",
                                "tool": "review",
                                "operations": ["invoke"],
                                "max_invocations": 2,
                                "ttl": 900,
                            }
                        ]
                    }
                },
            },
        )
        result = self.run(
            "trust",
            "federated-issue",
            "--presentation-response",
            self.directory / "challenges" / (order_id + ".response.json"),
            "--challenge",
            self.directory / "challenges" / (order_id + ".json"),
            "--capability-policy",
            policy,
            remote=True,
        )
        if (
            result["verification"]["accepted"] is not True
            or result["capability"]["subject"] != self.subject
        ):
            raise ValueError("Native federation refused or changed the provider subject")
        write(self.directory / "issued-capability.json", result)
        return {**self.credentials, "capability": result["capability"]}


def verify_presentation(directory, data, *, consume=False):
    native = directory / "native"
    member = read(native / "membership.json")
    presentation = data["presentation"]
    if digest(presentation["passport"]) != member["passport_hash"]:
        raise ValueError("Presentation does not carry the admitted native passport")
    with tempfile.TemporaryDirectory(prefix="verify-", dir=native) as temporary:
        response = Path(temporary) / "response.json"
        write(response, presentation)
        arguments = [
            "passport",
            "challenge",
            "verify",
            "--input",
            response,
            "--challenge",
            native / "challenges" / (data["order_id"] + ".json"),
        ]
        if consume:
            arguments += ["--verifier-challenge-db", native / "admission-challenges.db"]
        verified = cli(*arguments, cwd=native)
    if verified["accepted"] is not True or verified["subject"] != "did:chio:" + member["subject"]:
        raise ValueError("Native passport presentation did not pass the selected verifier policy")
    return {
        "verification": verified,
        "evidence_import": member["import"],
        "passport_hash": member["passport_hash"],
        "receipt_ids": member["receipt_ids"],
    }
