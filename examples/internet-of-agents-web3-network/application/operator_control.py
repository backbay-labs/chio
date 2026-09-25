"""Operator-owned identity and approval commands. These keys are never tools."""

import argparse
import datetime as dt
import hashlib
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from evidence import read, signed, write
from nacl.signing import SigningKey

HOSTS = ("atlas", "proofworks", "cipherworks", "meridian")


def key(path):
    if not path.exists():
        write(path, {"seed": SigningKey.generate().encode().hex()})
    return SigningKey(bytes.fromhex(read(path)["seed"]))


def runtime(directory, host, state="ready"):
    issuer = key(directory / "operator/runtime.json")
    body = {
        "host": host,
        "status": state,
        "code_hash": hashlib.sha256(Path(__file__).with_name("domain.py").read_bytes()).hexdigest(),
        "measured_at": int(time.time()),
        "expires_at": int(time.time()) + 1800,
        "measurement": "operator-verified application source on this local host",
    }
    write(directory / host / "runtime.json", signed(body, issuer))
    return body


def bootstrap(directory):
    operator = directory / "operator"
    membership = key(operator / "membership.json")
    approval = key(operator / "approval.json")
    runtime_key = key(operator / "runtime.json")
    ca_seed = key(operator / "workload-ca.json")
    ca_key = Ed25519PrivateKey.from_private_bytes(ca_seed.encode())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Chio local work-order trust domain")]
    )
    now = dt.datetime.now(dt.UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(seconds=10))
        .not_valid_after(now + dt.timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, algorithm=None)
    )
    pem = ca.public_bytes(serialization.Encoding.PEM).decode()
    workloads = {}
    for role in ("buyer", "provider", "specialist", "auditor"):
        credentials = read(directory / "credentials" / (role + ".json"))
        public_key = credentials["capability"]["subject"]
        uri = "spiffe://work-order.local/agent/" + role
        workloads[public_key] = uri
        actor = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(credentials["seed"]))
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(name)
            .public_key(actor.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(seconds=10))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
            )
            .sign(ca_key, algorithm=None)
        )
        credentials["certificate"] = cert.public_bytes(serialization.Encoding.PEM).decode()
        write(directory / "credentials" / (role + ".json"), credentials)
    trust = {
        "workload_ca": pem,
        "workloads": workloads,
        "membership_issuer": membership.verify_key.encode().hex(),
        "approval_issuer": approval.verify_key.encode().hex(),
        "runtime_issuer": runtime_key.verify_key.encode().hex(),
        "members": ["proofworks", "discount-reviewers", "shadow-settlers"],
        "kernels": {
            host: read(directory / host / "config.json")["trusted_kernel"] for host in HOSTS
        },
        "treasury_limit": 300000,
    }
    for host in HOSTS:
        write(directory / host / "trust.json", trust)
        runtime(directory, host)
    profiles = []
    for name, price in [
        ("proofworks", 200000),
        ("discount-reviewers", 100000),
        ("shadow-settlers", 400000),
    ]:
        profiles.append(
            signed(
                {
                    "provider_id": name,
                    "price": price,
                    "currency": "wUSD",
                    "expires_at": int(time.time()) + 1800,
                    "membership": "work-order.local",
                },
                membership,
            )
        )
    write(directory / "providers.json", profiles)
    write(directory / "trust.json", trust)


def approve(directory, quote, *, review_receipt=None, amount=None):
    issuer = key(directory / "operator/approval.json")
    if review_receipt is None:
        body = {key: quote[key] for key in ["order_id", "invoice_hash", "amount", "rail"]}
        body["approved"] = True
    else:
        body = {"order_id": quote["order_id"], "amount": amount, "review_receipt": review_receipt}
    body["expires_at"] = int(time.time()) + 300
    return signed(body, issuer)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    approval = sub.add_parser(
        "approve", help="Sign a reviewed invoice from the operator-owned directory"
    )
    approval.add_argument("directory", type=Path)
    approval.add_argument("quote", type=Path)
    approval.add_argument("output", type=Path)
    appraisal = sub.add_parser("runtime", help="Quarantine or remeasure one installed host")
    appraisal.add_argument("directory", type=Path)
    appraisal.add_argument("host", choices=HOSTS)
    appraisal.add_argument("state", choices=["ready", "quarantined"])
    args = parser.parse_args()
    if args.action == "approve":
        quote = read(args.quote)
        write(args.output, approve(args.directory, quote))
        print(
            "Signed approval for", quote["order_id"], "amount", quote["amount"], "to", args.output
        )
    else:
        print(runtime(args.directory, args.host, args.state))
