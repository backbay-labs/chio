"""Render Kubernetes resources from an operator's explicit deployment configuration.

Input JSON fields: image (registry/image@sha256:...), authority_url (HTTP(S)
origin), trusted_kernel_key (64 hexadecimal characters). The public key must
come from your authority operator's trusted configuration. This command renders
resources; it does not change your cluster or replace Istio MeshConfig.
"""

import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlparse


def resources(config):
    if not isinstance(config, dict) or set(config) != {
        "image",
        "authority_url",
        "trusted_kernel_key",
    }:
        raise ValueError("Configuration needs exactly image, authority_url and trusted_kernel_key")
    image = config["image"]
    key = config["trusted_kernel_key"]
    if not isinstance(config["authority_url"], str):
        raise ValueError("authority_url must be an HTTP(S) origin")
    origin = urlparse(config["authority_url"])
    if not isinstance(image, str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("image must select your built registry image by its sha256 digest")
    if not isinstance(key, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", key):
        raise ValueError(
            "trusted_kernel_key must be the operator-selected 32-byte public key in hex"
        )
    if (
        origin.scheme not in ("http", "https")
        or not origin.hostname
        or origin.username
        or origin.password
        or origin.query
        or origin.fragment
        or origin.path not in ("", "/")
    ):
        raise ValueError("authority_url must be an HTTP(S) origin without credentials or a path")
    namespace = "chio-system"
    labels = {"app.kubernetes.io/name": "chio-sidecar"}
    metadata = lambda name: {"name": name, "namespace": namespace, "labels": labels}
    container = {
        "name": "authorization",
        "image": image,
        "args": [
            "--listen",
            "0.0.0.0:9091",
            "--health-listen",
            "0.0.0.0:9092",
            "--authority-url",
            config["authority_url"],
            "--trusted-kernel-key-file",
            "/etc/chio/kernel-key.txt",
        ],
        "ports": [
            {"name": "grpc", "containerPort": 9091},
            {"name": "health", "containerPort": 9092},
        ],
        "volumeMounts": [{"name": "trust", "mountPath": "/etc/chio", "readOnly": True}],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "resources": {
            "requests": {"cpu": "100m", "memory": "128Mi"},
            "limits": {"cpu": "1", "memory": "512Mi"},
        },
        "startupProbe": {
            "httpGet": {"path": "/healthz", "port": "health"},
            "periodSeconds": 1,
            "failureThreshold": 30,
        },
        "livenessProbe": {"httpGet": {"path": "/healthz", "port": "health"}, "periodSeconds": 10},
        "readinessProbe": {"httpGet": {"path": "/readyz", "port": "health"}, "periodSeconds": 5},
    }
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": namespace, "labels": {"istio-injection": "disabled"}},
            },
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": metadata("chio-authority-trust"),
                "data": {"kernel-key.txt": key.lower() + "\n"},
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": metadata("chio-sidecar"),
                "spec": {
                    "replicas": 2,
                    "selector": {"matchLabels": labels},
                    "template": {
                        "metadata": {"labels": labels},
                        "spec": {
                            "automountServiceAccountToken": False,
                            "securityContext": {
                                "runAsNonRoot": True,
                                "runAsUser": 65532,
                                "runAsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "containers": [container],
                            "volumes": [
                                {
                                    "name": "trust",
                                    "configMap": {
                                        "name": "chio-authority-trust",
                                        "defaultMode": 292,
                                    },
                                }
                            ],
                        },
                    },
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": metadata("chio-sidecar"),
                "spec": {
                    "selector": labels,
                    "ports": [
                        {"name": "grpc", "port": 9091, "targetPort": "grpc", "appProtocol": "grpc"},
                        {
                            "name": "health",
                            "port": 9092,
                            "targetPort": "health",
                            "appProtocol": "http",
                        },
                    ],
                },
            },
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(resources(json.loads(args.config.read_text())), indent=2))
    except (ValueError, TypeError, OSError) as error:
        parser.error(str(error))
