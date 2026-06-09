# chio-mercury-core

`chio-mercury-core` defines MERCURY evidence contracts layered on Chio receipt
truth. It owns receipt metadata, bundle manifests, proof packages, inquiry
packages, and bounded product package shapes; command orchestration and file
export live in `chio-mercury`.

Use this crate when validating or constructing MERCURY evidence artifacts.
Validators fail closed on schema drift, missing required evidence, inconsistent
workflow scope, malformed optional business identifiers, and mismatched Chio
receipt, checkpoint, or bundle bindings.
