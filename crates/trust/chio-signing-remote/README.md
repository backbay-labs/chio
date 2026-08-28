# chio-signing-remote

`chio-signing-remote` implements fail-closed `SigningBackend` adapters for a
versioned Chio HTTP signer and HashiCorp Vault Transit. Both adapters pin an
Ed25519 public key and explicit key version, reject redirects, bound response
sizes, and verify every returned signature locally over the exact input bytes.

Production endpoints must use HTTPS. Plain HTTP is accepted only for literal
loopback endpoints used by local qualification.
