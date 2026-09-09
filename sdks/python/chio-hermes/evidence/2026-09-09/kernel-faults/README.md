# Live authority and kernel failure boundaries

Artifact identities and individual cases are in artifact.json. All native
sessions use the installed candidate, actual native runtime, OpenAI service,
and actual Chio owner. Each initial session completes one authorized write.
Capability or session-credential revocation occurs just before forwarding its
second native call. The revoked capability yields a verified denial; revoked
credentials cannot provide verified terminal evidence and remain unknown.

The other three initial cases kill the isolated actual kernel, inject invalid
JSON at the gateway transport, or withhold that response until its configured
timeout. The latter two are deliberate transport faults, not claims that an
unmodified kernel emitted invalid bytes. No second write appears. Each unknown
session is restarted with its original private configuration and journal;
the replacement native write remains fenced and the original record is
unchanged. Restarting the killed owner preserves databases and volumes.

Six separate startup cases exercise an absent actual kernel, a genuinely
expired five-second credential, mismatched principal/session/resource, and a
configuration that advertises an unauthorized fifth tool. These refuse before
native startup. They are not native tool-call denials. Independent observers
record zero new resource actions for each. Required unexecuted paths remain
open; this bounded evidence does not accept a complete host integration.
