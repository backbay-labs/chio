# Hermes trusted launcher death

The r10 wheel left the actual native Hermes process alive 12 seconds after its
launcher was SIGKILLed following a committed write, before result delivery. The
private gateway stopped, the original completion remained unacknowledged, and
the harness explicitly killed the observed orphan. The failure is retained.

The r11 wheel adds a trusted isolated Python supervisor with a private parent
liveness pipe. The native host cannot inherit or keep the pipe open. Launcher
death stops the isolated native process group, including descendants whose
leader exits first. The component suite passes 237 tests, with four legacy
opt-in skips still unresolved. The cold-installed wheel SHA256 is
f2c3d0e79a04c496c80950dccaa5752177216e7d2d267deb78c6b5c3f953b4f3.

The actual r11 Hermes/OpenAI/kernel crash case passed automatic process absence,
original-authority restart fencing and explicit recovery. The original write
occurred once; recovery added one read and no write. SIGKILL produces no launcher
terminal report, so the retained unacknowledged journal remains authoritative.
Other r11 acceptance cases must be rerun independently before replacing r10's
bounded evidence. Neither build is an accepted integration.


The r11 native reruns additionally passed useful write/edit/read/list, forbidden
read/write, response loss, private gateway crash, operator SIGTERM, revocation,
in-flight capability/credential revocation, actual kernel death and its fenced
restart, malformed response, and all seven approval stages. Six separate
preflight cases passed absent kernel, expired credential, wrong principal,
session/resource, and scope escalation. These startup refusals are not native
tool-call denials. Every attempted run is retained in rerun-records.json.

The first budget run stopped after one legitimate write and did not reach the
budget limit; it failed qualification. A subsequent explicit-call budget test
and the malformed-response fenced restart were blocked by the provider's HTTP
429 response: no API credits remained. They produced zero new effects but no
required native tool attempt, so they remain failed/unresolved. The timeout,
remaining evidence substitutions, concurrent-owner, complete budget and new
wheel lifecycle/delivery qualifications are not inferred from r10 results.
The r11 wheel is retained as a pending candidate until those runs can finish.
