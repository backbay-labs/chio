# Forced trusted-gateway crash

The actual host requested a write. The test-only injector fsynced a cutpoint record and killed the trusted gateway process with SIGKILL after the completed result was durably retained and before the host received its HTTP response. Independent readonly resource/audit observations found exactly one original write and no acknowledged host delivery.

The operator recovered only the stale dead-owner lock. A restart using the original configuration remained fenced and caused no replacement effect. The operator exported, read and acknowledged the exact retained result without dispatch. A subsequent actual-host read succeeded, with unchanged file bytes and exactly one additional read dispatch. No replacement authority or cleared journal was used.

The crash itself cannot produce a successful launcher terminal report. Raw exit/status records remain distinct from the later recovered read. These cases do not close the complete I04/I07/I08 matrix or constitute publication acceptance.

Hermes keeps the HTTP gateway in a private Node child. That child was killed; the Python launcher remained alive long enough to report unresolved status with zero confirmed deliveries.
