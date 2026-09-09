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
