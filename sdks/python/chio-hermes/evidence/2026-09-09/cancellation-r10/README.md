# Hermes operator cancellation repair

The actual r9 launcher died on SIGTERM after a committed write without writing
a terminal record. Its before-r9 evidence is preserved, including the failed
qualification and original unacknowledged effect. The new r10 wheel handles
operator SIGTERM/SIGINT, forwards cancellation to a separate native-host process
group, force-stops remaining descendants if necessary, and records uncertainty
before closing its private transport. A real-process component test verifies
cancellation also reaps a descendant when the group leader exits first.

The cold-installed wheel's actual Hermes/OpenAI/kernel cancellation case records
operatorInterrupt=SIGTERM and outcome=unresolved, with one original write and
no acknowledgement. A replacement write stays fenced. Explicit recovery reads
the original result and acknowledges it, then a later native read succeeds
without another write. Legacy scenario label host-response-loss is retained;
the injector's raw record identifies actual operator cancellation.

This wheel separately passed useful work, both denials, response loss and
recovery, private-gateway SIGKILL, aggregate budget and all seven approval stages.
Its own 14-case authority/fault matrix covers two live revocations, three kernel
transport failures, three original-authority fenced restarts and six explicit
startup refusals. No prior r9 test is substituted for this wheel's result.
The component suite has 236 passes and four unresolved legacy opt-in skips.
SIGKILL of the Python launcher and remaining lifecycle cutpoints are not closed.
