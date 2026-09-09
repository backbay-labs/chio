# Committed Hermes artifact qualification

Status: unaccepted. The wheel from source commit `65671a01c` installed from an
offline wheelhouse into a fresh consumer, and `pip check` passed. The actual
Hermes host used the pinned public upstream source and OpenAI provider.

The useful workflow produced four independently observed resource dispatches,
the expected edited bytes, and four host delivery confirmations. A forbidden
read and write each produced a signed denial with zero resource dispatches.

At the final HTTP response cutpoint, one write committed but its result never
reached Hermes. The launcher returned unresolved, with no acknowledgement.
A new host session using the same authority could not replace that write.
The operator exported, read and explicitly acknowledged the original outcome
without dispatch; a subsequent actual host read recovered the original bytes.
This exercises host restart, not conversation resume, which is disabled in the
current one-shot mode.

The process boundary probe initially omitted the Python framework bootstrap
executable and failed before its positive control. That failure is preserved.
The corrected probe uses the installed launcher's framework rules: both a
Python process and its Python descendant were denied home data, another
profile, an alternate filesystem alias, symlink and hardlink access, shell
execution, Unix sockets and an unrelated TCP listener. Independent listeners
observed zero denied connections and both selected-port positive controls.
These are OS process probes, separate from native host acceptance.

The final host authority, approval, budget, revocation, evidence fault,
cancellation, kernel failure and lifecycle matrices remain open. No skips in
these four host scenarios or the corrected process probe are counted as passes
for any other required gate. Existing legacy opt-in test skips remain unresolved.
