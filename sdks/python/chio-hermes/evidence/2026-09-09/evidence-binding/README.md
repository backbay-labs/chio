# Actual native host evidence binding

Each initial run makes two legitimate writes through the real kernel. The first
result is verified and acknowledged. The test transport alters the second
response after that authorized effect, using one of three mutations:

- Substitute the first call's intact, valid signed receipt into the second
  call's evidence. The signature is not modified; it binds a different request.
- Change the second receipt's claimed signing key.
- Replace the second envelope's request ID with the first call's ID.

The intended second native call and its return are required. All three altered
responses yield unverified unknown outcomes and no second delivery acknowledgement.
The independent resource observer correctly sees two authorized writes. These
are evidence-integrity tests, not claims that after-effect verification prevented
the original authorized effects. The retained first receipt and fault record
identify the signed foreign receipt used in the negative control.

Three subsequent native sessions retain each original configuration and journal.
Replacement writes remain fenced, with zero new dispatches and the original
unknown records unchanged. These runs do not recover an unknown outcome by
silently creating new authority. Full I01-I08 acceptance remains open.
