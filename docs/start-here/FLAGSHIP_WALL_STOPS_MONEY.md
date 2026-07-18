# Flagship: the wall stops money (offline verifier proof)

One command walks the whole arc over the signed, deterministic Proof Room bundle:

    bash scripts/demo/flagship-wall-stops-money.sh

It runs `chio proof verify <bundle> --require denials --require commerce --require
settlement --require risk --require trust-market` and then narrates:

1. MANDATE / ALLOWANCE - mandate-commerce-001 (max_amount_minor, max_occurrences).
2. DENIED - a kernel-signed terminal receipt (terminal_status `denied_guard_request`),
   alongside the negative catalog (commerce-payment-before-budget,
   commerce-mandate-occurrence-limit, commerce-expired-mandate,
   commerce-payment-amount-mismatch) that the verifier REJECTS.
3. ALLOWED - a kernel-signed terminal receipt (terminal_status `allowed_executed`),
   authorized via the x402/AP2/ACP verify-only protocol projections.
4. SETTLED - the offline settlement-packet (status `settled`).

## Honesty boundary (non-claims)

This is a verifier-level proof over an OFFLINE projection. The DENIED and ALLOWED
receipts are two independent kernel-signed terminal receipts; they carry no amount
and no mandate reference, so this walkthrough does NOT claim they are two occurrences
of one mandate. Settlement is a verify-only x402/AP2/ACP projection over an offline
PSP (stripe-shaped-offline). No funds are held, no live money-stop is claimed, and no
public availability is asserted. See docs/start-here/PROOF_ROOM_QUICKSTART.md.
