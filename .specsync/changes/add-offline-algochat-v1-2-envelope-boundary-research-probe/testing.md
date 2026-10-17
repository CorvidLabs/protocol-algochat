---
change: add-offline-algochat-v1-2-envelope-boundary-research-probe
artifact: testing
---

# Testing

## Actual evidence

- Before-cap receipt 20261016T052906Z-A1-09bb03: 18 tests, 16 passed, 2 failed, exit 1.
  The upper endpoint exceeded UINT32_MAX at MAX-199 and MAX; setup succeeded.
- Corrected receipt 20261016T053208Z-A1-dba9d2: 21 tests, 21 passed, 0 failed, 0 skipped.
- Probe 20261016T053430Z-A1-d6c674: 34 matched controls; real PSK sender opens
  published plaintext, sender-wrap corruption fails sender but preserves recipient,
  and patterned PSK fails AEAD after counter acceptance/key/tag setup.
- Native verify 20261016T053430Z-A1-ea897c: 5 documents / 6 registry entries. This
  validates registry structure, not runtime operation of six client implementations.
- Strict SpecSync 20261016T053430Z-A1-0d8466: exit 0, 0 specs / 0 source files. This
  does not cover the new scripts. Strict score's existing empty-set failure and
  three pre-existing stale/incomplete change records are preserved honestly.
- Independent review r2 is bound to source 44ea1c8e, tests e5387b58 and final doc
  e835581a. The final document change only corrects the lower/upper range wording.

- Final local receipt `20261016T054350Z-A1-dd53e0`: 21 tests passed after the
  wording correction; native registry validation and strict empty-source check
  passed. The native interview is complete; definition approval remains false.

## Publication gates

Coordinator records final post-wording 21-test, committed-range Trust/risk and
unchanged-policy Attest results separately for the exact candidate commit. Earlier
empty-range Trust did not review untracked files and is not reused as that proof.

## Limits

No Raven/client audit, ledger replay, durable PSK state, transaction signature
binding, PQ execution, fragmentation, rollover policy or human acceptance.
Native registry validation and empty-source SpecSync checks do not establish
those properties. The definition remains an unapproved draft; no prior change
records or policy are edited to obtain green checks.
