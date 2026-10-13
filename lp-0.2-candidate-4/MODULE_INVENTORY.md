# LP 0.2 module inventory — the private candidate `lp02-private-candidate-4` (candidate-3 + `lp02.liveline/1`)

> **PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1 · `lp02-private-candidate-4`.** Candidate-3's successor: candidate-3
> unchanged + `lp02.liveline/1`, the Live Line WebRTC data-channel profile (MASTER, 2026-10-08). Nothing here is published.
> Block 58A. Every protocol-relevant part of LYNE as of
> 2026-10-03, classified once. LP 0.1 (`03_Protokoll/`) is unchanged and is not part of this candidate's text.

## Classes

| class | meaning | changes how |
|---|---|---|
| **CORE** | LP 0.1 objects and rules, byte-identical to the registered snapshot | never by LP 0.2 |
| **BASE** | `lp02.federation` — required before any LP 0.2 module is used | candidate revision (MASTER) |
| **MODULE** | a negotiated optional module of the candidate: SPEC section, exact objects, vectors, ≥ 2 implementations | candidate revision (MASTER) |
| **EVIDENCE** | a format or a client rule that verifies what exists; no new authority, no negotiation | candidate revision (MASTER) |
| **RUNTIME** | a product feature of the LYNE runtime; interoperates through MODULEs, is not itself protocol | product decision |
| **DEFERRED / REJECTED** | considered in block 33 and not adopted | a new evidence block |

## Inventory

| part | class | SPEC | depends on | implementations | vectors | since |
|---|---|---|---|---|---|---|
| THING, STATE, GRANT, Redemption, Binding, LINE, RESULT | CORE | LP 0.1 | — | A, B (LP 0.1 reference suite) | LP 0.1 suite | LP 0.1 |
| `lp02.federation` | BASE | §3 | — | A, B, C | 29 | 34 |
| `lp02.admission` (+ open-point lifecycle, block 53) | MODULE | §4 | federation | A, B, C | 42 | 34 |
| `lp02.referral` | MODULE | §8 | federation, admission | A, B, C | 16 | 34 |
| `lp02.request` | MODULE | §5 | federation | A, B | 14 | 34 |
| `lp02.wake` | MODULE | §6 | federation | A, B | 24 | 34 |
| `lp02.linecaps` | MODULE | §7 | — (in-band on the Line) | A, B | 46 | 34 |
| `lp02.exit` | MODULE | §9 | federation | A, B | 6 | 34 |
| `lp02.result` | MODULE | §12 | federation, request | A, B, C | 35 | 43 |
| `lp02.delegation` | MODULE | §13 | federation | A, B, C | 46 | 44 |
| `lp02.recovery` | MODULE | §14 | federation | A, B | 41 | 45 |
| `lp02.nonce` (+ `lap-sig/2`, one profile two layers, block 54) | MODULE | §16 | federation | A, B, C | 23 | 50 |
| `lp02.agreement` | MODULE | §17 | federation, request | A, B, C | 49 | 55 |
| `lp02.introduction` | MODULE | §18.2 | federation | A, B | 30 | 56 |
| `lp02.channel` /2 (candidate-3) | MODULE | §19 | federation | A, B, C | 55 | R-1 hardening (2026-10-08) |
| `lp02.liveline` /1 (candidate-4) | MODULE | §20 | federation | A, B, C (+ browser peers A, B) | 77 (+ 17 negotiation) | LP02-B1 WebRTC interop closure (2026-10-08) |
| `lp02.channel` /1 | SUPERSEDED in candidate-3 (kept in the frozen candidate-2) | — | — | A, B, C | — | MASTER 2026-10-08 (R-1) |
| `lyne-result-proof/1` | EVIDENCE | §15 | (result / agreement / LP 0.1 Result) | A, B, C, LYNE-free tool, browser | 42 | 49 |
| trust view (verified apart from claimed) | EVIDENCE | §18.1 | — | A, B | 14 | 56 |
| common rules: strict JSON, JCS, the JWS profile, RFC 9421/9530, times, typed members | BASE | §2, §18 | — | A, B, C | 26 | 34 |
| seats (`lyne-seat/0.1-exp`) | RUNTIME | — (used by §17 roles) | — | A | runtime tests | 28 |
| provider agents, LAP endpoint references, `lap-sig/2` registration | RUNTIME | §16.2a (the signing profile only) | — | A | runtime tests | 23, 54 |
| personal runtime (compartments, points 7/30 days, rotation, DONE retention 30 days) | RUNTIME | §4 expiry rule only | — | A | runtime tests | 46–53 |
| attention, Console, owner access gate, PIN, export `lyne-result-export/1` | RUNTIME | — | — | A | runtime tests | 23–49 |
| C4, C5, D-5, D-6 | DEFERRED | — | — | — | — | 33 |
| C7, D-1, D-2, D-3, D-4 | REJECTED | — | — | — | — | 33 |
| `lp02.thread/1` (an ordered event history) | REJECTED | — | — | — | — | MASTER 2026-10-07 |

Counts are the vectors of `lp02-vectors.json` at the freeze (common = `common` + `common.rfc9421`; trust view = `lp02.trust`).

## What the classification decides

- A MODULE or EVIDENCE part is in the frozen text: changing it is a candidate revision (MASTER decision), recorded in
  `FREEZE.json` and checked by `tests/check_freeze.py`.
- A RUNTIME part may change with the product, but never so that a MODULE's rule changes (the conformance and the
  three-way differential run on every commit).
- Nothing here is published: Q-PUBLIC remains CLOSED; LP 0.1 remains the only public protocol.
