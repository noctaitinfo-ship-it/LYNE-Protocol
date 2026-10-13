# LP 0.2 — security considerations

> **PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1 · `lp02-private-candidate-4`.** Candidate-3's successor: candidate-3
> unchanged + `lp02.liveline/1`, the Live Line WebRTC data-channel profile (MASTER, 2026-10-08). Nothing here is published.

LP 0.1 `Threat_model.md` applies unchanged to the core. This file covers what the modules add. Each row names the
conformance vectors or cross-implementation tests that prove the counter-measure.

| Threat | Counter-measure | Proof |
|---|---|---|
| Signature substitution across object kinds | mandatory `typ` in the module JWS header, exact header comparison | vectors `X-typ-*` |
| Changed payload after signing | JCS over the whole object; any member change breaks the signature | vectors `*-tampered*` |
| Non-canonical / ambiguous JSON (duplicate members) | duplicate members refused before parsing into objects | vectors `*-dupkey*` |
| Replay of OPEN, referral, answer, wake | nonce / (iss, nonce) / (created, signature) / `sent_at` memory | vectors `*-replay*` |
| Cross-provider / cross-tenant reuse | `aud` and `point_id` bound into the OPEN; referral `aud` and pinned `iss`; Thing-key requests bound to the target URI | vectors `*-aud*`, `*-cross*` |
| Silent downgrade | signed documents; ratchet by `issued_at`; required modules refused, never imitated; line tools only after hello | vectors `F-*`, compatibility matrix |
| Third party strips modules | it cannot re-sign a document; an older document is `FED_DOWNGRADE` | vector `F-downgrade-replay` |
| Malicious federated peer | quota 50/24 h, single-use, point allow-list, unpin at once | FD6, `R-*` |
| Body swap on a signed request | `content-digest` mandatory for any body with members | vectors `A-digest-*` |
| Remote control without consent | control never pre-allowed; each command confirmed by the receiving person | L6, lines E2E |
| Memory exhaustion on a Line | 16 MiB receive budget, record and file limits, 32 KiB frame limit | L9, vectors `L-*` |
| Autonomous agents 1000× faster | rates per address and point; capacity; per-peer quota; one open request per Thing; coalesced and capped wakes; agent mandate (LAP) | SPEC §4–§8, 35C |
| Revocation races | every check reads current state; the Binding and Grants are re-read per request; exit revokes Grants atomically | 35C race tests |
| Provider key rotation | LP 0.1 has none (a new key is a new Thing); a federation document signed by another key for a pinned origin is refused | vector `F-pin-key` |
| Clock skew | ± 300 s everywhere; vectors at the edges | vectors `*-skew*` |
| Conversation / social-graph reconstruction (c2) | no persistent per-exchange record; deliveries deleted at `exp` + 300 s; resolve authority-scoped | `CH-*` record vectors, history probe, retention proof |
| Endpoint correlation / address recovery / R-1 liveness oracle (c3) | references minted by the runtime, never supplied; no cross-Thing index; every unknown reference or binding gets the one refusal (`ROUTE_NOT_OFFERED` / `BINDING_UNKNOWN`) | `C2-R1-*` vectors, R-1 red team (A/B/C + runtime HTTP, timing) |
| Malicious relay / compromised adapter (c2) | only the recipient's signed receipt delivers; attempts only over offered routes | `CH-*` relay vectors, red team |
| Channel downgrade / version confusion (c3) | negotiation + ratchet; version 2 only; a /1 object `MODULE_VERSION_UNSUPPORTED`; `MODULE_NOT_NEGOTIATED` | `C3N-*`, `C2-offer-v1-object` |

Not addressed (residual): a declared `actor` kind is not a proof of humanity; a bearer link (Grant, referral) can be
used by whoever holds it first within its short window; a person can record a Line by external means (LP 0.1 T19).

## Candidate-4 (§20 `lp02.liveline/1`)

| threat | control | evidence |
|---|---|---|
| silent downgrade of a Line to in-band or partially reliable channels | negotiated before the Line; a negotiated endpoint never falls back (§20.2 rule 5); in-band LYNE labels, other ids, ordering, reliability or protocol end the Line (§20.5, §20.6) | `LL-*` vectors; browser interop I2 (14 configurations × verifiers A and B) |
| reordered or lost Result / `bye` messages | `lyne-control` ordered and fully reliable — partial reliability is refused | `LL-frame-control-max-*`, `LL-frame-control-unordered`; interop I2 |
| DATA without authority | the Grant decides; DATA without it is `CHANNEL_NOT_GRANTED` | `LL-frame-data-without-grant`; interop I2 `data-without-authority` |
| a lying profile frame | wire-observable checks do not rely on it: DCEP detection, `PROFILE_TIMEOUT` (traffic on another stream never reaches stream 0) | interop I2 `lying-frame` |
| negotiation downgrade | §3.2 ratchet and signed documents | `C4N-downgrade-replay`, `C4N-forged-upgrade` |
| asymmetric negotiation | a client whose declaration was accepted does not open a Line it cannot verify (§20.2 rule 6) | product client; SPEC |
