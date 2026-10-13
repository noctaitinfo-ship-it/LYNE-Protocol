# LP 0.2 — the minimal implementable specification

> **PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1 · `lp02-private-candidate-4`.** Candidate-3's successor: candidate-3
> unchanged + `lp02.liveline/1`, the Live Line WebRTC data-channel profile (MASTER, 2026-10-08). Nothing here is published.
> Block 58C, for the frozen candidate `lp02-private-candidate-1`.
> `SPEC.md` remains the only normative text; this page says which parts of it an implementation needs, in what order,
> and what a third implementation written from it alone (C, block 57) had to be told.

## Profiles — read only what your role needs

An implementation MAY implement any subset of modules (SPEC §1). These profiles are the smallest useful subsets; each
is proven implementable from the text alone by implementation C (C#, base library only), which passes every vector of
the sections listed and agrees with A and B on all of them.

| profile | role | read | vectors | proven by |
|---|---|---|---|---|
| **V — verifier** | checks evidence offline: a Result proof, a multi-actor Result | LP 0.1 §2 (JWS, JCS), SPEC §2.1–2.2, §12.3, §15, §17.3 | `PF-*`, `AR-*`, `AG-*` | A, B, C, LYNE-free tool, browser |
| **F — federating provider** | publishes a document and points, admits | V + §2.3, §3, §4 (+ §8 to accept referrals) | `F-*`, `CM-*`, `D-*`, `O-*`, `R-*` | A, B, C |
| **K — client endpoint** | a person's device / agent bound to a Thing | §2.3, §3.3, §5 (+ §12.1–12.2 to conclude, §16 for many requests per second, §18 to receive introductions) | `H-*`, `Q-*`, `NC-*`, `IN-*`, `TV-*` | A, B (C: §2.3, §16) |
| **D — delegating holder** | narrows its authority to an agent | §13 | `AD-*` | A, B, C |
| **M — multi-actor** | runs an agreement with seats / several parties | §17 (+ V) | `AG-*`, `PF-agreement*` | A, B, C |
| **T — transport carrier** (candidate-3, /2) | offers its routes, carries and confirms deliveries; keeps no history | §1.1, §3, §19 | `C2-*`, `C3N-*` | A, B, C |

Everything a profile does not read it MUST NOT imitate (SPEC §3.2): an absent module is refused, never approximated.

## Rules that hold everywhere (the short list an implementer gets wrong first)

1. Exact member sets at every level; unknown members refused; forbidden names refused at any depth (§2.1).
2. A pattern is tested only on a string; a time is the pattern AND a real calendar time (§17.3 rule 1, §18).
3. A label's length is counted in UTF-16 code units (§12.1).
4. Signatures: the header is compared to the exact expected one, the payload is rebuilt from the received object
   (§2.2); `typ` separates every domain.
5. First failure wins, in the order each section gives — the order is part of the protocol (§3.2, §3.3, §4.1, §4.2,
   §8.3, §12.3, §13.3, §15.2, §16.2, §17.3, §18).
6. Nothing a person wrote is evidence; nothing names a person (§2.1 rule 6, §18).

## What a from-the-spec implementation had to be told (all now in SPEC.md)

| defect | found by | fixed in |
|---|---|---|
| §1 module table and §3.3 client modules stopped at block 45 | C (57) | §1, §2.2, §3.3 |
| §3.3: order of members vs version | C (57, three-way fuzz) | §3.3 |
| §4.1: the descriptor's refusal order | C (57) | §4.1 |
| §12.1: label length unit (B counted code points) | C (57) | §12.1, B |
| §17.2: a CLOSED Thing keeps no seats | state model (57B) | §17.2 |
| `MANIFEST_INVALID` used but not registered | architecture check (58E) | §10 |
| DRIVER.md op table out of date | C (57) | tests/DRIVER.md |
| RegExp coercion (`['x']` passed as `'x'`) | red team (55) | §17.3, all verifiers |
| an impossible date (`2026-02-30`) normalised or crashing | red team (56) | §18, all verifiers |

## Implementation-defined (not protocol — an implementation chooses, and says so)

Rate limits and their codes (`RATE_LIMITED`, `BUSY`); storage bounds; retention (the reference: DONE 30 days); the
open-point expiry policy within the protocol's finite rule (reference: person 7 / 30 days, provider 90 / 365);
seats, agents and access gates (RUNTIME, see MODULE_INVENTORY.md).

## Candidate-2 (`lp02-private-candidate-2`, the predecessor)

- Everything above holds unchanged; profile **T** is new.
- An implementation of T must keep only the current offer per actor and Thing, delete deliveries at `exp` + 300 s
  (or at Thing closure), store no payload and no digest beyond that, and let only the owner (or the sender of an OPEN
  delivery to it) resolve an offer (§19.1).
- Profile switch: the conformance context member `candidate` (conformance/DRIVER.md); absent = candidate-1.

## Candidate-3 (`lp02-private-candidate-3`, the predecessor)

- Profile **T** follows §19 `/2`: an actor offers adapter **bindings**; the runtime mints every Endpoint reference
  (16 CSPRNG bytes), keeps no index of references across Things, and answers an unknown reference with the one
  refusal any string gets (`ROUTE_NOT_OFFERED` as a route, `BINDING_UNKNOWN` as a binding).
- Profile switch: `context.candidate` = `"lp02-private-candidate-3"`.

## Candidate-4 (`lp02-private-candidate-4`)

- Candidate-3 unchanged, plus **`lp02.liveline` /1** (§20): an implementation that runs Live Lines and
  negotiates it creates `lyne-control` (negotiated, id 0, ordered, fully reliable, protocol "") and — only with DATA in
  the Grant — `lyne-data` (the same, id 1), self-checks them, sends the profile frame first and verifies the peer's.
  An implementation without Live Lines (e.g. C, a protocol-object implementation) implements the verification ops.
- Profile switch: `context.candidate` = `"lp02-private-candidate-4"`.
