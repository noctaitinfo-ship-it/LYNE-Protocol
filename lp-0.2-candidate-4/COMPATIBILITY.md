# LP 0.1 ↔ LP 0.2 compatibility

> **PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1 · `lp02-private-candidate-4`.** Candidate-3's successor: candidate-3
> unchanged + `lp02.liveline/1`, the Live Line WebRTC data-channel profile (MASTER, 2026-10-08). Nothing here is published.

1. LP 0.2 contains LP 0.1 unchanged. Every LP 0.1 operation between any two parties stays LP 0.1 and is **SUPPORTED**.
2. An LP 0.2 operation is used only after negotiation (SPEC §3): through the federation document between providers or
   towards an opener, through the client declaration towards a client endpoint, through `hello` on a Line.
3. Outcome classes (the only three):
   - **SUPPORTED** — the operation is LP 0.1, or both sides support it without negotiation being needed;
   - **NEGOTIATED** — an LP 0.2 module, used because both sides support a common version;
   - **REFUSED** — an LP 0.2 module the other side lacks: an explicit refusal with a code
     (`MODULE_UNSUPPORTED`, `MODULE_NOT_NEGOTIATED`, `VERSION_UNSUPPORTED`, the route absent — 404 `NOT_FOUND` — on an
     LP 0.1 runtime), or **NOT_OFFERED**: the LP 0.1 side has no such operation, and the LP 0.2 side sends it nothing
     (no request, no wake, no line frame).
   There is no fourth class. **SILENTLY DEGRADED** — doing something weaker that looks similar — is a conformance failure.
4. An LP 0.1-only endpoint never receives an LP 0.2 object it cannot recognise: requests are not created for it, line
   frames are not sent to it (not even `hello`: SPEC §7 rule 0), wakes go only to endpoints it registered itself.
   A party without a federation document is an LP 0.1 party (SPEC §3.2, "No document").
5. Newer module versions: a receiver that knows `lp02.X` but not version n refuses with `MODULE_VERSION_UNSUPPORTED`;
   negotiation picks the highest common version before any object is sent.

## Matrix (block 36)

`compat/run-matrix.mjs` RUNS every pair over HTTP — 4 runtimes × 4 clients × 7 operations, and 4 × 4 providers for
federation and referral — and writes `compat/matrix.json`. Parties: runtimes A-0.2 (LYNE runtime), B-0.2
(lp02-independent-peer), A-0.1 (P0 kitchen-table, LP 0.1), B-0.1 (B with `--lp 0.1`); clients A-0.1 (P0 Node client),
B-0.1 (B's client, LP 0.1 operations only), A-0.2 (Personal agent; line capabilities by the client page's
`lp02doc.js`), B-0.2 (B's client).

| Pair | LP 0.1 core | LP 0.2 modules |
|---|---|---|
| LP 0.1 client ↔ LP 0.1 runtime | SUPPORTED | REFUSED (NOT_OFFERED / route absent) |
| LP 0.1 client ↔ LP 0.2 runtime | SUPPORTED | REFUSED (`MODULE_NOT_NEGOTIATED` for a request; NOT_OFFERED otherwise; no wake, no frame) |
| LP 0.2 client ↔ LP 0.1 runtime | SUPPORTED | REFUSED (404 `NOT_FOUND`, `MODULE_UNSUPPORTED` — never imitated) |
| LP 0.2 client ↔ LP 0.2 runtime | SUPPORTED | NEGOTIATED |
| LP 0.2 provider ↔ LP 0.2 provider | — | NEGOTIATED (pin both ways, referral admitted) |
| LP 0.2 provider → LP 0.1 provider | — | REFUSED (`MODULE_UNSUPPORTED`) |
| LP 0.1 provider → any | — | REFUSED (NOT_OFFERED) |

Every A↔B combination is in the matrix (cross-implementation cells are marked). An observation outside the three
classes — an LP 0.2 effect without negotiation, a refusal that changed the State, a wake or frame to a party that did
not ask, an LP 0.1 operation that failed — is `SILENTLY_DEGRADED` or `BROKEN` and fails the run. The runner's
`--self-test` proves it can fail: against B with `--fault imitate-request` (a deliberately non-conforming vendor) the
request cells must come out `SILENTLY_DEGRADED`.

## Nonce matrix (block 51, `lp02.nonce/1`)

`compat/run-nonce-matrix.mjs` runs 4 clients (A and B; LP 0.1 and nonce) x 5 runtimes (A and B; LP 0.1 and LP 0.2; and an
OLDER LP 0.2 runtime without `lp02.nonce`, `B --legacy`) - 65 observations, every one RUN, A and B identical:

| client -> runtime | LP 0.1 core (low-rate) | 50 reads in one second | a nonce without negotiation |
|---|---|---|---|
| LP 0.1 -> LP 0.1 | SUPPORTED | REFUSED (an LP 0.1 client has no nonce) | REFUSED `SIGNATURE_INVALID` (LP 0.1 §6.5) |
| LP 0.1 -> LP 0.2 | SUPPORTED | REFUSED (as above) | REFUSED `MODULE_NOT_NEGOTIATED` |
| nonce -> LP 0.1 | SUPPORTED (LP 0.1 rules) | REFUSED **by the client** `MODULE_NOT_NEGOTIATED` - never downgraded | REFUSED `SIGNATURE_INVALID` |
| nonce -> LP 0.2 with nonce | SUPPORTED | **NEGOTIATED** - 50/50 | REFUSED `MODULE_NOT_NEGOTIATED` (another, unnegotiated binding) |
| nonce -> older LP 0.2 | SUPPORTED; every other module NEGOTIATED | REFUSED by the client | REFUSED `MODULE_NOT_NEGOTIATED` |

Found: the personal agent declared its module wishes blindly; an older LP 0.2 runtime would have refused the whole
declaration and every LP 0.2 module would have disappeared silently. It now reads the runtime's own signed document
first and declares the intersection.

## Candidate-1 ↔ candidate-2 (the predecessor; its vectors `C2N-*` and runner live in the frozen candidate-2)

| pair | outcome |
|---|---|
| candidate-2 ↔ candidate-2 | `lp02.channel` NEGOTIATED (may be required) |
| candidate-2 ↔ candidate-1 | candidate-1's module set exactly; `lp02.channel` absent; required → `MODULE_UNSUPPORTED` (REFUSED) |
| candidate-1 ↔ candidate-2 | the candidate-1 party stays candidate-1 (no silent upgrade); its declarations of `lp02.channel` are `CLIENT_MODULES_INVALID` |
| any ↔ LP 0.1 | `lp` 0.1, no module: Channel semantics never reach an LP 0.1 peer (NOT_OFFERED / REFUSED) |
| no common version / missing `lp02.federation` | absent, never guessed |
| a replayed older document without the module | `FED_DOWNGRADE` |
| a forged document adding the module | `FED_DOC_INVALID` |

Additivity: every candidate-1 vector gives candidate-1's answer under the candidate-2 profile, on A, B and C.

## Candidate-2 ↔ candidate-3 (the predecessor's; its vectors `C3N-*` and runner live in the frozen candidate-3)

| pair | outcome |
|---|---|
| candidate-3 ↔ candidate-3 | `lp02.channel` /2 NEGOTIATED |
| candidate-3 (/2) ↔ candidate-2 (/1) | no common version: the module is ABSENT; required → `MODULE_UNSUPPORTED`. /2 never becomes /1 |
| candidate-2 (/1) ↔ candidate-3 (/2) | the same from the other side: /1 never becomes /2 |
| a peer offering /1 and /2 | the highest common version: 2 |
| a /1 object sent to a candidate-3 runtime | `MODULE_VERSION_UNSUPPORTED` |
| a replayed older document offering only /1 | `FED_DOWNGRADE`; a forged one claiming /2 | `FED_DOC_INVALID` |
| candidate-1, LP 0.1 | as before: no channel module |

## Candidate-3 ↔ candidate-4 (vectors `C4N-*`, `conformance/run_candidate4.py`)

| pair | outcome |
|---|---|
| candidate-4 ↔ candidate-4 | `lp02.liveline` /1 NEGOTIATED (and `lp02.channel` /2): every Line of a Thing whose client declared it follows §20 |
| candidate-4 ↔ candidate-3 | `lp02.liveline` ABSENT: Lines follow LP 0.1 §8.3 alone, no frame is sent, the profile is never imitated; required → `MODULE_UNSUPPORTED` |
| candidate-3 ↔ candidate-4 | unknown to the candidate-3 party: ignored in documents, `CLIENT_MODULES_INVALID` in its declarations; no silent upgrade |
| a peer offering /1 and a future /2 | the highest common version: 1; a peer with /2 only: absent |
| a document listing `lp02.liveline` without `lp02.federation` | the dependency is missing: absent |
| a replayed older document without the profile | `FED_DOWNGRADE`; a forged one adding it: `FED_DOC_INVALID` |
| candidate-1, LP 0.1 | as before: no channel module, no profile |
