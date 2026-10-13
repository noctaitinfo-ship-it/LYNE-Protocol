# LP 0.2 conformance driver protocol

> **PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1 · `lp02-private-candidate-4`.** Candidate-3's successor: candidate-3
> unchanged + `lp02.liveline/1`, the Live Line WebRTC data-channel profile (MASTER, 2026-10-08). Nothing here is published.

An implementation under test provides a **driver**: a process that reads one JSON object per line on stdin and writes
one JSON object per line on stdout, in order. The runner (`run_conformance.py`) starts the driver, sends every vector,
and compares.

## Request

```json
{ "id": "O-replay", "context": { … }, "steps": [ { "op": "adm.open", "input": { … } }, … ] }
```

The driver creates a **fresh instance** for each vector (no state carries over between vectors), sets it up from
`context`, runs the steps in order against that one instance, and answers:

```json
{ "id": "O-replay", "results": [ { "outcome": "ACCEPT" | "REFUSE" | "IGNORE", "code": "OPEN_REPLAY", "result": { … } } ] }
```

`code` is present on REFUSE. `result` carries the fields an op defines below; the runner compares only the fields the
vector lists in its expectation. A driver that does not implement an op answers `{ "outcome": "UNSUPPORTED" }` for that
step — the runner reports it, it never counts as a pass.

## Clock

`context.now` (unix seconds) is the instance's clock for every step unless the step input carries `now` or `at_ms`.

## Ops

| op | context | input | result on ACCEPT |
|---|---|---|---|
| `json.parse` | — | `{ text }` | — (REFUSE `INVALID_JSON` on malformed or duplicate members) |
| `jws.verify` | — | `{ object, pub, typ }` | — (REFUSE `SIGNATURE_INVALID`) |
| `fed.negotiate` | `now`, `ratchet` (map `origin\|pub` → issued_at) | `{ local, remote, required?, expect_origin?, expect_pub? }` | `{ lp, modules }` |
| `fed.client_modules` | — | `{ body }` | `{ modules }` |
| `adm.descriptor` | `now` | `{ descriptor, expect_pub? }` | — |
| `adm.open` | `now`, `origin`, `point`, `codes`, `peers` | `{ request }` | `{ admitted: true }` |
| `rfc9421.verify` | `now`, `binding` | `{ method, target_uri, headers, body }` | — |
| `req.create` | `now`, `thing` | `{ template }` | `{ next_state }` |
| `req.answer` | `now`, `thing` | `{ request_id, option, by }` | `{ next_state }` |
| `wake.subscribe` | `now`, `thing`, `local` | `{ wake_id, body }` | — |
| `wake.verify` | `registered` | `{ signal }` | — (the last accepted `sent_at` is remembered per `wake_id`) |
| `exit.leave` | `now`, `thing` | `{ kid }` | `{ left, grants, next_state }` |
| `lc.hello_allowed` | — | `{ document (or null: no route), provider_pub }` | — (REFUSE `MODULE_UNSUPPORTED` / `FED_DOC_INVALID` / `FED_DOC_STALE` / `MODULE_VERSION_UNSUPPORTED`) — the client endpoint's decision of SPEC §7.1 rule 0 |
| `lc.manifest` | — | `{ manifest }` | — (REFUSE `MANIFEST_INVALID`) |
| `lc.open` | — | `{ side }` | — |
| `lc.receive` | — | `{ text, at_ms }` | `{ violations, limit }`; REFUSE with the violation code; IGNORE if not a frame of this module |
| `lc.propose` | — | `{ manifest, at_ms }` | — (REFUSE `MODULE_NOT_NEGOTIATED` / `MANIFEST_INVALID`) |
| `lc.settle` | — | `{}` | `{ files, violations, last }` after every pending check (file hashes) completed |
| `ares.verify` | `now`, `thing`, `bindings`, `accepted` | `{ result }` | `{ … }` — an asynchronous Result (SPEC §12) |
| `ares.make` | — | `{ provider (key label), aud, question, answer, epoch, issued_at, result_id }` | `{ signature, outcome }` (identical bytes) |
| `ares.body` | — | `{ question }` | `{ body }` — the concluding body (exact text) |
| `dlg.verify` | `now`, `thing`, `revoked` (`{ ids, kids }`), `uses` | `{ chain, request: { action, channels? } }` | `{ leaf_kid, length }` — a delegation chain (SPEC §13) |
| `dlg.make` | — | `{ signer (key label), fields }` | `{ signature, hash }` (identical bytes) |
| `rcv.key` | — | `{ seed_label }` | `{ pub }` — the recovery key of the test seed SHA-256(`LP02 TEST SEED <label>`) (SPEC §14.1); a vector never carries seed bytes |
| `rcv.grant` | `thing` | `{ grant }` | `{ recovery_id }` — a Recovery Grant (SPEC §14.1) |
| `rcv.move` | `now`, `thing`, `record` | `{ method, target_uri, headers, body, now? }` | `{ action }` — `move` / `pending` / `complete` (SPEC §14.2) |
| `rcv.restart` | — | `{}` | — the instance loses every in-memory state; the record (with each decision's effect applied) stays (block 48) |
| `proof.verify` | — | `{ proof }` | `{ outcome, basis, thing_id, title, provider_kid, client_kid, agreed_at, closed_at, version }` (SPEC §15) |
| `nonce.verify` | `now`, `binding`, `required` | `{ method, target_uri, headers, body, now? }` | `{ kid }`; IGNORE = no nonce and not required (LP 0.1 applies) (SPEC §16) |
| `nonce.restart` | — | `{}` | — in-memory nonces gone; fingerprints of POSTs stay |
| `agr.verify` | `now`, `thing`, `customer` (`{ epoch, client_pub }` or null), `accepted` | `{ result }` | `{ outcome, option, roles }` — a multi-actor Result (SPEC §17) |
| `agr.make` | — | `{ provider (key label), aud, question, option, signers, epoch, issued_at, result_id }` | `{ signature, outcome }` (identical bytes) |
| `agr.body` | — | `{ question, role }` | `{ body }` — what an actor signs (exact text) |
| `intro.verify` | `now`, `thing` (`{ thing_id, aud, provider_pub, client_pub }`) | `{ intro, point?, fetched_from? }` | `{ checked_target, introduced_by, target, purpose, claimed? }` (SPEC §18.2) |
| `intro.make` | — | `{ signer (key label), by, thing_id, aud, target, purpose, issued_at, exp, intro_id }` | `{ signature }` (identical bytes) |
| `trust.view` | `now` | `{ doc, fetched_from, pins }` | `{ verified, claimed }` (SPEC §18.1) |

Block 57: three implementations speak this protocol — A, B and C (`04_Prototuup/lp02-impl-c`, C#); `run_three_way.py`
compares all three on C's scope and A with B everywhere.

### `context.point` (admission)

`{ point_id, label, service, purposes: [{code, label}], admission: { mode, humans, agents, referral, max_pending,
max_open }, grant: { channels, line_max_seconds, lifetime_seconds }, status: "ACTIVE"|"REVOKED", valid_until }`;
`context.codes`: `[{ code, uses_remaining, expires }]` (unix); `context.peers`: pins `[{ origin, provider_pub, points,
modules }]` of the receiving provider.

### `context.thing` (request, wake, exit)

`{ thing_id, state: { version, status, waiting_on, next_action }, binding: { client_kid } | null, declared: { modules } |
null, left: bool, grants: [{ grant_id, status, active_line }], requests: [ <stored request> ], templates: [ <template> ],
wakes: [{ wake_id, thing_id }] }`. A provider State transition proposed while the Thing's version differs from the
expected one is `STATE_CONFLICT`. `next_state` = `{ status, waiting_on, next_action, deadline }` of the transition made.

## Candidate-3

**Profile.** `context.candidate` = `"lp02-private-candidate-3"` selects the candidate-3 profile: `lp02.channel` (version
2) is a client-side module (`fed.client_modules`) and depends on `lp02.federation` (`fed.negotiate`). Absent =
candidate-1. `conformance/run_candidate3.py` sets it on every vector.

### Channel /2 ops (SPEC §19)

**Context.**

```json
{ "now", "negotiated": true|false, "mint_seed": "<string>",
  "bindings": { "<kid>": [ "<binding>", … ] },
  "thing": { "thing_id", "status", "parties": [ { "role", "kid", "pub", "revoked" } ] } }
```

| op | input | result on ACCEPT |
|---|---|---|
| `ch2.offer` | an endpoint offer | `{ "actor", "generation", "routes": [ { "channel", "endpoint_ref" } … ] }` (minted) |
| `ch2.send` | `{ "request", "payload"? }` | `{ "delivery_id", "routes" }` |
| `ch2.attempt` | an attempt | `{ "attempt", "status" }` |
| `ch2.receipt` | a receipt | `{ "delivery_id", "status" }` |
| `ch2.tick` | `{ "now" }`: the clock moves on and retention applies | `{}` |
| `ch2.resolve` | `{ "requester", "target", "delivery_id"? }` | `{ "routes": [ { "channel", "endpoint_ref" } … ] }` (SPEC §19.1, visibility) |
| `ch2.record` | `{}` | the persistent record view (SPEC §19.5): the observer's storage inspection, not an actor API |
| `ch2.sign` | `{ "signer": label, "typ", "object" }`: sign with a test key, for cross-implementation checks | `{ "signature" }` |

## Candidate-4

**Profile.** `context.candidate` = `"lp02-private-candidate-4"` selects the candidate-4 profile: candidate-3's, plus
`lp02.liveline` (version 1) as a client-side module (`fed.client_modules`) depending on `lp02.federation`
(`fed.negotiate`). `conformance/run_candidate4.py` sets it on every vector except negotiation vectors that name another profile.

### Liveline ops (SPEC §20)

| op | input | ACCEPT result | refusals |
|---|---|---|---|
| `ll.make` | `{ grant_data }` | `{ frame }`: the profile frame of a compliant endpoint (SPEC §20.4) | — |
| `ll.local` | `{ grant_data, channels: { "lyne-control": D\|null, "lyne-data": D\|null } }` | `{}` | SPEC §20.5 rules 5–9 |
| `ll.frame` | `{ grant_data, text }` | `{}` | SPEC §20.5 |
| `ll.session` | `{ grant_data, events: [e…] }` | `{ state: "verified" \| "waiting", held_data }` | SPEC §20.6 (the first failure ends the session) |

**`ll.session` events.**

- `{ "e": "ice_connected" }`
- `{ "e": "control_open" }` (the endpoint's own)
- `{ "e": "message", "channel": "lyne-control" | "lyne-data", "text": s }`
- `{ "e": "datachannel", "label": s }`
- `{ "e": "elapsed", "ms": n }`

**How the events are applied.**

- Time starts at 0. `elapsed` advances it; timeouts are checked after every event.
- `held_data` counts the `lyne-data` messages held so far (reset to 0 when they are delivered on verification).
- Events after a failure are not processed.

Vectors: `vectors/liveline-vectors.json`, ids `LL-*`.
