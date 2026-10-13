# LP 0.2 — privacy

> **PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1 · `lp02-private-candidate-4`.** Candidate-3's successor: candidate-3
> unchanged + `lp02.liveline/1`, the Live Line WebRTC data-channel profile (MASTER, 2026-10-08). Nothing here is published.

LP 0.2 must not recreate an address, a phone number, an inbox, a message, a chat history or a global identity. For every
module: what is held, by whom, for how long (terms of LP 0.1 §2.5).

| Module | Data | Holder | Persistence |
|---|---|---|---|
| federation | the tenant's document (no person) | anyone who fetches it | not held by LYNE beyond the pin |
| federation | client declaration (module ids, kid) | provider | retained until the Binding changes or the Thing closes |
| admission | admission record: point, purpose, actor kind, time, Grant id | provider | retained until the relationship closes |
| admission | OPEN nonce | provider | transient (600 s) |
| request | open + latest decided request incl. the answer evidence | provider | retained until the next decision; none after CLOSED |
| wake | subscription (URL chosen by the client, per Thing), send times of the last 24 h | provider | retained until removed / exit / close |
| wake | signal | client endpoint | transient |
| linecaps | all Line content | both endpoints | transient (the Line), zeroed at its end |
| referral | pins (peer origin, key, points) | provider | persistent, removable |
| referral | used referral hashes and per-peer counters | receiving provider | retained ≥ 24 h, then deleted |
| exit | departure (thing, time, kid) | provider | retained until the client's next Redemption |
| channel (c3, /2) | current endpoint offer per actor (channel classes, runtime-minted references, expiry; never a binding) | the Thing's provider runtime | until replaced, expired (≤ 30 d; reference default 24 h), revoked, or the Thing closes |
| channel (c3, /2) | delivery request, digest, current attempt, receipt flag | the routing runtime | memory only; deleted at `exp` + 300 s or at closure |
| channel (c3, /2) | the real address, and the binding linking it to a reference | the transport adapter only | never in any LYNE object |

Properties checked by tests: no module object has a member that names a person, an address, a device or the network
address of a party; the referral names neither the customer nor the case; a wake carries no thing id; one wake URL path
per Thing; the opener key is single-use; a Line leaves nothing on any server.

"Did we recreate an address?" — No module has a value that lets a party reach a person outside a relationship the person
entered: Open Points are service contexts of organisations; a wake URL is the client's own, per Thing, removable; a
referral is single-use and short-lived and opens nothing without the person following it.

Candidate-2 (§19): no thread, inbox, message history, address book or social graph; after retention a Thing that
carried exchanges is indistinguishable from one that carried none (the retention proof); an offer is visible only to its
owner or to the sender of an open delivery to it; a reference is refused in a second Thing or tenant.

Candidate-3 (§19 /2): Endpoint references are minted by the runtime per Thing, actor and generation; no index of
references across Things or tenants exists, so no answer can reveal whether a reference is live elsewhere (R-1). The same
real address in two Things gets two unrelated references.

Candidate-4 (§20 `lp02.liveline/1`): the profile frame carries six channel parameters per channel — no identifier,
address or content. It is transient Line traffic (LP 0.1 §8.5): never persisted, logged or audited. Labels are not
identities. Nothing new is stored by any party.
