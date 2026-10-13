# LP 0.2 modules — exact objects and lifecycles

> **PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1 · `lp02-private-candidate-4`.** Candidate-3's successor: candidate-3
> unchanged + `lp02.liveline/1`, the Live Line WebRTC data-channel profile (MASTER, 2026-10-08). Nothing here is published.
> Companion to `SPEC.md`; where they differ, `SPEC.md` wins and
> the difference is a defect.

Per module: identifier, version, wire, canonicalization, signing, verification, authority, lifecycle, expiry, replay,
refusals, privacy, fields, unknown fields, compatibility, downgrade. "JCS+JWS(typ)" means SPEC §2.2.

## lp02.federation / 1

| Aspect | Rule |
|---|---|
| Wire | federation document (SPEC §3.1); client declaration request (§3.3) |
| Canonicalization / signing | JCS + JWS `typ lp02.federation` by the tenant's provider key |
| Verification | SPEC §3.2 steps 1–4 |
| Authority | none — a document describes, it grants nothing |
| Lifecycle / expiry | valid until `expires_at` (≤ 24 h); re-fetched or re-pinned after |
| Replay | an older document of the same (origin, key) is `FED_DOWNGRADE` (ratchet) |
| Unknown fields | refused (`FED_DOC_INVALID`); unknown *module ids* inside `modules` are ignored |
| Compatibility | `lp` lists LP versions; `"0.1"` alone ⇒ no modules |
| Downgrade | only by the peer's own newer signed document; never by a third party |

## lp02.admission / 1

| Aspect | Rule |
|---|---|
| Wire | point view, descriptor (`typ lp02.descriptor`), OPEN request (`typ lp02.open`) — SPEC §4 |
| Signing | OPEN: a one-time opener key generated for this request and then discarded |
| Verification | SPEC §4.2, 13 ordered steps |
| Authority | admission policy of the point; result: a Thing + one Grant for the opener only |
| Lifecycle | admitted → Grant redeemed within 120 s, else withdrawn and the Thing closed |
| Expiry | OPEN `created` ± 300 s; descriptor `valid_until` ≤ 1 h; admission codes per point (default 7 days), referral codes 24 h |
| Replay | nonce remembered 600 s; codes single-use (or `uses`), consumed atomically before the Thing is made |
| Refusals | `OPEN_POINT_UNKNOWN` for unknown, revoked and expired alike; a refusal writes nothing |
| Privacy | no free text; admission record = point, purpose, actor kind, time, Grant id |
| Fields | OPEN: v, aud, point_id, purpose, actor, opener_pub, nonce, created, [admit], [fed_referral], signature |

## lp02.request / 1

| Aspect | Rule |
|---|---|
| Wire | request view (signed GET), answer (signed POST, option in the path) — SPEC §5 |
| Signing | the answer is an RFC 9421 signature by the Thing-key; the State it causes is LP 0.1, provider-signed |
| Authority | only the side waited on; only a declared option; the client only after declaring `lp02.request` |
| Lifecycle | OPEN → ANSWERED / EXPIRED (deadline) / CLOSED (`STATE_MOVED`, `CLIENT_LEFT`) |
| Expiry | `deadline` with a consequence declared up front (escalate / close / choose) |
| Replay | §2.3 (f); a second answer is `REQUEST_DECIDED`; races: exactly one decides |
| Privacy | templates are the owner's words; no free text; only open + latest decided request kept |
| Downgrade | a client without `lp02.request` is never asked (`MODULE_NOT_NEGOTIATED`) — no imitation by a bare WAITING State |

## lp02.wake / 1

| Aspect | Rule |
|---|---|
| Wire | subscription (signed POST with content-digest), signal (`typ lp02.wake`) — SPEC §6 |
| Authority | none: a signal only says "look"; the receiver reads the State itself |
| Lifecycle | subscription until removed, the client leaves, or the Thing closes (one last signal) |
| Expiry / replay | receiver refuses a signal with `sent_at` older than the last accepted one (`WAKE_REPLAY`) |
| Bounds | 2 subscriptions per Thing; ≥ 30 s between signals; ≤ `max_per_day` (1–100, default 24) |
| Privacy | no thing id, no State, no text; one URL path per Thing chosen by the client |

## lp02.linecaps / 1

| Aspect | Rule |
|---|---|
| Wire | `lyne-data` frames tagged `"lyne": "lp02.linecaps/1"` — SPEC §7 |
| Negotiation | the provider's signed federation document lists the module (SPEC §7 rule 0) ⇒ the client says `hello` first; no hello ⇒ refused for this Line |
| Authority | the manifest the provider declared **and** the client accepted for this Line; receiver-enforced |
| Lifecycle / expiry | manifest `expires_s` 10–3600; everything ends with the Line |
| Replay | file ids unique per Line; command ids unique; a result for an unknown id is a violation (late results after the 60 s timeout are ignored) |
| Privacy | peer to peer (DTLS); nothing reaches a server; buffers zeroed at the end |

Cap members (exact):

| kind | members |
|---|---|
| struct | kind, code, label, from, fields (1–12: {code, label, type: number{min,max,unit?} \| enum{values 2–12} \| bool \| text{max_chars 1–280}}), max_records 1–100 |
| file | kind, code, label, from, types (1–8 MIME), max_bytes 1–8 388 608, max_files 1–10 |
| stream | kind, code, label, from, unit, min, max, max_hz (0, 50] |
| control | kind, code, label, from (provider \| client), commands (1–12: {code, label, params: fields without text}) |

## lp02.referral / 1

| Aspect | Rule |
|---|---|
| Wire | referral (`typ lp02.referral`) in the link fragment; pins from federation documents — SPEC §8 |
| Authority | admission at one listed point of the receiving provider, once |
| Expiry | `exp` ≤ issue + 3600 |
| Replay | (iss, nonce) single-use, remembered ≥ 24 h in durable storage |
| Bounds | 50 admissions per peer per 24 h |
| Privacy | names no customer, case or customer key; the receiving side makes a new Thing-key |

## lp02.exit / 1

| Aspect | Rule |
|---|---|
| Wire | `POST /t/<thing>/leave` (signed, no body); attention view — SPEC §9 |
| Authority | only the bound key; reduces authority only |
| Lifecycle | departure until the client's own next Redemption |
| Replay | idempotent (a second leave returns the first `left_at`) |
| Privacy | the provider learns only that the customer left; the client device forgets the case |

## lp02.agreement / 1

| Aspect | Rule |
|---|---|
| Wire | agreement question (§12 question + `policy`), actor signature (RFC 9421 POST, digest, no nonce), Result (`typ lp02.agreement`) — SPEC §17 |
| Authority | the policy fixed before anyone signs; customer = bound key; seats = their role; provider counted once; a delegate never signs |
| Lifecycle | OPEN → DECIDED (first option meeting the policy, atomically with CLOSED); one per Thing |
| Expiry | `deadline` (± 300 s skew); a signature counts only while the signer's authority holds |
| Replay | one entry per key; a second signature `AGREEMENT_SIGNED`; after the decision `REQUEST_DECIDED` |
| Privacy | no names, no text: roles, keys, the question and the option; the actors see only which roles signed |
| Unknown fields | refused (`AGREEMENT_INVALID`), in the policy and every signer entry too |

## lp02.introduction / 1

| Aspect | Rule |
|---|---|
| Wire | introduction (`typ lp02.introduction`), read by the bound client with a signed GET — SPEC §18.2 |
| Signing | one party of the Thing (provider or bound client) — never an agent, never a third party |
| Verification | on the person's device, with the key of its own Thing; the fetched target checked (origin, point, key) |
| Authority | none — evidence for the person; the target's admission policy decides |
| Lifecycle / expiry | ≤ 7 days; at most 3 live per Thing |
| Privacy | no name, no text, nothing of the introducing relationship reaches the target |
| Unknown fields | refused (`INTRO_INVALID`), in the target too |

## lp02.channel / 2 (candidate-3; replaces candidate-2's /1)

| Aspect | Rule |
|---|---|
| Wire | endpoint offer by adapter **bindings** (`typ lp02.endpoint-offer`, v `lp02.channel/2`) → minted references; delivery request (`typ lp02.delivery`), attempt (router), receipt (`typ lp02.delivery-receipt`), resolve — SPEC §19 |
| Canonicalization / signing | JCS + JWS(typ) by the actor's key in the Thing (§2.2); the attempt is the router's record, unsigned |
| Verification | first failure wins, in §19.1 / §19.2 / §19.3 / §19.4 order |
| Authority | the Thing's parties only (provider, bound customer, active seats); a revoked key does nothing (`KEY_REVOKED`) |
| Lifecycle | offer: current only, replaced as a whole; delivery: request → attempts (one current) → receipt by the recipient only |
| Expiry | offer ≤ 30 days (protocol maximum; a runtime's default is shorter — the reference uses 24 h); delivery `exp` ≤ 600 s after `created`, deleted at `exp` + 300 s |
| Replay | the same request again = IGNORE; another request under the same `delivery_id` = `DELIVERY_REPLAY`; a receipt twice = IGNORE |
| Refusals | §10 (channel rows) |
| Privacy | references minted by the runtime per Thing, actor and generation (rotation by construction), never addresses (`ENDPOINT_EXPOSED` for an address-like binding); **no index across Things, no answer about a reference elsewhere** (`ROUTE_NOT_OFFERED` / `BINDING_UNKNOWN` for every unknown string); resolve only by the owner or the sender of an open delivery (`OFFER_NOT_VISIBLE`); no history, no per-exchange audit |
| Unknown fields | refused (`OFFER_INVALID`, `DELIVERY_INVALID`, `RECEIPT_INVALID`); a route/history member in a request refused |
| Compatibility | client-side; depends on `lp02.federation`; version 2 only — a candidate-2 party (/1) shares no version (absent); a /1 object is `MODULE_VERSION_UNSUPPORTED`; unknown to candidate-1 |
| Downgrade | only by the peer's own newer signed document; a replayed older one is `FED_DOWNGRADE` (vector `C3N-downgrade-replay`) |

## lp02.liveline / 1 (candidate-4)

| | |
|---|---|
| Purpose | the interoperable creation of a Live Line's data channels (LP02-B1): LP 0.1 §8.3 names the labels; this module fixes negotiated / stream id / ordered / reliability / protocol |
| Wire | the profile frame `{ lyne: "lp02.liveline/1", t: "profile", channels: { "lyne-control": D, "lyne-data": D \| null } }`, first on `lyne-control` — SPEC §20.4 |
| Profile | `lyne-control`: negotiated, id 0, ordered, `maxRetransmits` / `maxPacketLifeTime` null, protocol `""`; `lyne-data`: the same with id 1, only with DATA in the Grant |
| Authority | creating a channel grants nothing; the Grant (LP 0.1 §8.2) decides; DATA without it is `CHANNEL_NOT_GRANTED` |
| Failure | explicit, never a silent fallback: `LINE_PROFILE_INVALID`, `LINE_PROFILE_MISMATCH` (in-band channel, other ids, ordering, reliability, protocol, no frame in time), `CHANNEL_NOT_GRANTED` |
| Privacy | the frame carries six channel parameters per channel, no identifier or content; transient Line traffic, never stored |
| Compatibility | client-side; depends on `lp02.federation`; unknown to candidates 1–3 (absent; refused in their declarations); a frame `lp02.liveline/2` is `MODULE_VERSION_UNSUPPORTED` |
| IANA | none: `lyne-control` / `lyne-data` are data-channel labels; the DCEP `protocol` field stays empty |
