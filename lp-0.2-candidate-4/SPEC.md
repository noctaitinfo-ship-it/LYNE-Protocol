# LYNE Protocol 0.2 — private protocol candidate-4 (`lp02-private-candidate-4`)

> **PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1 · CANDIDATE-4.** Candidate-4 (MASTER, 2026-10-08) = candidate-3
> unchanged (candidate-1 r1 + `lp02.channel/2`) + `lp02.liveline/1`, the Live Line WebRTC data-channel profile (§1, §10, §11, §20). Candidate-1: owner decision 2026-10-02 (MASTER): adopt the seven KEEP
> modules into a private LP 0.2 candidate. Nothing here is published. LP 0.1 (`03_Protokoll/PROTOCOL.md`) is unchanged
> and byte-identical to its registered snapshot. This area lives outside `03_Protokoll/` because the LP 0.1 snapshot
> check hashes that whole tree.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Every rule that can be checked by a machine is
checked by the conformance suite in `tests/` against the vectors in `vectors/`; a sentence of this document that no
vector exercises is a defect of this document.

## 1. Shape

**LP 0.2 = the LP 0.1 core, unchanged, + negotiated optional modules.**

- The core objects THING, STATE, GRANT, Redemption, Binding, LINE and RESULT are exactly those of LP 0.1, with
  `"lp_version": "0.1"`. LP 0.2 adds no member to them and changes no rule of them.
- A **module** adds objects or requests *next to* the core. A module is used only after both parties know the other
  supports it (§3). An implementation MAY implement any subset of modules.

| Module id | Version | Objects / requests | Depends on |
|---|---|---|---|
| `lp02.federation` | 1 | Federation document; negotiation; client module declaration | — |
| `lp02.admission` | 1 | Open Point view, discovery descriptor, OPEN request | `lp02.federation` |
| `lp02.request` | 1 | Request view, answer request | `lp02.federation` |
| `lp02.wake` | 1 | Wake subscription request, wake signal | `lp02.federation` |
| `lp02.linecaps` | 1 | Line frames: hello, manifest, accept, data frames | — (negotiated in-band on the Line) |
| `lp02.referral` | 1 | Pinned peer, federated referral | `lp02.federation`, `lp02.admission` |
| `lp02.exit` | 1 | Exit request, attention view | `lp02.federation` |
| `lp02.result` | 1 | Concluding question, concluding answer, async Result (§12) | `lp02.federation`, `lp02.request` |
| `lp02.delegation` | 1 | Root and child delegations, chain verification, revocation (§13) | `lp02.federation` |
| `lp02.recovery` | 1 | Recovery Grant, moving a relationship to a new device (§14) | `lp02.federation` |
| `lp02.nonce` | 1 | Nonce request-signing profile (§16) | `lp02.federation` |
| `lp02.agreement` | 1 | Agreement question, actor signatures, multi-actor Result (§17) | `lp02.federation`, `lp02.request` |
| `lp02.introduction` | 1 | Introduction by context (§18.2) | `lp02.federation` |
| `lp02.channel` | 2 | Endpoint offer by adapter bindings, runtime-minted references, delivery request, attempt, receipt, resolve — transport without history and without a cross-Thing oracle (§19; candidate-3) | `lp02.federation` |
| `lp02.liveline` | 1 | Live Line WebRTC data-channel profile: creation parameters of `lyne-control` / `lyne-data`, profile frame, verification, explicit failure (§20; candidate-4) | `lp02.federation` |

Client-side modules (a client endpoint declares them, §3.3): `lp02.request`, `lp02.wake`, `lp02.linecaps`, `lp02.exit`,
`lp02.result`, `lp02.delegation`, `lp02.recovery`, `lp02.nonce`, `lp02.agreement`, `lp02.introduction`, and (candidate-3, version 2)
`lp02.channel`, and (candidate-4) `lp02.liveline`. Provider-only:
`lp02.federation`, `lp02.admission`, `lp02.referral`. (Block 57: implementation C, written from this document, found
this table and §3.3 behind the modules of blocks 50–56.)

A **module version string** is `<module id>/<version>`, e.g. `lp02.admission/1`. Versions are positive integers.

### 1.1 Terms (candidate-4)

| term | meaning | persists? |
|---|---|---|
| THING | the context of a relationship | yes (LP 0.1) |
| STATE + RESULT | the persistent record: what is true now, and the agreed outcome | yes (LP 0.1) |
| GRANT | authority | LP 0.1 rules |
| LINE | a bounded live interaction; under candidate-4 its data channels follow §20 when `lp02.liveline` is negotiated (labels are labels — not subprotocols, identities, authority or addresses) | no (its content never) |
| CHANNEL | a transport **class** (`email`, `voice`, `agent`, …) — a name, not an object | — |
| ROUTE | the transport selection for ONE attempt | no |
| ENDPOINT | an opaque, Thing-scoped transport reference **minted by the runtime** for an actor's offer (never an address, never chosen by an actor, never answerable outside its Thing) | current offer only (§19.1) |
| DELIVERY | a bounded, ephemeral transport operation | no: deleted at `exp` + 300 s (§19.5) |

There is **no Thread, conversation, message history, inbox or address book** in any candidate: a persistent ordered
record of exchanges is not a protocol primitive (`lp02.thread/1` was rejected, MASTER 2026-10-07).

**Candidate profiles.** A party works under exactly one candidate. Under candidate-1, `lp02.channel` is an unknown
module: ignored in documents (§3.2 rule 6), refused in a client declaration (§3.3). Under candidate-2 it is a
client-side module, version 1. Under candidate-3 it is a client-side module, **version 2 only**, depending on
`lp02.federation`; a candidate-2 party and a candidate-3 party share no version of it, so it is absent between them.
Under candidate-4, `lp02.liveline` (version 1) is a client-side module depending on `lp02.federation`; it is unknown
to candidates 1–3 (absent between a candidate-4 and an earlier party, refused in their declarations), and a
candidate-4 party never imitates it towards them. A module is used only when negotiation (§3.2) or the client
declaration (§3.3) gives a common version: no silent upgrade, no silent downgrade (`FED_DOWNGRADE`), never imitated.

## 2. Common rules

### 2.1 JSON text

1. JSON text is UTF-8 (RFC 8259). A receiver MUST refuse JSON text that contains a **duplicate member name** at any
   depth (I-JSON, RFC 7493 §2.3). Code: the receiving endpoint's malformed-input code (`INVALID_JSON` for an HTTP body;
   `CAP_MALFORMED` for a Line frame).
2. In every **signed** LP 0.2 object, numbers MUST be integers (as LP 0.1 §2.2). A non-integer number in a signed
   object makes the object malformed (the module's `*_INVALID` code).
3. Identifiers are 16 random bytes, b64u (22 characters). Public keys are raw Ed25519, b64u (43). Times are RFC 3339 UTC
   with `Z` and whole seconds, unless a field says *unix seconds* (an integer).
4. **Unknown members.** Every LP 0.2 object has an **exact member set**. A member that is not listed for the object is
   refused with the module's `*_INVALID` code. (Forward compatibility is by version, never by tolerated members.)
5. **Member names** are ASCII (LP 0.1 §2.2), so that JCS key order is the same in every language.
6. **Forbidden member names.** A member whose name could carry a person's words or a credential — `message`,
   `messages`, `text`, `body`, `note`, `comment`, `prompt`, `reasoning`, `transcript`, `conversation`, `history`, `chat`,
   `token`, `secret`, `password`, `api_key`, `credential` — is refused at any depth with the module's `*_INVALID` code,
   except where this document names it explicitly (the Line frame `struct` value fields of kind `text`).

### 2.2 Canonical form and signatures

1. Canonical form: JCS (RFC 8785) over the LP value subset (strings, integers, booleans, null, arrays, objects).
2. **Module JWS profile.** A signed LP 0.2 object carries `signature` = detached JWS (RFC 7515 App. F) with protected
   header **exactly** `{"alg":"EdDSA","kid":<kid of the signing key>,"typ":<the object's typ>}` serialized with JCS,
   payload = JCS of the object without `signature`, value `b64u(header) || ".." || b64u(Ed25519 signature)`.
3. `kid` = JWK Thumbprint (RFC 7638, SHA-256) of `{"crv":"Ed25519","kty":"OKP","x":<pub>}`, b64u.
4. A verifier MUST reconstruct the payload from the received object, MUST compare the header to the exact expected
   header (expected key, expected `typ`), and MUST refuse any other header. The `typ` values:

| typ | Object | Signed by |
|---|---|---|
| `lp02.federation` | Federation document | provider key |
| `lp02.descriptor` | Discovery descriptor | provider key |
| `lp02.open` | OPEN request | one-time opener key |
| `lp02.wake` | Wake signal | provider key of the Thing |
| `lp02.referral` | Federated referral | issuing provider key |
| `lp02.result` | Async Result (§12) | provider key of the Thing |
| `lp02.delegation` | Delegation (§13) | root: provider key; child: the parent's subject key |
| `lp02.recovery` | Recovery Grant (§14) | provider key of the Thing |
| `lp02.agreement` | Multi-actor Result (§17) | provider key of the Thing |
| `lp02.introduction` | Introduction (§18.2) | the introducing party's key in the Thing |

   `typ` separates domains: a signature made for one typ never verifies as another (vector `X-typ-*`).
5. LP 0.1 core objects keep the LP 0.1 header `{"alg","kid"}` (no `typ`); LP 0.2 never re-signs a core object.

### 2.3 Requests signed with a Thing-key (RFC 9421 profile)

A module request from the bound client endpoint of a Thing is an HTTP request to `<aud>/t/<thing_id>/…`, signed as
LP 0.1 §6.5 with these exact rules:

1. Without a body: `Signature-Input: sig1=("@method" "@target-uri");created=<unix>;keyid="<kid>";alg="ed25519"`.
2. With a body (a JSON object): `Signature-Input: sig1=("@method" "@target-uri" "content-digest");created=…;keyid=…;alg="ed25519"`
   and `Content-Digest: sha-256=:<base64 of SHA-256 of the exact body bytes>:` (RFC 9530) — exactly this one value, no
   other algorithm, no whitespace; any other form does not match (`DIGEST_MISMATCH`).
3. Signature base: one line per component, `"@method": <METHOD>`, `"@target-uri": <aud><path>` (no query),
   `"content-digest": <header value>` when covered, then `"@signature-params": <the parenthesised list and parameters>`,
   joined by `\n`. `Signature: sig1=:<base64 of the 64-byte Ed25519 signature>:`.
4. Verification order, first failure wins: (a) the Thing exists — else `THING_UNKNOWN` (404); (b) a Binding exists —
   else `KEY_MISMATCH` (403); (c) both headers parse exactly as above — else `SIGNATURE_INVALID` (401); (d) `keyid`
   equals the bound kid — else `KEY_MISMATCH` (403); (e) `created` ∈ [now − 300, now + 300] — else
   `SIGNATURE_INVALID` (401); (f) the pair (`created`, signature) was not seen within 300 s — else `SIGNATURE_INVALID`
   (401); (g) a body other than empty or `{}` requires the `content-digest` component, and a covered digest must
   match the exact body bytes — else `DIGEST_MISMATCH` (400); (h) the signature verifies with the bound key — else `SIGNATURE_INVALID` (401); then the
   pair is remembered.
5. A request that carries no data sends no body or the body `{}`; neither needs `content-digest`. A body with any member
   MUST be covered by `content-digest`: otherwise it could be swapped without breaking the signature.

### 2.4 Clocks

`MAX_CLOCK_SKEW` = 300 s (LP 0.1). Every "now" in this document is the receiver's clock. Conformance vectors carry
`now` explicitly; an implementation under test MUST use it.

## 3. Module `lp02.federation` /1 — documents, negotiation, client declaration

### 3.1 Federation document

`GET <origin>/d/<tenant>/federation` (unauthenticated except for a deployment's own access gate) returns:

| Member | Type | Rule |
|---|---|---|
| `v` | string | `"lp02.federation/1"` |
| `origin` | string | the provider's origin (`https://host[:port]`; `http://127.0.0.1:port` only in local development) |
| `tenant` | string | `default` or a 22-character id |
| `implementation` | object | exactly `{ "name": string 1–64, "version": string 1–32 }` — informative, never used for decisions |
| `lp` | array | supported LP versions, strings `"0.1"` and/or `"0.2"`, no duplicates |
| `modules` | object | module id → non-empty array of supported versions (positive integers, no duplicates); `{}` if `lp` lacks `"0.2"` |
| `provider_pub` | public key | the provider key of this tenant |
| `issued_at` | integer | unix seconds |
| `expires_at` | integer | unix seconds; `issued_at` < `expires_at` ≤ `issued_at` + 86 400 |
| `signature` | JWS | `typ lp02.federation`, by `provider_pub` |

### 3.2 Negotiation (deterministic)

`negotiate(local, remote, { now, required = [], expect_origin?, expect_pub?, ratchet? })`:

1. Validate each document, first failure wins, code `FED_DOC_INVALID` (400) unless stated: exact members; `v` of the
   module but another version → `MODULE_VERSION_UNSUPPORTED` (400); types and ranges of §3.1; signature (`typ
   lp02.federation`, key `provider_pub`).
2. `remote.expires_at` ≤ now, or `remote.issued_at` > now + 300 → `FED_DOC_STALE` (400).
3. `expect_origin` given and ≠ `remote.origin`, or `expect_pub` given and ≠ `remote.provider_pub` → `FED_DOC_INVALID`.
4. **Ratchet** (downgrade guard): the negotiator keeps, per (`remote.origin`, `remote.provider_pub`), the `issued_at`
   of the newest document it accepted. A document with an older `issued_at` → `FED_DOWNGRADE` (409). (A newer document
   MAY list fewer modules: that is the peer's signed decision, not a downgrade by a third party.)
5. `lp` = the highest version in both `lp` lists (compare as major.minor integers). None → `VERSION_UNSUPPORTED` (409).
6. If `lp` = `"0.1"`: the module set is empty. Else, for each module id in **both** documents: the highest version in
   both lists; a module id with no common version is absent. A module id present in only one document is absent
   (unknown modules are ignored, never guessed).
7. For each id in `required`: absent → `MODULE_UNSUPPORTED` (409), with the first missing id (in the order given) as
   detail. A missing dependency (§1 table) makes a module absent.
8. Result: `{ "lp": <v>, "modules": { id: version }, "transcript": b64u(SHA-256(JCS([local.signature, remote.signature]))) }`.
   The ratchet then records `remote.issued_at`.

An implementation MUST NOT use a module that is absent from the negotiation result, and MUST NOT replace an absent
module by an LP 0.1 behaviour that imitates it (e.g. a WAITING State whose `next_action` reads like a question). It
refuses instead (§3.3, §5, §7).

**No document = an LP 0.1 party** (block 36). A provider whose `GET <origin>/d/<tenant>/federation` answers 404, or a
runtime whose `GET <aud>/t/<thing_id>/modules` answers 404, is treated as `lp` = `"0.1"`, modules none: every required
module is `MODULE_UNSUPPORTED`, and nothing of LP 0.2 is sent to it. Extensions of one runtime family that are not in
LP 0.1 or this candidate (e.g. agent participation statements) are likewise optional: their absence (404 `NOT_FOUND`)
never makes an LP 0.1 operation fail.

### 3.3 Client module declaration

The client endpoint of a Thing declares which client-side modules it can act on:
`POST <aud>/t/<thing_id>/modules` (RFC 9421 with content-digest, §2.3), body:

| Member | Rule |
|---|---|
| `v` | `"lp02.federation/1"` |
| `modules` | module id → array of versions the client endpoint implements, among the client-side modules (§1) |

Codes: §2.3 order, then — first failure wins — the exact members `{ v, modules }` (`CLIENT_MODULES_INVALID`), `v`
(another version of this module → `MODULE_VERSION_UNSUPPORTED` 400, another module → `CLIENT_MODULES_INVALID`), then
`CLIENT_MODULES_INVALID` (400) for types, unknown or provider-only module ids (the order of §3.2 rule 1; block 57). The
runtime stores the declaration with the bound kid; a new Binding of another key drops it. `GET <aud>/t/<thing_id>/modules`
(RFC 9421) returns `{ "v", "document": <the tenant's federation document>, "declared": <the stored declaration or null> }`.

A provider-side operation that needs a client-side module refuses with `MODULE_NOT_NEGOTIATED` (409) unless the client
declared a common version.

## 4. Module `lp02.admission` /1

### 4.1 Objects

**Open Point view** `GET <origin>/o/<point_id>` (Accept: application/json) — unsigned, served over TLS by the point's
provider: exactly `{ "v": "lp02.admission/1", "aud", "provider_pub", "point_id", "label", "service", "purposes": [{ "code",
"label" }], "admission": { "mode": "public"|"token", "humans": "allow"|"deny", "agents": "allow"|"deny" }, "channels",
"valid_until": time, "open": "<aud>/o/<point_id>" }`.

**Every Open Point expires (block 53).** `valid_until` is always a finite time: an Open Point is a temporary admission
surface, never an address. A point without one is not open (rule 1) — never "open forever". How long is a runtime's
policy, not this protocol's (a person's reference runtime: 7 days by default, 30 at most; a provider's: 90 / 365).
Continued reachability is a NEW point (a new opaque id; for a person, a new compartment and key) — the same point is
never extended without end. A point may also end with its first admission: `admission.expire_on_first: true` (rule 14).

**Discovery descriptor** `GET <origin>/d/<tenant>` — exactly `{ "v": "lp02.admission/1", "aud", "tenant", "provider_pub",
"issued_at": time, "valid_until": time (≤ issued_at + 3600), "points": [ <point view without v, aud, provider_pub> ],
"signature" }` (`typ lp02.descriptor`). Only points the owner marked discoverable; never a person. A verifier refuses a
descriptor past `valid_until` (`FED_DOC_STALE`), whose `provider_pub` is not the one it expects (`KEY_MISMATCH`), or
that lists a point without a finite `valid_until` (`FED_DOC_INVALID`). Order, first failure wins (block 58): exact members
and `v` (`FED_DOC_INVALID` / `MODULE_VERSION_UNSUPPORTED`); `provider_pub` a key and `points` an array
(`FED_DOC_INVALID`); the expected key (`KEY_MISMATCH`); the signature (`FED_DOC_INVALID`); `valid_until` in the future
(`FED_DOC_STALE`); every point's finite `valid_until` (`FED_DOC_INVALID`).

**OPEN request** `POST <origin>/o/<point_id>/open`:

| Member | Rule |
|---|---|
| `v` | `"lp02.admission/1"` |
| `aud` | the point's origin |
| `point_id` | equals the path |
| `purpose` | one of the point's purpose codes |
| `actor` | `"human"` or `"agent"` (declared kind) |
| `opener_pub` | a one-time Ed25519 public key |
| `nonce` | 22 characters |
| `created` | integer unix seconds |
| `admit` | OPTIONAL: a one-time admission code (43 b64u characters) |
| `fed_referral` | OPTIONAL: a federated referral object (§8); not together with `admit` |
| `signature` | JWS `typ lp02.open` by `opener_pub` |

### 4.2 Verification order (first failure wins)

1. The point exists, is not revoked or expired, has a finite `valid_until` and is not past it → else `OPEN_POINT_UNKNOWN` (404).
2. The body is a JSON object; no forbidden member (§2.1.5); exact member set → else `OPEN_INVALID` (400).
3. `v`: another module → `OPEN_INVALID`; `lp02.admission/<n>` with n unsupported → `MODULE_VERSION_UNSUPPORTED` (400).
4. `aud` = this origin and `point_id` = path → else `OPEN_INVALID` (cross-provider and cross-point reuse).
5. `actor` ∈ {human, agent} → else `OPEN_INVALID`. `opener_pub` 43, `nonce` 22, `created` integer → else `OPEN_INVALID`.
6. `purpose` declared by the point → else `OPEN_PURPOSE_UNKNOWN` (400).
7. The actor kind is admitted by the point → else `OPEN_ACTOR_NOT_ADMITTED` (403).
8. `fed_referral` present: the point accepts referral and `admit` is absent → else `OPEN_REFERRAL_INVALID` (403). Else
   `admit` present: a known, unexpired, unused code of this point → else `OPEN_TOKEN_INVALID` (403). Else a
   `token`-mode point → `OPEN_TOKEN_REQUIRED` (403).
9. |now − `created`| ≤ 300 → else `OPEN_STALE` (401).
10. Signature (`typ lp02.open`, key `opener_pub`) → else `OPEN_SIGNATURE_INVALID` (401).
11. `nonce` not seen within 600 s → else `OPEN_REPLAY` (409); remember it.
12. `fed_referral` present: §8.3.
13. Capacity (`max_pending`, `max_open`) → else `OPEN_CAPACITY` (429).

   *Order rationale (37F, abuse hardening):* the point's own policy (7–8) is checked before any cryptography or memory
   (9–11): a request a token or referral point would refuse anyway costs one hash lookup and stores nothing. A code is
   256 random bits, so learning that a guessed code is unknown, before the signature is checked, teaches nothing.
14. **Admit**: consume the code; create a Thing (LP 0.1, title = the point's label and the purpose label, never the
    opener's words), its State v1, and a Grant; return `{ "admitted": true, "thing_id", "link", "provider_pub",
    "redeem_by" }` (201). The opener redeems the link by LP 0.1 Redemption. **A refusal writes nothing.** A point with
    `admission.expire_on_first` is EXPIRED by this admission: the next OPEN is `OPEN_POINT_UNKNOWN`.

### 4.3 Lifecycle, privacy

An admitted relationship nobody redeemed within 120 s is withdrawn (Grant revoked, Thing closed). The admission record
holds point, purpose, actor kind, time and Grant id — never the opener's key, address or device.

## 5. Module `lp02.request` /1

### 5.1 Objects

**Request view** `GET <aud>/t/<thing_id>/requests` (RFC 9421, §2.3) → `{ "v": "lp02.request/1", "request": null |
{ "request_id", "thing_id", "template", "label", "waiting_on": "client"|"provider", "role": null, "role_label": null,
"options": [{ "code", "label" }], "deadline": time, "on_deadline": { "action": "escalate"|"close"|"choose", "option"? },
"status": "OPEN", "created_at", "state_version": integer, … } }`. The view is informative; the signed State chain is
authoritative.

**Answer** `POST <aud>/t/<thing_id>/requests/<request_id>/answer/<option_code>` — RFC 9421 without a body (§2.3). The
option is in the signed `@target-uri`, so the stored signature proves exactly this choice.

### 5.2 Rules

1. **Creation (provider side).** A request puts the State to `WAITING`, `waiting_on` = the side that must act,
   `next_action` = the template label, `deadline` = now + the template's seconds. At most one OPEN request per Thing
   (`REQUEST_OPEN`, 409). A request waiting on the client requires a Binding (`BINDING_MISSING`, 409), a client that did
   not leave (§9; `CLIENT_LEFT`, 409) and a client declaration of `lp02.request` (§3.3; `MODULE_NOT_NEGOTIATED`, 409).
2. **Answer**, verification order after §2.3: first the staleness rule (5) is applied to every OPEN request; then
   request unknown or of another Thing → `REQUEST_UNKNOWN` (404); status not OPEN — including a request closed because
   the State moved — → `REQUEST_DECIDED` (409); not the side waited on → `NOT_YOUR_TURN` (403); option unknown →
   `OPTION_UNKNOWN` (400). (A concurrent State change between these checks and the transition is `STATE_CONFLICT`,
   409; it cannot be produced by a vector.)
3. **Transition on answer**: new provider-signed State: `status` WAITING, `waiting_on` = the other side,
   `next_action` = `<label>: <option label>` (clipped to 140 characters with `…`), `deadline` null; the request becomes
   ANSWERED with `answer`, `answered_by` and the evidence `{ kid, signature_input, signature }`.
4. **Deadline**: `escalate` → WAITING on provider, `Overdue: <label>`; `close` → CLOSED; `choose` → as an answer with
   the preset option, `answered_by` = `deadline`.
5. **Staleness**: when anyone else moves the State, an OPEN request is CLOSED (`STATE_MOVED`) at once.
6. **No history**: only the OPEN and the latest decided request are kept; none after the Thing is CLOSED.
7. **Retries.** A client that lost a response does not resend the same signed request (it is a replay:
   `SIGNATURE_INVALID`); it re-reads the request view or the State (LP 0.1 GetThing), which is the truth, and only then
   decides. A second, different answer to a decided request is `REQUEST_DECIDED`.

## 6. Module `lp02.wake` /1

1. **Subscription** `POST <aud>/t/<thing_id>/wake/<wake_id>` (RFC 9421 **with content-digest**), body exactly
   `{ "url": string, "max_per_day"?: integer 1–100 }` (default 24). `wake_id` 22 characters chosen by the client.
   Order after §2.3: `wake_id` format, exact body members, `max_per_day` an integer 1–100 → `WAKE_INVALID` (400);
   client left → `CLIENT_LEFT` (409); url not an `https` URL with a host name (no IP literal, no credentials, no
   fragment; local development only: `http://127.0.0.1`) → `WAKE_INVALID`; Thing CLOSED → `THING_CLOSED` (409);
   `wake_id` used by another Thing → `WAKE_INVALID`; already 2 subscriptions for the Thing → `WAKE_LIMIT` (409). Removal: `POST …/wake/<wake_id>/remove` (no body).
2. **Signal** `POST <url>` body `{ "v": "lp02.wake/1", "wake_id", "event": "thing.changed", "sent_at": time,
   "signature" }` (`typ lp02.wake`, provider key of the Thing). No thing id, no State, no text.
3. **Receiver verification** (client endpoint), order: exact members, `v`, `event` → `WAKE_INVALID`; `wake_id` not one it
   registered → `WAKE_UNKNOWN`; signature with the provider key **pinned for that Thing** → else `WAKE_UNVERIFIED`;
   `sent_at` not newer than the last accepted signal for that `wake_id` → `WAKE_REPLAY`. A `v` of another version of
   this module → `MODULE_VERSION_UNSUPPORTED`. On acceptance the receiver reads the
   current State itself (LP 0.1 GetThing). A wake is a hint; it never carries authority.
4. **Delivery bounds**: changes are coalesced (≥ 30 s between signals to one endpoint); at most `max_per_day` signals a
   day; retries 0 s, 10 s, 60 s then dropped; a signal is also sent once when the Thing closes, then the subscription
   ends.

## 7. Module `lp02.linecaps` /1

Frames are JSON objects on the LP 0.1 `lyne-data` channel of a Live Line, each with `"lyne": "lp02.linecaps/1"` and `t`.
Line content is transient (LP 0.1 §8.5). Frames are not signed: the Line is already authenticated end to end (LP 0.1 §7–§8).

0. **Before the Line (block 36)**: the client endpoint sends a frame of this module only to a provider whose federation
   document — from `GET <aud>/t/<thing_id>/modules` (§3.3); none on 404 — passes §3.2 steps 1–2, is signed by this
   Thing's provider key (else `FED_DOC_INVALID`), and lists LP `"0.2"` and a version of `lp02.linecaps` the endpoint
   implements (else `MODULE_UNSUPPORTED`). Otherwise the module is REFUSED for this Thing and no frame — not even a hello
   — is sent: an LP 0.1 provider endpoint shows any `lyne-data` text to its person (vectors `LC-hello-*`).
1. **Hello (negotiation)**: the client endpoint sends `{ lyne, t: "hello", versions: [1] }` once `lyne-data` opens. The
   provider endpoint MUST NOT send a manifest before it received a hello with a common version; without one the
   capability layer is **REFUSED** for this Line (an LP 0.1 client never sees a frame of this module).
2. **Manifest** (provider → client): `{ lyne, t: "manifest", manifest: { caps: [cap…], expires_s: 10–3600 } }`;
   `cap` = `{ kind: struct|file|stream|control, code, label, from: provider|client|both, … }` with the exact members and
   ranges of `MODULES.md` §linecaps (struct fields number/enum/bool/text; file types/max_bytes ≤ 8 MiB/max_files ≤ 10;
   stream unit/min/max/max_hz ≤ 50; control commands with non-text params, `from` ≠ both).
3. **Accept** (client → provider): `{ lyne, t: "accept", caps: [codes] }` (empty = decline). Exactly once.
4. **Data frames**: `struct {cap, values}`, `file-start {cap, id, name, type, size, chunks, sha256}`,
   `file-chunk {cap, id, n, data}` (12 KiB chunks; `data` is strict, padded base64 — RFC 4648 §4, length a multiple
   of 4 — anything else is `CAP_FRAMING`), `sample {cap, v, at}`, `command {cap, id, command, params}`,
   `command-result {id, ok, reason}`.
5. **Receiver enforcement** — a text on `lyne-data` is treated as a frame of this module iff, after leading
   whitespace, it begins with `{` and matches the regular expression `"lyne"\s*:\s*"lp02\.linecaps/` anywhere;
   anything else is left to the application (IGNORE). Such a text that is not a JSON object (strict, §2.1) whose
   top-level `lyne` is a version this endpoint implements is `CAP_MALFORMED`. The receiver's own clock is authoritative
   for expiry and rate (a sample's `at` is informative). Each frame is checked; a failure is a **violation** with one of these codes, and 5
   violations end the Line (`CAP_VIOLATION`): `CAP_MALFORMED` (not JSON / duplicate members / > 32 KiB),
   `CAP_UNEXPECTED` (hello/manifest/accept/result out of turn), `CAP_NOT_ACCEPTED`, `CAP_DIRECTION`, `CAP_EXPIRED`
   (later than `expires_s` after the accept was sent or received),
   `CAP_INVALID` (schema, range, unknown command), `CAP_LIMIT` (records/files), `CAP_BUDGET` (16 MiB held per endpoint),
   `CAP_RATE` (a sample less than 0.8 × 1000/`max_hz` ms after the last accepted sample of that stream), `CAP_FRAMING` (file ids, chunk order or size), `CAP_HASH` (file hash — the violation of the chunk frame that
   completes the file).
6. Each `control` command is shown to the receiving person and runs only if allowed (`DONE` / `DECLINED` / `REFUSED` /
   `NO_ANSWER` after 60 s; one at a time). At the end of the Line every buffer is zeroed and released.

## 8. Module `lp02.referral` /1

1. **Pinned peer** (local, explicit): created only from the peer's **federation document** (§3.1), which the operator
   obtains out of band and the pinning side verifies and negotiates (`required: ["lp02.admission", "lp02.referral"]`).
   Stored: `{ peer_id = kid(provider_pub), origin, provider_pub, points: [point ids the peer may refer to], modules,
   pinned_at }`. An origin is never re-pinned with another key without removing the pin first (`PEER_INVALID`).
2. **Referral** (issued by A for its bound customer, to B's point): `{ v: "lp02.referral/1", iss: A origin, aud: B
   origin, point_id, purpose, nonce (22), exp (unix, ≤ now + 3600), signature }` (`typ lp02.referral`, A's provider key).
   It names neither the customer, nor the case, nor any customer key. It travels in the link fragment
   `<B>/o/<point>#fr=<b64u(JSON)>` — never in a query or path.
3. **Acceptance at B** (inside OPEN step 11), order: exact members / `v` of another module → `OPEN_REFERRAL_INVALID`
   (another version of this module → `MODULE_VERSION_UNSUPPORTED`, 400); `aud` = B, `point_id`
   = the path, `purpose` = the OPEN's → else `OPEN_REFERRAL_INVALID`; `exp` > now and ≤ now + 3600 + 300 → else
   `OPEN_REFERRAL_INVALID`; `iss` pinned at B with this point allowed and `lp02.referral` negotiated → else
   `OPEN_REFERRAL_UNTRUSTED`; signature with the **pinned** key (never a key the referral names) → else
   `OPEN_REFERRAL_UNTRUSTED`; (`iss`, `nonce`) unused → else `OPEN_REFERRAL_USED`; fewer than 50 admissions from this
   peer in 24 h → else `OPEN_REFERRAL_QUOTA` (429). Used referrals are remembered in durable storage for at least 24 h.

## 9. Module `lp02.exit` /1

1. **Exit** `POST <aud>/t/<thing_id>/leave` (RFC 9421, no body) by the bound key. Order after §2.3: a kid other than the
   bound one → `KEY_MISMATCH` (403); a Live Line in progress → `LINE_ACTIVE` (409) — the Line holds the State until it
   ends, so the client ends the Line first. Effects, atomically from the client's
   view: every wake subscription of the Thing removed; an OPEN request waiting on the client CLOSED (`CLIENT_LEFT`) and
   the State moved to WAITING on provider, `next_action` `The customer left: <label>`; every Grant that could still open
   a Line (ISSUED, REDEEMED, EXHAUSTED without an active Line) REVOKED; nothing new may wait on the client
   (`CLIENT_LEFT`, 409). Response `{ "v": "lp02.exit/1", "left": true, "left_at": time }` (idempotent).
2. Only a new LP 0.1 Redemption on the Thing ends the departure.
3. **Attention view** `GET <aud>/t/<thing_id>/attention` (RFC 9421) → `{ v, left, wakes: [{ wake_id, max_per_day,
   sent_24h }], waiting_on_you, seats_you_invited, line_possible }`.

## 10. Error registry

| Code | HTTP | Module |
|---|---|---|
| `INVALID_JSON` | 400 | all (malformed body, duplicate members) |
| `MODULE_VERSION_UNSUPPORTED` | 400 | all (known module, unknown version) |
| `MODULE_UNSUPPORTED` | 409 | federation (required module not negotiated) |
| `MODULE_NOT_NEGOTIATED` | 409 | request, linecaps (client did not declare the module) |
| `VERSION_UNSUPPORTED` | 409 | federation (no common LP version) |
| `FED_DOC_INVALID`, `FED_DOC_STALE` | 400 | federation |
| `FED_DOWNGRADE` | 409 | federation |
| `CLIENT_MODULES_INVALID` | 400 | federation |
| `THING_UNKNOWN` | 404 | §2.3 |
| `KEY_MISMATCH` | 403 | §2.3 |
| `SIGNATURE_INVALID` | 401 | §2.3 |
| `DIGEST_MISMATCH` | 400 | §2.3 |
| `OPEN_*` | 400–429 | admission, referral (see §4.2, §8.3) |
| `REQUEST_UNKNOWN` 404, `REQUEST_DECIDED` 409, `NOT_YOUR_TURN` 403, `OPTION_UNKNOWN` 400, `STATE_CONFLICT` 409, `REQUEST_OPEN` 409, `BINDING_MISSING` 409 | | request |
| `WAKE_INVALID` 400, `WAKE_LIMIT` 409, `WAKE_UNKNOWN`, `WAKE_UNVERIFIED`, `WAKE_REPLAY` (receiver) | | wake |
| `CLIENT_LEFT` 409, `THING_CLOSED` 409, `LINE_ACTIVE` 409 | | exit, request, wake |
| `CAP_*` (violation codes) | — | linecaps |
| `MANIFEST_INVALID` | 400 | linecaps (a manifest outside §7's caps grammar, refused by the client before accepting — found by the block-58 architecture check) |
| `PEER_INVALID` 400, `PEER_UNKNOWN` 404 | | referral |
| `RECOVERY_INVALID` 400, `RECOVERY_UNKNOWN` 404, `RECOVERY_REVOKED` 403, `RECOVERY_USED` 409, `RECOVERY_EXPIRED` 403, `RECOVERY_EPOCH_STALE` 409, `RECOVERY_PENDING` 409 | | recovery |
| `PROOF_INVALID` 400, `PROOF_SIGNATURE` 401, `PROOF_NOT_CLOSED` 409, `PROOF_ANCHOR` 409, `PROOF_AUTHORITY` 403, `PROOF_SCOPE` 409; `PROOF_NOT_AVAILABLE` 409 (runtime: nothing to prove) | | result proof (§15) |
| `NONCE_REQUIRED` 401, `NONCE_INVALID` 400, `NONCE_REPLAYED` 401, `NONCE_NOT_HERE` 400, `MODULE_NOT_NEGOTIATED` 409 (a nonce without negotiation) | | nonce (§16) |
| `DELEGATION_INVALID` 400, `DELEGATION_TOO_DEEP` 400, `DELEGATION_CYCLE` 400, `DELEGATION_PARENT` 400, `DELEGATION_SCOPE` 409, `DELEGATION_WIDENS` 403, `DELEGATION_EPOCH_STALE` 409, `DELEGATION_REVOKED` 403, `DELEGATION_EXPIRED` 403, `DELEGATION_DENIED` 403, `DELEGATION_EXHAUSTED` 409 | | delegation |
| `TRUST_INVALID` 400, `TRUST_ORIGIN_MISMATCH` 409, `INTRO_INVALID` 400, `INTRO_SCOPE` 409, `INTRO_EXPIRED` 403, `INTRO_TARGET_MISMATCH` 409, `INTRO_LIMIT` 409 (runtime) | | trust, introduction (§18) |
| `AGREEMENT_INVALID` 400, `AGREEMENT_UNKNOWN` 404, `AGREEMENT_OPEN` 409, `AGREEMENT_SIGNED` 409, `POLICY_NOT_MET` 409, `DELEGATION_DENIED` 403 (a delegate never signs); and the result codes below | | agreement (§17) |
| `RESULT_INVALID` 400, `RESULT_SCOPE` 409, `RESULT_NOT_AGREED` 409, `RESULT_OUTCOME_MISMATCH` 409, `RESULT_EPOCH_STALE` 409, `KEY_REVOKED` 403, `RESULT_BASIS_INVALID` 401 (verification) / 400 (making), `RESULT_STALE` 409, `RESULT_EXISTS` 409 | | result |
| `OFFER_INVALID` 400, `OFFER_STALE` 409, `ENDPOINT_EXPOSED` 400, `BINDING_UNKNOWN` 400, `OFFER_NOT_VISIBLE` 403, `CHANNEL_THING_MISMATCH` 409, `CHANNEL_UNSUPPORTED` 400, `ACTOR_UNKNOWN` 403, `RECIPIENT_INVALID` 400 | | channel /2 (§19) |
| `LINE_PROFILE_INVALID` 400, `LINE_PROFILE_MISMATCH` 409; reused: `CHANNEL_NOT_GRANTED` (LP 0.1 §8.3, a Line end code), `MODULE_VERSION_UNSUPPORTED` 400, `MODULE_NOT_NEGOTIATED` 409, `MODULE_UNSUPPORTED` 409 | | liveline (§20) |
| `DELIVERY_INVALID` 400, `DELIVERY_EXPIRED` 409, `DELIVERY_REPLAY` 409, `DELIVERY_UNKNOWN` 404, `PAYLOAD_DIGEST_MISMATCH` 400, `NO_ROUTE` 409, `ROUTE_NOT_OFFERED` 403, `RECEIPT_REQUIRED` 409, `RECEIPT_INVALID` 400, `ATTEMPT_ORDER` 409; `RATE_LIMITED` 429 (as §14.2 rule 12); reused: `MODULE_NOT_NEGOTIATED` 409, `MODULE_VERSION_UNSUPPORTED` 400, `THING_CLOSED` 409, `KEY_REVOKED` 403, `SIGNATURE_INVALID` 401 | | channel /2 (§19) |

## 11. Conformance

`tests/DRIVER.md` defines a JSON-lines driver protocol; `tests/run_conformance.py` feeds every vector of `vectors/` to
any implementation that speaks it and compares outcome, code and state transition. Two implementations exist: **A**
(the LYNE runtime, `04_Prototuup/P1_provider_pilot`) and **B** (`04_Prototuup/lp02-independent-peer`, written from this
document only).

**Candidate-4.** Three implementations speak the driver protocol: A, B and **C** (`04_Prototuup/lp02-impl-c`, C#,
base library only, written from this document). Candidate-4's conformance is ONE vector set for all of them:
`vectors/lp02-vectors.json` (candidate-1, byte-identical), `vectors/channel2-vectors.json` (§19, unchanged from
candidate-3), `vectors/liveline-vectors.json` (§20) and `vectors/negotiation-vectors.json` (candidate-3 ↔ candidate-4 ↔
candidate-1 ↔ LP 0.1), every vector run under the candidate-4 profile (`conformance/run_candidate4.py`); candidate-1's and
candidate-3's vectors must give exactly their own answers under it. C implements a declared profile of modules (MINIMAL.md);
it runs every vector of the modules it implements. §20 is also proven between two independently written browser peers
(the candidate's evidence).

## 12. Module `lp02.result` /1 — a RESULT without a Line (block 43)

A RESULT is the verified, persistent outcome of a THING. LP 0.1 forms it on a Live Line (both parties sign it there:
the **line basis** — it stays exactly as LP 0.1 defines it, and this module does not touch it). This module adds the
**request-answer basis**: the outcome is agreed asynchronously, by the bound client's signed choice of one of the
provider's declared options, and the provider's signed **async Result** carries that choice as its evidence. No text a
person wrote is evidence; only the provider's own question (its fixed wording and codes) and the client's signature.

A provider that CLOSES a THING without such an answer closes it without an agreed Result (LP 0.1 `result_id` null);
nothing in this module turns a unilateral closure into agreement.

### 12.1 Objects

**Concluding question** — the client's view of an OPEN request whose template concludes (provider-defined):
`GET <aud>/t/<thing_id>/conclusion` (RFC 9421, §2.3) → `{ "v": "lp02.result/1", "question": null | Q }` with Q exactly
`{ "request_id", "thing_id", "template", "label", "options": [{ "code", "label" }], "conclusion": { <option code>:
<outcome code> }, "deadline": time, "created_at": time }`. `conclusion` names the options that conclude the THING and the
outcome each one means; an option not named there answers the question without concluding. Outcome codes match
`[a-z][a-z0-9._-]{0,31}`; labels 1–60 **UTF-16 code units** (a character outside the BMP counts two — block 58: B had
counted code points); 2–8 options; 1–8 conclusion entries, each naming an option.

**Concluding answer** — `POST <aud>/t/<thing_id>/requests/<request_id>/conclude/<option code>` with the body **exactly**
`JCS({ "v": "lp02.result/1", "question": <b64u SHA-256 of JCS(Q)> })`, signed with the Thing-key and covered by
`content-digest` (§2.3 rule 2). The client signs the request's identity, its option (in `@target-uri`) and the exact
question it was shown, meaning included (in the digest of the body).

**Async Result** (typ `lp02.result`, signed by the provider key of the THING), exactly:
```
{ "v": "lp02.result/1", "result_id", "thing_id", "aud", "outcome", "epoch", "issued_at": time,
  "basis": { "kind": "request_answer", "question": Q,
             "answer": { "option", "created": <unix>, "kid", "signature_input", "signature" } },
  "signature" }
```
`epoch` is the Binding epoch (LP 0.1 §10.3) of the key that answered. `created` is the `created` parameter of the
answer's signature; `signature_input` and `signature` are the answer's header values.

### 12.2 Making an async Result (provider)

On a concluding answer that verifies (§2.3, then §5.2 rule 2, then: the body equals the expected bytes for the current
question — else `RESULT_BASIS_INVALID` 400), the provider applies the answer (§5.2 rule 3), then — if the option is named
in `conclusion` — issues the async Result with `outcome` = `conclusion[option]` and appends a CLOSED State. At most one
async Result per THING.

### 12.3 Verification (any party; first failure wins)

Inputs: the Result; the THING `{ thing_id, aud, provider_pub, closed_at | null }` (`closed_at` = a CLOSED State that this
Result did not make); the Bindings `[{ epoch, client_pub, bound_at, revoked_at | null }]`; the async Results already accepted for
the THING (their `result_id`s).

1. Shape: an object; `v` = `lp02.result/1` (another version of this module → `MODULE_VERSION_UNSUPPORTED`); exact member
   sets at every level (§2.1 rule 4); no forbidden member (§2.1 rule 6); identifiers, times, integers, codes and the
   question as defined in §12.1; `basis.kind` = `request_answer`; `answer.option` is a code — else `RESULT_INVALID` (400).
2. The provider signature verifies with `provider_pub`, typ `lp02.result` — else `SIGNATURE_INVALID` (401).
3. `thing_id` = the THING's, `aud` = the THING's `aud`, `question.thing_id` = `thing_id` — else `RESULT_SCOPE` (409).
4. `answer.option` is one of `question.options` — else `OPTION_UNKNOWN` (400).
5. `answer.option` is named in `question.conclusion` — else `RESULT_NOT_AGREED` (409): the client chose, but not an
   agreement.
6. `outcome` = `question.conclusion[answer.option]` — else `RESULT_OUTCOME_MISMATCH` (409).
7. A Binding with `epoch` = the Result's `epoch` exists and its kid equals `answer.kid` — else `KEY_MISMATCH` (403).
8. The epoch was the current one **when the client answered**: no Binding of a higher epoch has `bound_at` ≤ `created`
   — else `RESULT_EPOCH_STALE` (409); and that Binding's `revoked_at` is null or later than `created` — else `KEY_REVOKED`
   (403). A later rebinding (a lost device, §10.4 of LP 0.1) does not undo an agreement made before it; an answer signed
   with the old key after it is refused.
9. The answer signature: `signature_input` = `sig1=("@method" "@target-uri" "content-digest");created=<created>;keyid="<kid>";alg="ed25519"`,
   and the signature over the §2.3 base of `POST`, `<aud>/t/<thing_id>/requests/<question.request_id>/conclude/<option>`
   and the `content-digest` of the expected body (§12.1, with this Result's `question`) verifies with that Binding's
   `client_pub` — else `RESULT_BASIS_INVALID` (401). (A provider cannot invent consent: it has no client key.)
10. `created` ∈ [`question.created_at` − 300, `question.deadline` + 300] (the clock skew §2.3 already accepts) and
    `created` ≤ `issued_at` + 300 — else `RESULT_STALE` (409).
11. `closed_at` is null or later than `created` — else `THING_CLOSED` (409).
12. No other async Result was accepted for this THING (a different `result_id`) — else `RESULT_EXISTS` (409). The same
    Result verified again is accepted (idempotent).

### 12.4 One Result

Rule 12 is enforced by every party that holds the THING's record (the provider, the client endpoint). The provider
appends a CLOSED State with the first async Result, so a second concluding question cannot be asked or answered (rule 11;
§5.2 rule 1). A provider that signs two Results for one THING has produced evidence of its own double-dealing: both
carry its signature and the client's distinct answers.

### 12.5 Privacy

The evidence is codes, the provider's own question and signatures. Nothing the client typed exists: there is nothing
to type. The async Result is kept for the life of the THING (it is its outcome); the request record it came from is
the one kept per §5.2 rule 6.

## 13. Module `lp02.delegation` /1 — attenuated delegation (block 44)

Authority is passed on only by **narrowing** it. A holder of authority over a THING may give a key a part of it; the
part can never be wider than what the holder had, in any dimension, and lives no longer than its ancestors. This is
capability attenuation, not trust between agents: CAPABILITY ≠ AUTHORITY; GRANT = AUTHORITY.

### 13.1 Delegation object (typ `lp02.delegation`)

Exactly:
```
{ "v": "lp02.delegation/1", "delegation_id", "thing_id", "aud", "epoch",
  "parent": null | { "delegation_id", "hash" },
  "issuer_kid", "subject_pub",
  "actions": [ … ], "channels": [ … ], "purpose", "not_before": time, "exp": time, "max_uses": int, "depth": int,
  "signature" }
```
- **Root** (`parent` null): signed by the THING's provider key (`issuer_kid` = its kid). It hands the bound client's key
  (`subject_pub`, at Binding `epoch`) the authority it may delegate. A provider issues a root only on the bound client's
  request and only within the provider's policy; nothing is implicit: without a root nothing can be delegated.
- **Child**: `parent.delegation_id` and `parent.hash` (b64u SHA-256 of JCS of the whole parent object, signature
  included) name its parent; it is signed by the parent's subject key (`issuer_kid` = kid of `parent.subject_pub`).
- `actions` ⊆ { `answer`, `line`, `read`, `subscribe` } (sorted, no duplicates, ≥ 1). **Concluding is not delegable**
  in /1: an agreement (§12) is the bound client's own signature — a person keeps the final word. `answer` never covers a
  question that concludes the THING (§12.1): a delegate's answer to it is refused `DELEGATION_DENIED` (403) (block 46); `channels` ⊆
  { `data`, `voice`, `video` } (sorted, no duplicates; may be empty); `purpose` a code `[a-z][a-z0-9._-]{0,63}`;
  `max_uses` 1–100000; `depth` 0–7 = how many further levels this holder may still create (0: none).

### 13.2 Attenuation (child against its parent)

`thing_id`, `aud`, `epoch` equal; `actions` ⊆ parent's; `channels` ⊆ parent's; `purpose` = parent's or starts with
parent's + `.`; `not_before` ≥ parent's; `exp` ≤ parent's; `max_uses` ≤ parent's; parent `depth` ≥ 1 and child
`depth` < parent `depth`. Any violation: `DELEGATION_WIDENS` (403).

### 13.3 Verifying a chain before an action (first failure wins)

Input: the chain `[root, …, leaf]` (root first); the THING `{ thing_id, aud, provider_pub, epoch }` (current Binding
epoch); `now`; the revoked delegation ids and revoked holder kids of the THING; the use counts per delegation id; the
requested `action` (and `channel` for `line`). The request itself is signed (§2.3) with the leaf's subject key — the
runtime checks that signature first.

1. The chain is an array of 1–8 elements — else `DELEGATION_TOO_DEEP` (400) for more than 8, `DELEGATION_INVALID` (400)
   otherwise. Each element: `v` (another version of this module → `MODULE_VERSION_UNSUPPORTED`), exact members, no
   forbidden member, the value rules of §13.1 — else `DELEGATION_INVALID` (400).
2. `delegation_id`s are pairwise different — else `DELEGATION_CYCLE` (400).
3. Element 0 is a root (`parent` null) and every later element is not — else `DELEGATION_PARENT` (400).
4. For each element in order: (a) its `thing_id` and `aud` are the THING's — else `DELEGATION_SCOPE` (409); (b) a
   root's `issuer_kid` is the provider's kid and its signature verifies with `provider_pub` — else `SIGNATURE_INVALID`
   (401); (c) a child's `parent` names the previous element (`delegation_id` and `hash`) — else `DELEGATION_PARENT`
   (400); (d) a child's `issuer_kid` is the kid of the previous element's `subject_pub` and its signature verifies with
   that key — else `SIGNATURE_INVALID` (401).
5. Each child against its parent: §13.2 — else `DELEGATION_WIDENS` (403).
6. The root's `epoch` is the THING's current Binding epoch — else `DELEGATION_EPOCH_STALE` (409).
7. No element's `delegation_id` is revoked and no element's subject kid is a revoked holder — else
   `DELEGATION_REVOKED` (403). (Revoking a parent, or a compromised ancestor key, ends every descendant; revoking a child
   leaves its parent and siblings.)
8. `now` ∈ [`not_before`, `exp`] of every element — else `DELEGATION_EXPIRED` (403).
9. `action` ∈ the leaf's `actions`, and for `line` the requested channels ⊆ the leaf's `channels` — else
   `DELEGATION_DENIED` (403).
10. The use count of every element is below its `max_uses` — else `DELEGATION_EXHAUSTED` (409). An accepted action counts
    once against every element of the chain (a parent's allowance bounds all its descendants together).

A verifier needs no call to the provider to *understand* a chain (it is self-contained and signed); the provider applies
its current revocation state and use counts (rules 6, 7, 10) before an action is exercised.

### 13.4 Revocation

The bound client revokes (in /1 only the bound client): `POST <aud>/t/<thing_id>/delegations/<delegation_id>/revoke`
(that element and every descendant), or `POST <aud>/t/<thing_id>/delegations/holders/<kid>/revoke` (a compromised holder
key: every element whose subject it is, and their descendants). A client that leaves the THING (§9) ends every
delegate's access with it. A Binding revocation or a new Binding (LP 0.1 §10.4)
makes every root of the old epoch stale. Revocation is decided by the provider's state at the moment of the action:
whatever runs faster, an action is checked against the revocation state current when it is applied.

## 14. Module `lp02.recovery` /1 — moving a relationship to a new device (block 45)

A person who loses the device holding a Thing-key moves the relationship to a new device — no account, no e-mail, no
SMS, no password, no LYNE identity. The authority to do so is a **Recovery Grant**: a GRANT whose only power is to have
the provider re-issue an ordinary LP 0.1 Grant for the same THING; the new device redeems it (LP 0.1 §6) with a new
Thing-key. Everything else is LP 0.1 as it is: the old Binding is revoked (§10.4: epoch + 1, the old key never binds or
reads again, every older Grant revoked); every delegation of the old epoch is stale (§13.3 rule 6).

### 14.1 Recovery Grant (typ `lp02.recovery`, signed by the provider key of the THING)

Exactly: `{ "v": "lp02.recovery/1", "recovery_id", "thing_id", "aud", "epoch", "recovery_pub", "purpose": "rebind",
"issued_at": time, "exp": time, "hold_seconds": int, "signature" }`.

- `recovery_pub`: the public half of a **recovery key** the client made. Its private half is held by a second device of
  the person, or kept offline as a 32-byte seed (printed, saved); the Ed25519 private key is
  `HKDF-SHA256(salt = "lyne-recovery/1", ikm = seed, info = "lp02.recovery key", L = 32)` used as the Ed25519 seed. The
  provider stores only `recovery_pub` — never a bearer secret.
- `epoch`: the Binding epoch it may move FROM; `hold_seconds` 0, or 900–604800 (block 48: longer than twice the §2.3
  window); `exp` ≤ `issued_at` + 400 days.
- Issued only on the bound client's request `POST <aud>/t/<thing_id>/recovery` with body `{ "recovery_pub", "hold_seconds" }`
  (§2.3, content-digest); a new one replaces the previous (at most one per THING). Revoked by the bound client
  `POST …/recovery/revoke`.

### 14.2 Moving (first failure wins)

`POST <aud>/t/<thing_id>/recover` with body exactly `JCS({ "v": "lp02.recovery/1", "recovery_id" })`, signed per §2.3 with
the **recovery key** (`keyid` = its kid; content-digest required).

1. Body shape — else `RECOVERY_INVALID` (400).
2. The THING has a Recovery Grant with this `recovery_id` — else `RECOVERY_UNKNOWN` (404) (another THING, another
   tenant: unknown).
3. The request signature verifies with that grant's `recovery_pub` (§2.3 c–g: key, `created` window, content-digest,
   signature) — else `SIGNATURE_INVALID` (401). **Not** §2.3 h: the replay memory is never consulted for a move (rule 11).
4. The grant is not revoked — else `RECOVERY_REVOKED` (403); not used — else `RECOVERY_USED` (409); `now` ≤ `exp` —
   else `RECOVERY_EXPIRED` (403).
5. The grant's `epoch` is the THING's current Binding epoch — else `RECOVERY_EPOCH_STALE` (409) (a move already happened:
   every older recovery artifact is dead).
6. The THING is not CLOSED — else `THING_CLOSED` (409); the client did not leave it (§9) — else `CLIENT_LEFT` (409).
7. With `hold_seconds` = 0: the move happens now. Otherwise the first valid request starts a **pending move**
   (`{ "pending_until" }`, 202) that the current bound key may cancel (`POST …/recovery/cancel`); a valid request after
   `pending_until` completes it; a request while it is pending answers `RECOVERY_PENDING` (409).
8. The move, atomically: the grant becomes used; the current Binding is revoked (epoch + 1); a new LP 0.1 Grant is issued
   (purpose `rebind`, the THING's channels, redeemable for 900 s) and its link returned once: `{ "link" }` (200). The
   new device redeems it with a fresh Thing-key. Two concurrent moves: one completes, the other is `RECOVERY_USED`.

**Determinism (block 48).** Every rule reads only the request, the clock and the Recovery Grant's PERSISTENT state
(`revoked_at`, `used_at`, `pending_until`) — never memory that a restart or the timing of other requests changes. So:

9. A repetition of any request — the exact bytes again in the same second, the next second, after a restart, one of N
   concurrent copies, or a different valid request with the same capability — gets the answer of rules 1–7 against the
   state the first one left: after a move `RECOVERY_USED`; while held `RECOVERY_PENDING`. A lost race always sees the
   winner's epoch + 1 as well and answers `RECOVERY_USED` (rule 4 comes before rule 5). The decision and its effect are
   one atomic step per THING: of concurrent requests exactly one moves.
10. The old device's own Thing-key is not the recovery key: its move request is `SIGNATURE_INVALID` (rule 3), before and
   after a move.
11. A replay of the request that STARTED a held move cannot complete it: completing needs `now` ≥ `pending_until` ≥ its
   start + 900 s, and that request's `created` is then outside the ±300 s window (rule 3).
12. A runtime MAY refuse any request **before rule 1** with `RATE_LIMITED` (429, `Retry-After`) — resource policy, not a
   protocol decision; it never replaces a rule's answer: a retry after `Retry-After` gets rules 1–9. A runtime that no
   longer holds the THING's key answers `THING_FROZEN` (409) in place of an ACCEPTING decision of rule 7 (a move, a
   pending start, a completion) and consumes nothing; every refusal of rules 1–7 stays as it is.

The recovery key cannot read the THING, answer, conclude, delegate or open a Line — its only route is `recover`. After a
move the person makes a new recovery key on the new device.

A provider that no longer holds the THING's provider key (LP 0.1 §10 item 8: the THING is frozen) refuses an otherwise
valid move `THING_FROZEN` (409) and consumes nothing — recovery cannot thaw or fork a frozen THING. The move is judged
against the provider's own stored Recovery Grant (rule 2), so a re-wrap of the SAME provider key (a master-secret rotation)
leaves every artifact valid.

## 15. LYNE RESULT PROOF `lyne-result-proof/1` — portable evidence of a CLOSED Thing's outcome (block 49)

Not a module and not a new signed object: an **evidence envelope** around objects the provider already signed. It proves
the final outcome of a CLOSED Thing **offline** — without LYNE, an account or the provider being reachable. It is
**evidence, not authority**: it binds no key, issues no Grant, gives no Line and never re-opens a Thing. A CLOSED Thing is
never rebound (MASTER decision 03.10.2026); after closure the person carries this proof, not the relationship.

### 15.1 Members (exactly these)

`{ "kind": "lyne-result-proof/1", "basis": "line" | "request_answer" | "agreement", "thing", "anchor", "result", "agreement":
{ "client_thing_pub", "grant", "receipt" } | null }` (`null` only for basis `agreement` without a customer signer)

- `thing`: the Thing's latest revision (LP 0.1 §3, provider-signed) — `closed_at` set.
- `anchor`: the State that closed it (LP 0.1 §4, provider-signed, `status` CLOSED, `timestamp` = `thing.closed_at`).
- `result`: `line` — the LP 0.1 Result (§9, both signatures) that made `anchor`; `request_answer` — the `lp02.result/1`
  Result (§12) whose agreement closed the Thing.
- `agreement`: the authority the customer agreed under: the provider-signed Grant and Redemption Receipt that bound the
  customer's key, and that public key (the key current at the agreement — after a device move, an earlier one).

Nothing else: no State chain, no other revision or Grant, no audit trail, no Line content, no question history, no
capability secret. (The full `lyne-result-export/1` remains the provider's record; it now carries every bound public key
and this proof — block 49A.)

### 15.2 Verifying (first failure wins)

1. Members, `kind`, `basis` — else `PROOF_INVALID`.
2. `thing` (lp_version 0.1) verifies with `thing.provider_pub` — else `PROOF_SIGNATURE`.
3. `thing.closed_at` is set — else `PROOF_NOT_CLOSED`.
4. `anchor` is this Thing's and verifies with the provider key — else `PROOF_SIGNATURE`; it is CLOSED at `closed_at` —
   else `PROOF_ANCHOR`.
5. `grant`: this Thing, issuer = the provider key, verifies; `receipt`: of that Grant, this Thing, `client_kid` =
   kid(`client_thing_pub`), verifies — else `PROOF_AUTHORITY`.
6. `line`: `result` of this Thing and of that Grant (`PROOF_SCOPE`); `provider_sig` and `client_thing_sig` verify
   (`PROOF_SIGNATURE`); `anchor.result_id` = `result.result_id` and `anchor` carries `result.next_state` (`PROOF_ANCHOR`);
   agreed at or after the binding (`PROOF_AUTHORITY`).
   `request_answer`: `result.v` (`MODULE_VERSION_UNSUPPORTED` / `PROOF_INVALID`); this Thing and the Grant's `aud`
   (`PROOF_SCOPE`); `result.epoch` = the Grant's epoch (`PROOF_AUTHORITY`); §12.3 rules 1–10 with the binding
   `{ epoch, client_pub, bound_at: receipt.bound_at }` (their codes) — the question, its options, the conclusion mapping,
   the customer's choice, signature and answer time, the provider's signature and the outcome; answered no earlier than
   the binding minus the §2.3 skew (`PROOF_AUTHORITY`); `anchor.result_id` null and `anchor` made in the same step
   (`issued_at` ≤ `timestamp` ≤ `issued_at` + 300 s) — else `PROOF_ANCHOR`.
   `agreement` (block 55): `result.v` as above; this Thing and the Grant's `aud` (`PROOF_SCOPE`); `epoch` = the Grant's
   (`PROOF_AUTHORITY`); §17.3 rules 1–8 with the customer binding (their codes); the anchor as for `request_answer`.
   With `agreement: null` steps 5 and the Grant checks are skipped and a customer signer is `KEY_MISMATCH`.

Result: `{ outcome, basis, thing_id, title, provider_kid, client_kid, agreed_at, closed_at, version }` (+ `roles` for
`agreement`; `client_kid` null without a customer signer). **Singularity**:
the anchor is the Thing's closing; a CLOSED Thing has no later State (LP 0.1) and at most one async Result (§12.4).
A proof made by another provider verifies as THAT provider's: a relying party compares `provider_kid`.

### 15.3 Runtimes

`GET <aud>/t/<thing_id>/result-proof` (the bound key, §2.3) and the provider's own API return it for a Thing closed by
an agreement, else `PROOF_NOT_AVAILABLE` (409). The customer's page offers **SAVE VERIFIED RESULT** for a CLOSED Thing and
**MOVE TO A NEW DEVICE** only for an active one; `/proof` checks a saved file in the browser and sends nothing.

## 16. Module `lp02.nonce` /1 — many legitimate requests from one key in one second (block 50)

LP 0.1 §6.5 makes `created` plus the (deterministic Ed25519) signature the replay key: a key gets one fresh signature
per request target per second. Agents cannot wait for the next second. This module separates what LP 0.1 mixes:

**CREATED** = freshness (±300 s) · **NONCE** = uniqueness per key · **RATE LIMIT** = resource and attention policy
(unchanged) · **AUTHORITY** = Grant and policy (unchanged). A valid signature is never an authorized action.

(The module id is `lp02.nonce`, not `lp02.http-nonce`: module ids are `lp02.[a-z]{1,32}` (§3) and a hyphenated id would
make every existing LP 0.2 peer refuse the whole federation document.)

### 16.1 The profile (exactly)

`sig1=("@method" "@target-uri"[ "content-digest"]);created=<int>;nonce="<n>";keyid="<kid>";alg="ed25519"` — this order
only. `<n>`: 16 bytes from a cryptographically secure source made by the signing endpoint, base64url without padding —
22 characters, the canonical spelling (the last character carries two zero bits); no meaning (not a user, an identity
or an address). A key never reuses a nonce.

### 16.2 Verifying (first failure wins)

0. Negotiation: the bound client declared `lp02.nonce` (§3.3). Not negotiated: a request carrying a nonce is
   `MODULE_NOT_NEGOTIATED` (409); one without follows LP 0.1 §6.5 unchanged. Negotiated: a request without a nonce is
   `NONCE_REQUIRED` (401) — never a silent downgrade.
1. The headers match the profile exactly — else `SIGNATURE_INVALID`.
2. `keyid` is the bound key (or, for a delegate, the chain's leaf key) — else `KEY_MISMATCH`.
3. `created` within now − 300 … now + 300 — else `SIGNATURE_INVALID` (a fresh nonce never makes an old request fresh).
4. The nonce is canonical — else `NONCE_INVALID` (400).
5. content-digest (§2.3) — else `DIGEST_MISMATCH`.
6. The signature verifies over the parameters including the nonce — else `SIGNATURE_INVALID`.
7. (key, nonce) unused — else `NONCE_REPLAYED` (401), whatever is signed with it this time. Then it is recorded.

Replay model: the runtime keeps `SHA-256("lp02.nonce/1|kid|nonce")` (a fingerprint — never the nonce, the request or its
content) until `created` + 600 s. For a **state-changing** request (POST) it is kept in persistent storage — a captured
mutation never succeeds twice, a restart included; for a **safe read** (GET) in memory only — after a restart the same
read is answered again (harmless, specified). Storage is bounded: full after pruning → `BUSY` (503), never "accept
unchecked".

### 16.2a One profile, two layers (block 54)

The check of §16.2 rules 1–7 is a signed-request profile, not an LP idea: the same profile serves a runtime's own Agent
API as the LAP agent request-signing profile `lap-sig/2` (chosen per agent registration; no LP negotiation, because
that API is not an LP route). One validator, one replay memory per runtime (a key never reuses a nonce, whatever it
signs), one refusal order and one set of codes; each layer adds only its own authorization before or after it.

### 16.3 What keeps its own profile

The concluding answer (§12 — its signature is the agreement's evidence, a person's act) and the recovery move (§14 —
signed by the recovery key, its refusal order fixed by §14.2) keep their profiles; a nonce there is `NONCE_NOT_HERE`
(400). Rate limits, admission, question, attention and Grant limits are not changed by this module.

## 17. Module `lp02.agreement` /1 — a Result several actors agree to (block 55)

Not a group and not a conversation: a **state and authority rule**. One Thing, one agreement question, a policy fixed
before anyone signs, one signature per required actor, ONE Result. Depends on `lp02.federation` and `lp02.request`.

### 17.1 Objects

**Agreement question** = the §12 question members plus `policy`:
`{ request_id, thing_id, template, label, options, conclusion, policy, deadline, created_at }` (§12.1 rules for the
others). **Policy** (structure only, no free text):

`{ "requirements": [ { "roles": [<code>, …], "min": <n> }, … ] }` — 1–4 requirements; each 1–6 roles, codes
(`[a-z][a-z0-9._-]{0,31}`), sorted ascending, no duplicates; `min` 1–12. **Met** when EVERY requirement has at least
`min` **distinct signer keys** holding one of its roles. ALL = one requirement per role; ANY-of = one requirement,
`min` 1; M-of-N = one requirement, `min` M. Roles: `customer` (the bound client key), `provider` (counted once, by the
provider's own signature on the Result — never a signer entry), or a role of the Thing's seats (block 28).

**Signed body** (what an actor signs): `JCS({ "v": "lp02.agreement/1", "question": b64url(SHA-256(JCS(question))),
"role": <the actor's role> })`, sent as `POST <aud>/t/<thing_id>/agreements/<request_id>/sign/<option>` with an RFC 9421
signature (§2.3, content-digest, **no nonce** — §16.3) by the actor's own key. The role is inside the signature: a
signature for one role is never another role's.

**Signer entry** — exactly one of:
- answer: `{ basis: "answer", role, pub, created, signature_input, signature }` — the actor's RFC 9421 signature;
- line: `{ basis: "line", role: "customer", pub, result }` — an LP 0.1 Line Result (§9, both signatures) with
  `outcome` `agreed` and `summary` exactly `"<question label>: <option label>"` (≤ 280) stands for the customer.

**Result** (`typ lp02.agreement`, provider-signed, JCS+JWS): exactly `{ v, result_id, thing_id, aud, outcome, option,
epoch, issued_at, question, signers, signature }`; `outcome` = `conclusion[option]`; `signers` 1–12, sorted by
`role` + kid(`pub`), one entry per key; at most one `customer`.

### 17.2 Who signs, and how long it counts

The customer (the bound key, which declared `lp02.agreement`) or an ACTIVE seat key of the Thing (its role is the seat's
role). **A delegate never signs** (`lyne-delegation` → `DELEGATION_DENIED`): capability is not authority, and no
delegation action agrees (§13). A signature counts only while its authority holds: a customer key no longer bound
(a device move) or a seat removed or left stops counting — revoked authority never returns. A CLOSED Thing keeps no
seats: after CLOSED no seat signature counts (found by the state model, block 57B). Several representatives may
sign; each key counts once. The first option, in question order, whose counting signers meet the policy is decided: the
Result is issued and the Thing CLOSED **atomically** (one request at a time per Thing); every later signature,
submission or other outcome meets `REQUEST_DECIDED`; one per Thing (`AGREEMENT_OPEN` while one is open, `RESULT_EXISTS`
after).

### 17.3 Verification (any party; first failure wins)

1. Shape: members exact, types exact (a pattern is tested only on a string), question and policy valid, signer entries
   exact, no signer with role `provider` — else `AGREEMENT_INVALID` (400); another `lp02.agreement/<n>` —
   `MODULE_VERSION_UNSUPPORTED`.
2. The provider's signature (`typ lp02.agreement`) — else `SIGNATURE_INVALID`.
3. This Thing and `aud`, and the question's Thing — else `RESULT_SCOPE`.
4. `option` is an option (`OPTION_UNKNOWN`), concludes (`RESULT_NOT_AGREED`), `outcome` = its conclusion
   (`RESULT_OUTCOME_MISMATCH`).
5. Signer keys distinct and in canonical order — else `AGREEMENT_INVALID`.
6. Each signer's evidence: answer — its RFC 9421 signature over the signed body for ITS role, this question and this
   option (`RESULT_BASIS_INVALID`), `created` within question `created_at` − 300 … `deadline` + 300 and ≤ `issued_at` +
   300 (`RESULT_STALE`); line — role customer, this Thing, `agreed`, the exact summary, both signatures
   (`RESULT_BASIS_INVALID`).
7. The customer signer is the key bound at `epoch` — else `KEY_MISMATCH`.
8. The policy, as declared in the question everyone signed, with the provider counted once — else `POLICY_NOT_MET`.
9. Not after a closure it did not make — `THING_CLOSED`; 10. one per Thing — `RESULT_EXISTS`.

Lowering a threshold, adding a role, swapping an option or a role after signing changes the question or the signed
body: every actor's signature fails (rule 6). A provider that re-signs cannot invent consent.

### 17.4 Runtime routes

`POST <aud>/api/provider/things/<id>/agreements` `{ template, policy }` (provider; template with a conclusion; roles
the provider has) · `GET <aud>/t/<id>/agreements` (an actor reads the exact question and which roles have signed — no
names, keys or words) · `POST …/agreements/<rid>/sign/<option>` · `POST <aud>/api/provider/things/<id>/agreements/<rid>/line/<result_id>`
(the provider counts a Line Result as the customer's) · `GET <aud>/t/<id>/agreement-result`. The proof (§15) carries
basis `agreement`.

## 18. Trust without global identity (block 56)

There is no directory, no global name and no search for a person. What a party can know about another is what it can
verify — a key, an origin, a signature, freshness, its own earlier relationship — and what it can be told by someone it
already has a relationship with. Everything else is a **claim**.

**Times (all modules).** A time member is valid only if it matches `YYYY-MM-DDThh:mm:ssZ` **and** is a real calendar
time: `2026-02-30T00:00:00Z` matches the pattern and is no time — it is refused as the member's module refuses a bad
time, never read as another day. **Patterns** are tested only on strings (§17.3 rule 1 holds for every module).

### 18.1 Trust view (verified apart from claimed)

For a descriptor (§4.1, signed) or a point view (§4.1, unsigned, served over TLS) that a device fetched from origin `F`,
with the person's own pins `[{ origin, provider_pub }]` (the keys of its earlier relationships), first failure wins:

1. `provider_pub` 43 b64url characters and `aud` an origin — else `TRUST_INVALID` (400). An origin is `https://` +
   lower-case ASCII host (punycode, never a look-alike letter) + optional port; `http://localhost` and
   `http://127.0.0.1` only for tests.
2. `aud` = `F` — else `TRUST_ORIGIN_MISMATCH` (409): a genuine description re-served elsewhere is someone else's copy.
3. A descriptor's signature (`typ lp02.descriptor`) — else `SIGNATURE_INVALID`.
4. `valid_until` a time in the future — else `FED_DOC_STALE`.
5. A pin for `aud` with another key — `KEY_MISMATCH` (403): a known origin presenting a new key is never silently
   accepted.

Result: `{ verified: { origin, provider_kid, signed, fresh_until, known: "pinned" | "new", same_key_at: [origins] },
claimed: { tenant?, label?, service?, purposes?, points? } }`. **Nothing called a name is ever verified**: a company
name, a label or a service is shown as the publisher's claim, next to the key and origin that are verified.

### 18.2 Module `lp02.introduction` /1 — trust by context

An **introduction** (`typ lp02.introduction`) is signed by one party of a Thing for the other: exactly `{ v, intro_id,
thing_id, aud, by: "provider" | "client", target: { aud, point_id, provider_pub }, purpose, issued_at, exp, signature }`;
`exp` > `issued_at`, at most 7 days later. It names a point and a key — **never a person, a name or a text**. It is
evidence for the person, **not admission authority**: opening the target still follows the target point's own policy.

Verification on the person's device, with its OWN Thing `{ thing_id, aud, provider_pub, client_pub }` (first failure wins):

1. Shape — else `INTRO_INVALID` (400); another `lp02.introduction/<n>` — `MODULE_VERSION_UNSUPPORTED`.
2. `thing_id` and `aud` are this Thing's — else `INTRO_SCOPE` (409).
3. The signature with the key of `by` **in this Thing** (never a key the introduction names) — else `SIGNATURE_INVALID`.
4. `issued_at` ≤ now + 300 and `exp` > now — else `INTRO_EXPIRED` (403).
5. (After fetching the target's point view from `target.aud`:) fetched from `target.aud`, and its `aud`, `point_id`
   and `provider_pub` are the target's — else `INTRO_TARGET_MISMATCH` (409).
6. The point is open now (`OPEN_POINT_UNKNOWN`) for the purpose (`OPEN_PURPOSE_UNKNOWN`).

**Why not §8 (referral)**: a referral is verified by the RECEIVING provider (its pinned peers) and gives admission; it
needs operator-level pins and names no target key, so it cannot tell a person that the page in front of them is the one
their contact meant. An introduction is verified by the person's device and binds the target key.

Runtime: `POST <aud>/api/provider/things/<id>/introductions` `{ target, purpose, [valid_seconds 300…604800] }` (the
provider, for its bound client; at most 3 live per Thing; extra members refused) · `GET <aud>/t/<id>/introductions`
(the bound client, which declared `lp02.introduction`). A person's runtime: `POST /api/me/things/<id>/introduce`;
`GET /api/me/things/<id>/introductions` (verified on the device, VERIFIED apart from CLAIMED);
`POST /api/me/things/<id>/introductions/<intro_id>/open` (opens as a human, the introduced key required).

### 18.3 Claims are not authority

An agent's display name, a declared capability (`svc:…`, an agent card's skills), a descriptor's label or a point's
service grant nothing: authority is the bound key, a seat's role, a delegation chain (§13) or the owner's explicit
policy. An agent never signs an agreement (§17.2) and is never an introducer (§18.2 `by`).

## 19. Module `lp02.channel` /2 — runtime-minted Endpoints, no cross-Thing oracle (candidate-3)

Adopted into `lp02-private-candidate-3` (MASTER, 2026-10-08), replacing candidate-2's `lp02.channel/1`. Depends on `lp02.federation`; a client-side module (§1, §3.3). This candidate defines **version 2 only**. Its errors are in §10, its conformance ops in `conformance/DRIVER.md`.

#### What changed from candidate-2's /1, and why

**R-1 (MASTER, rejected).** In `/1` an actor chose its own `endpoint_ref`. To stop references linking Things, the
runtime refused a reference already in use elsewhere (`ENDPOINT_CORRELATED`). That refusal is itself a cross-Thing
liveness oracle: whoever legitimately learned a reference could test whether it is still in use somewhere else.

`/2` removes the oracle **by construction**:

1. **An actor never supplies an Endpoint reference.** An offer names, per route, an opaque **binding**: the handle
   its own transport adapter issued when the actor registered an address there.
2. **The trusted runtime mints every `endpoint_ref`.**
   - From a CSPRNG with at least 128 bits of entropy.
   - Fresh per Thing, per actor and per offer generation, so it rotates on every replacement.
   - Never derived from the address or the binding, never searchable, never an identity.
3. **No index of references across Things exists, so no answer about one can exist.** `ENDPOINT_CORRELATED` and
   `ENDPOINT_REUSED` are gone.
   - A reference presented where it is not offered is refused with the **same** code as any other, `ROUTE_NOT_OFFERED`: a foreign, random, expired or withdrawn reference alike.
   - A reference presented as a binding is `BINDING_UNKNOWN`, like any other string.
4. **The same real address in two Things** (a person's one e-mail) gives two **unrelated** references. The adapter
   knows the address; LYNE's core never does.

Everything else of `/1` — deliveries, attempts, receipts, retention, visibility — is unchanged except the version
string `lp02.channel/2`.

### 19.0 The rule

**THING IS THE CONTEXT. CHANNEL IS HOW A TRANSIENT EXCHANGE IS CARRIED. STATE + RESULT ARE WHAT PERSIST.**

| object | role | lifetime |
|---|---|---|
| THING | relationship context and authority | persistent (LP 0.1) |
| STATE | what is true now, who waits on whom, the next action | persistent (LP 0.1) |
| GRANT | authority | LP 0.1 rules |
| LINE | the bounded live interaction, where one applies | LP 0.1 rules |
| RESULT | the agreed persistent outcome | persistent (LP 0.1) |
| **CHANNEL** | a transport **class**: `data`, `voice`, `video`, `agent`, `api`, `email`, `sms`, `tel`, `messaging`, `sensor`, `device`, or a future class | a name, not an object |
| **ENDPOINT** | an **opaque**, Thing-scoped reference an actor offers, behind which an adapter reaches it | current only; at most 30 days; replaced, never appended |
| **ROUTE** | the choice of one Channel and one offered Endpoint for one transport action | the length of one attempt |
| **DELIVERY** | the bounded attempt to carry one ephemeral payload, and its outcome | at most `exp` + 300 s, then deleted |
| **RELAY** | a component that carries a Delivery; never trusted for authenticity | — |

**Why not a Thread.** A Thread was a persistent, ordered, hash-chained list of who addressed whom, with what intent
and which content digest. Even without plaintext, that is a conversation history, an inbox and a social graph under
another name. In LYNE the **Thing** already is the context. What must persist is decided **State** and the agreed
**Result**, never the exchanges that led to them. This module therefore has **no order, no chain, no event, no
history and no persistent per-exchange record**.

### 19.1 Endpoint offer (typ `lp02.endpoint-offer`) — the only object that outlives a Delivery

An actor of a Thing says how it may currently be reached **for this Thing**:

```json
{ "v": "lp02.channel/2", "thing_id", "actor": { "role", "kid" },
  "routes": [ { "channel", "binding", "expires_at" } … ],   // 0–8; [] withdraws every route
  "issued_at", "expires_at", "signature" }
```

- `channel` is a class token `^[a-z][a-z0-9.-]{0,31}$`.
  - **Registered classes:** `data`, `voice`, `video`, `agent`, `api`, `email`, `sms`, `tel`, `messaging`, `sensor`,
    `device`.
  - **Future classes:** an unknown token is **kept** in the offer (forward compatibility) but cannot be used for an
    attempt by a runtime that does not support it (`CHANNEL_UNSUPPORTED`).
- `binding` is an **opaque handle** `^[A-Za-z0-9_-]{16,64}$` that the actor's own transport adapter issued when the
  actor registered an address with it.
  - It is **not an address.** The e-mail address, phone number, URL or handle stays inside the adapter. An address-like
    value is refused (`ENDPOINT_EXPOSED`).
  - It is **not an Endpoint.** It never appears in a delivery, an attempt, a resolve answer or the record. It is used
    once, to mint, and is known only to the actor and its adapter.
  - The same binding may be used in several Things: the minted references stay unrelated (point 4 above).
- **Lifetime.** `expires_at` ≤ `issued_at` + 30 days; each route's `expires_at` ≤ the offer's.
- **Current only.** An accepted offer **replaces** the actor's previous offer entirely. Nothing of the previous one is
  kept, and an older offer is refused (`OFFER_STALE`, a ratchet on `issued_at`). An offer is deleted at expiry, at
  revocation of the actor's key, and when the Thing closes.
- **Signature.** The offer is signed by the actor's key in the Thing (§19.2.2 module JWS).

#### Minting (the runtime)

On accept, the runtime mints for **each** route a fresh `endpoint_ref` `^[A-Za-z0-9_-]{22}$`:

- **Production:** 16 bytes from a cryptographically secure random generator, base64url without padding.
- **Never** derived from the binding, the address, the actor, the Thing or a counter visible to anyone.
- **Internal invariant:** a minted reference equal to one current in this runtime is discarded and minted again. That
  check is internal only and never visible to any party.
- **Conformance mode only (deterministic, so that implementations can be compared):** the n-th reference an instance
  mints (n = 0, 1, … in accept order, routes in their order) is
  `b64u(SHA-256("LP02 TEST MINT " + context.mint_seed + " " + n))` truncated to 22 characters. A production runtime
  never uses this.

Accept result: `{ "actor": kid, "generation": g, "routes": [ { "channel", "endpoint_ref" } … ] }` in the order of the
offer's routes. `g` is the previous current offer's generation + 1, or 1. The actor learns its own references; the
adapter links each reference to the binding internally.

#### Posting an offer (first failure wins)

1. **Module.** Not negotiated with this party (`context.negotiated` false: an LP 0.1 peer) →
   `MODULE_NOT_NEGOTIATED` (409).
2. **Version.** `v` is `lp02.channel/<n>` with n ≠ 2 → `MODULE_VERSION_UNSUPPORTED` (400). A `/1` object is never
   read as `/2`.
3. **Shape** → `OFFER_INVALID` (400) for any of:
   - members, types, patterns or lifetimes other than above, including an `endpoint_ref` member (an actor never
     supplies one);
   - a §2.1.6 forbidden member name at any depth;
   - a duplicate `binding`.
4. **Binding.** An address-like `binding` (containing `@`, `+`, `:`, `/` or `.`) → `ENDPOINT_EXPOSED` (400).
   Otherwise one not matching the opaque pattern → `OFFER_INVALID`.
5. **Thing.**
   - Another Thing → `CHANNEL_THING_MISMATCH` (409).
   - A CLOSED Thing → `THING_CLOSED` (409).
6. **Actor.**
   - Not a party in that role → `ACTOR_UNKNOWN` (403).
   - Revoked (LP 0.1 §10.4) → `KEY_REVOKED` (403).
7. **Signature.** Header `{alg, kid, typ: "lp02.endpoint-offer"}` by the actor's key → else `SIGNATURE_INVALID` (401).
8. **Time.** `expires_at` ≤ now, or `issued_at` > now + 60 → `OFFER_STALE` (409).
9. **Ratchet.** A current offer of this actor with `issued_at` ≥ this one → `OFFER_STALE` (409).
10. **Binding known.** A `binding` that this actor's adapter did not issue to **this actor**
    (`context.bindings[kid]` in conformance) → `BINDING_UNKNOWN` (400).
    - The refusal is identical for a random string, another actor's binding and an Endpoint reference minted anywhere.
11. **Accept.** The previous offer is dropped and the adapters forget its references. Fresh references are minted and
    the result is returned.

#### Who may see an offer (V3 — authority-scoped visibility)

An offer is **not** general Thing metadata. Its transport classes and references are resolved (`ch2.resolve`) only by:

1. **the actor who owns it** — its own routes;
2. **an actor currently authorized to deliver to that actor** — the sender of an **open** delivery to it, for that
   delivery and while it is open;
3. **the minimum routing component** that performs that delivery — the runtime's own adapter layer, internally.

Anyone else gets `OFFER_NOT_VISIBLE` (403). That includes another actor of the same Thing, a sender whose delivery has
closed, or a sender naming another actor's delivery. The refusal is the same whether or not the target has an offer,
so that probing reveals nothing.

- **No roster-wide view.** A multi-actor Thing exposes no list of every actor's transport classes, and there is no
  actor-global transport profile.
- **The record view is not an actor view.** `ch2.record` (§19.5) is the storage inspection of a conformance observer or
  operator, never an actor API.

**Runtime policy (V3).** The protocol maximum lifetime of an offer stays 30 days: a long-lived device (a sensor, a
robot) may need it. A runtime MAY enforce a shorter maximum, and SHOULD default to **24 hours**, allowing longer only
where a Thing or tenant enables an explicit use case. An offer above the runtime maximum is `OFFER_INVALID`. Expiry
removes the offer automatically.

#### Resolving an offer (first failure wins)

`ch2.resolve` takes `{ requester: { role, kid }, target: { role, kid }, delivery_id? }`. The requester is the
authenticated party of the request: an RFC 9421 Thing-key request, or the provider.

1. The module is not negotiated → `MODULE_NOT_NEGOTIATED` (409).
2. The requester is not a party in that role → `ACTOR_UNKNOWN` (403); its key is revoked → `KEY_REVOKED` (403).
3. The requester is the target → `{ "routes": [ … ] }`, its own current, unexpired routes (`[]` when it has none).
4. Otherwise `delivery_id` must name an **open** delivery whose `from` is the requester and whose `to` is the target →
   `{ "routes": [ … ] }`, the target's current, unexpired routes.
5. Otherwise → `OFFER_NOT_VISIBLE` (403).

Routes are listed as `{ "channel", "endpoint_ref" }`, sorted by channel, then by reference.

### 19.2 Delivery request (typ `lp02.delivery`) — ephemeral

```json
{ "v": "lp02.channel/2", "thing_id", "delivery_id", "from": { "role", "kid" }, "to": { "role", "kid" },
  "payload_digest", "created", "exp", "signature" }
```

- **No channel, route, endpoint or relay member.** The Route is chosen per attempt (§19.3), so a route change never
  changes the delivery.
- **No order or history member.** There is no `seq`, `prev`, thread or reply-to member.
- **The payload travels on the Channel.** `payload_digest` = b64u(SHA-256(JCS(payload))). The digest exists **only**
  for integrity and deduplication while the delivery is active.

#### Sending (first failure wins)

1. **Module.** Not negotiated → `MODULE_NOT_NEGOTIATED` (409).
2. **Shape** → `DELIVERY_INVALID` (400) for any of:
   - exact members;
   - a §2.1.6 forbidden name;
   - any member named `channel`, `route`, `endpoint`, `endpoint_ref`, `relay`, `seq`, `prev`, `thread_id` or
     `reply_to` at any depth.
3. **Thing.**
   - Another Thing → `CHANNEL_THING_MISMATCH` (409).
   - CLOSED → `THING_CLOSED` (409).
4. **Parties.**
   - `from` is not a party in that role → `ACTOR_UNKNOWN` (403); revoked → `KEY_REVOKED` (403).
   - `to` is not a party in that role, or is `from` → `RECIPIENT_INVALID` (400).
5. **Signature.** By `from`'s key, `typ` `lp02.delivery` → else `SIGNATURE_INVALID` (401).
6. **Time.** `exp` ≤ now, `created` > now + 60, or `exp` − `created` > 600 → `DELIVERY_EXPIRED` (409).
7. **Payload.** Present and its digest ≠ `payload_digest` → `PAYLOAD_DIGEST_MISMATCH` (400).
8. **Duplicates.** `delivery_id` is retained:
   - the identical request (same signature) → **IGNORE** (idempotent);
   - otherwise → `DELIVERY_REPLAY` (409).
9. **Route.** The recipient has no current, unexpired route → `NO_ROUTE` (409). The Thing, its State and its Results
   are unaffected: no transport is not an error of the relationship.
10. **Rate.** The sender already has 100 accepted deliveries in the last 60 s in this Thing → `RATE_LIMITED` (429).
11. **Accept.** Result: `{ "delivery_id", "routes": number of current routes of the recipient }`.

### 19.3 Attempt — a Route for one transport action

```json
{ "v": "lp02.channel/2", "delivery_id", "attempt": 1…, "route": { "channel", "endpoint_ref", "relay"? },
  "status": "QUEUED" | "SENT" | "FAILED", "at" }
```

1. **Shape.**
   - Not as above → `DELIVERY_INVALID` (400).
   - `status` `DELIVERED` → `RECEIPT_REQUIRED` (409). **Only the recipient's signed receipt delivers**; a relay or
     adapter cannot claim it.
2. **Delivery.**
   - Not known (never sent, or already purged) → `DELIVERY_UNKNOWN` (404).
   - Known but closed (`exp` ≤ now) → `DELIVERY_EXPIRED` (409).
   A delivery is **open** while now < `exp`, **retained** until `exp` + 300 s, and then purged.
3. **Channel.** Not supported (not a registered class) → `CHANNEL_UNSUPPORTED` (400).
4. **Endpoint.** Address-like `endpoint_ref` → `ENDPOINT_EXPOSED` (400).
5. **Route offered.** The (`channel`, `endpoint_ref`) is not a current, unexpired route of the **recipient's** offer
   **in this Thing** → `ROUTE_NOT_OFFERED` (403).
   - A relay cannot invent a destination.
   - A reference minted in another Thing, by another tenant, for another actor, an expired or withdrawn one, and a random string all get exactly this refusal, with no other member: **no answer distinguishes them** (§19.0 R-1).
6. **Order** → `ATTEMPT_ORDER` (409) if:
   - the delivery is already DELIVERED;
   - `attempt` is neither the current attempt nor current + 1;
   - a status moves backwards (QUEUED → SENT; FAILED is final for that attempt).
7. **Accept.** Result: `{ "attempt", "status" }`. Several attempts over different Routes are **one** delivery.

### 19.4 Receipt (typ `lp02.delivery-receipt`) — ephemeral

`{ "v", "thing_id", "delivery_id", "by": { "role", "kid" }, "payload_digest", "received_at", "signature" }`, signed
by the recipient.

| check | code |
|---|---|
| shape | `RECEIPT_INVALID` (400) |
| delivery not known / closed | `DELIVERY_UNKNOWN` (404) / `DELIVERY_EXPIRED` (409) |
| `by` ≠ the delivery's `to` | `RECEIPT_INVALID` |
| signature | `SIGNATURE_INVALID` (401) |
| `payload_digest` ≠ the request's (a payload altered on the way) | `PAYLOAD_DIGEST_MISMATCH` (400) |
| already DELIVERED, same receipt | **IGNORE** |

Accept → the delivery is DELIVERED. Result: `{ "delivery_id", "status": "DELIVERED" }`.

### 19.5 Retention — what persists and what does not

| data | kept | deleted |
|---|---|---|
| **Endpoint offer** (current reachability per actor per Thing) | while current | at replacement (nothing of the old one), expiry (≤ 30 days), key revocation, Thing closure |
| Delivery request, its `payload_digest`, attempts, receipt, the `delivery_id` replay entry | while open, then retained | **at `exp` + 300 s at the latest** (≤ 900 s after `created`) |
| Rate counters | count per sender per 60 s window | with the window |
| **Payload** (the content) | **never** by a LYNE runtime; it is the Channel's payload | — |
| Outcome of an exchange | only as **State** or **Result** (LP 0.1 / candidate), when the parties make it one | LP 0.1 rules |

**Why a digest does not persist.** A digest proves *what* was carried, but only while it can be compared with what
arrives (integrity) or with what arrives again (deduplication). After `exp` no arrival is acceptable, so neither need
remains. A permanently kept digest would instead let anyone who later sees a candidate text confirm that it was said:
a reconstructable conversation. Disputes about what was agreed are settled by a **Result**, which the parties sign
for exactly that purpose.

**Why a `delivery_id` does not persist.** Replay protection needs it only until `exp`: after that, step 6 refuses the
request anyway.

**No audit leak (V3).** Channel classes, endpoint references, routes, payload digests, sender–recipient pairs and
delivery chronology are never copied into a persistent audit record. An operational fact, if one is needed at all,
is structural and unattributed: a counter such as "delivery authority used", with no Thing, actor, time or transport.

**The persistent record view** (`ch2.record`, an observer's storage inspection — §19.1) is
`{ "thing_id", "offers": [ { "actor": kid, "channels": [ … ] } ], "active_deliveries", "retained_digests",
"content_retained": false }`. `active_deliveries` counts the retained deliveries; after the retention window `active_deliveries` = `retained_digests` = 0. Nothing in it
says who sent what to whom, or when.

### 19.6 Minimum structural evidence, and its adversarial review

| need | evidence | its lifetime |
|---|---|---|
| delivery success / failure | attempt statuses, the signed receipt | ≤ `exp` + 300 s |
| retry | attempt numbers on one `delivery_id` | ≤ `exp` + 300 s |
| duplicate prevention | `delivery_id` + `payload_digest` | ≤ `exp` + 300 s |
| replay protection | the active `delivery_id` set; `exp` | ≤ `exp` + 300 s |
| authority validation | LP 0.1 Binding / epoch / revocation; the signatures | LP 0.1 |
| abuse control | per-sender counter per 60 s | 60 s |
| dispute / audit | **State and Result** | LP 0.1 |

Adversarial questions, answered by the rules above:

- **Can this evidence recreate who said what when?** Only inside a window of at most 900 s, for deliveries still
  active, and never the content. After that, no.
- **Can it recreate a conversation graph?** It cannot persist anything per exchange. The current offers say only which
  transport *classes* each actor of one Thing currently accepts.
- **Can it be used as an inbox?** No: nothing is stored to be read later; the payload is never stored.
- **Can it become surveillance metadata?**
  - Endpoint references are minted by the runtime, fresh per Thing, actor and generation; no index across Things exists and
    no answer reveals a reference's use elsewhere (§19.1 Minting, §19.3 step 5).
  - An offer holds no address.
  - Offers are current-only and expire.

### 19.7 Legacy transport adapters

An adapter for e-mail, SMS, the telephone network or an existing messaging system holds the real address inside its
own boundary.
- The actor registers its address **with the adapter**, which returns an opaque `binding`.
- The actor names that binding in its offer.
- The runtime mints the `endpoint_ref`, and the adapter links it to the binding.
- LYNE's core sees only references, never the address or the link.

**Replacing an adapter** — for example, e-mail by an agent:

- the actor posts a new offer;
- the old route stops being routable at once (`ROUTE_NOT_OFFERED`);
- Thing, actor identity, State and Result are unchanged.

### 19.8 Errors

The 20 codes of this module are registered in §10. `RATE_LIMITED` (429) is the same code, with the same status, as candidate-1's resource refusal (§14.2 rule 12). `ENDPOINT_CORRELATED` and `ENDPOINT_REUSED` (candidate-2's `lp02.channel/1`) do not exist in this candidate.

### 19.9 Compatibility and versions

- **LP 0.1 is untouched.** Its Grant member `channels` names a Live Line's media channels and is unrelated.
  An LP 0.1 peer never negotiates this module: every operation with it is `MODULE_NOT_NEGOTIATED`.
- **/1 and /2 are different versions of one module id** (`lp02.channel`). Negotiation (§19.3.2) picks the highest
  **common** version.
  - A party that supports only `/1` and one that supports only `/2` have no common version: the module is absent.
    Requiring it is `MODULE_UNSUPPORTED`.
  - A `/1` object sent to a `/2`-only runtime is `MODULE_VERSION_UNSUPPORTED`. Nothing is converted or guessed.
  - **No silent substitution** in either direction.
- **Candidate-2 is unchanged** (it defines `/1`). A successor candidate defines `/2` only: `/2` creates no permanent
  dual-version debt, because `/1` was never public.
- **A Live Line can be one Channel** (`voice` / `video` / `data`), under LP 0.1's own rules.

### 19.10 Conformance

Ops `ch2.offer`, `ch2.send`, `ch2.attempt`, `ch2.receipt`, `ch2.tick`, `ch2.resolve`, `ch2.record` (an observer inspection, never an actor API) and `ch2.sign`: `conformance/DRIVER.md`. Vectors: `vectors/channel2-vectors.json`.

## 20. Module `lp02.liveline` /1 — the Live Line WebRTC data-channel profile (candidate-4)

Adopted into `lp02-private-candidate-4` (MASTER, 2026-10-08), closing LP02-B1. A client-side module depending on `lp02.federation` (§1, §3.3). LP 0.1 §8.3 is unchanged: this module does not claim that the creation parameters were ever normative in LP 0.1; it fixes them only between parties that negotiated it. Errors in §10, conformance ops in `conformance/DRIVER.md`.

#### Why a module (and not a change to LP 0.1)

- **What LP 0.1 fixes.** LP 0.1 §8.3 names the two data channels of a Live Line by their **labels**:
  - `lyne-control` on every Line;
  - `lyne-data` when the Grant's `channels` include `data`.

  It does **not** fix how they are created: negotiated or in-band (DCEP), stream ids, ordering, reliability. Two LP 0.1 endpoints can therefore both be "compliant" and still fail to meet.
- **LP 0.1 stays as it is.** This module does not claim that these creation parameters were ever normative in LP 0.1.
- **Why the existing places do not fit.** LP 0.1 §8 is frozen. `lp02.linecaps` cannot carry the profile: it is negotiated *on* `lyne-data`, which does not exist on a control-only Line, and it would come too late, because the parameters must be fixed before the channels exist.
- **So the profile is a small client-side module.** It is negotiated **before** the Line with the existing mechanism (§3.2 / §3.3), and verified explicitly on the Line.

### 20.1 The profile (exact)

| | `lyne-control` | `lyne-data` |
|---|---|---|
| label | `lyne-control` | `lyne-data` |
| negotiated | `true` (created out of band by both endpoints; no DCEP `DATA_CHANNEL_OPEN`) | `true` |
| stream id | `0` | `1` |
| ordered | `true` | `true` |
| reliability | fully reliable: neither `maxRetransmits` nor `maxPacketLifeTime` is set, so both read `null` | fully reliable |
| protocol (DCEP / `RTCDataChannel.protocol`) | `""` (empty) | `""` (empty) |
| exists | on every Live Line | only when the Grant's `channels` include `data` (LP 0.1 §8.2, §8.3) |

**What a label is not.** `lyne-control` and `lyne-data` are data-channel **labels** (RFC 8831 §6.6, RFC 8832 §5.1).

- They are **not** WebSocket subprotocols, DCEP protocol registry values or IANA protocol names, and **no IANA registration is needed**.
- They are not an actor identity, not authority and not a transport address.
- The DCEP `protocol` field stays the empty string.

**Capability is not authority.** Creating a channel grants nothing. LP 0.1 §8.2 (the Grant, its `channels`, the bound
Thing-key) stays the only authority for what a Line may carry. A `lyne-data` channel without `data` in the Grant is
refused (§20.5 rule 7, `CHANNEL_NOT_GRANTED`, LP 0.1 §8.3 rule 3).

### 20.2 Negotiation (before the Line)

1. **Client endpoint.** It applies this module to a Thing iff:
   - (a) the provider's federation document, from `GET <aud>/t/<thing_id>/modules`, passes §3.2 steps 1–2, is signed by this Thing's provider key, and lists LP `"0.2"` and `lp02.liveline` version `1`;
   - (b) its own client declaration (§3.3) listing `"lp02.liveline": [1]` was accepted: the response's `declared.modules` lists it.

   Otherwise the module is not negotiated for this Thing.
2. **Provider endpoint.** It applies this module to a Thing iff its own federation document lists `lp02.liveline` version 1 **and** the stored client declaration of the Thing's current Binding lists version 1.
3. **Not negotiated.** The Line follows LP 0.1 §8.3 alone. This module makes no claim about it, and neither endpoint sends a frame of this module (an LP 0.1 or candidate-3 endpoint never sees one).
4. **A provider MAY require the profile for its Lines.** Then LP 0.1 §8.2 acceptance also requires rule 2: an offer from a client that did not declare it is refused with `MODULE_NOT_NEGOTIATED` (409), no answer is sent, and no use is consumed. A client endpoint that requires the profile and does not meet rule 1(a) does not open the Line (`MODULE_UNSUPPORTED`, 409).
5. **No silent fallback.** An endpoint that negotiated this module for a Thing MUST NOT, on any Line of that Thing:
   - fall back to in-band (DCEP) channels;
   - remap a stream id;
   - substitute unordered delivery;
   - substitute partial reliability;
   - use another `protocol` value.

   If the profile cannot be met, the Line fails explicitly (§20.5–§20.6).
6. **No asymmetric Line.** A client endpoint whose declaration listing the module was accepted (rule 1 (b)) knows that
   the provider treats the profile as negotiated. If it cannot read the provider's document at that moment (rule 1 (a)
   undecided, e.g. a network failure), it does **not** open the Line, and tries again later. A Line that one endpoint
   runs with the profile and the other without would end at `PROFILE_TIMEOUT` (§20.6 rule 4): explicitly, but avoidably.

### 20.3 Creating the channels (both endpoints, every Line)

1. **When.** Before it creates or accepts the offer of a `line_seq`, each endpoint creates, on its own `RTCPeerConnection`:
   - `lyne-control` with exactly `{ negotiated: true, id: 0, ordered: true }`;
   - and — only if the Grant's `channels` include `data` — `lyne-data` with exactly `{ negotiated: true, id: 1, ordered: true }`.

   The members `maxRetransmits`, `maxPacketLifeTime` and `protocol` are **not passed**.
2. **Self-check.** The endpoint then reads the created channels' properties: `label`, `id`, `negotiated`, `ordered`, `protocol`, `maxRetransmits`, `maxPacketLifeTime`. They must equal §1. Otherwise the endpoint MUST NOT offer or answer: `LINE_PROFILE_MISMATCH` (its own runtime cannot meet the profile). Conformance op `ll.local`.
3. **Duplicate stream id.** A second channel with an id already in use is an error of the creating endpoint (`RTCPeerConnection.createDataChannel` throws `OperationError`). It never becomes a remapped id.

### 20.4 The profile frame

**When.** Once its `lyne-control` is open, each endpoint sends one frame, as the **first** message on that channel,
before any LP 0.1 object:

```json
{"lyne":"lp02.liveline/1","t":"profile","channels":{"lyne-control":D,"lyne-data":D_or_null}}
```

**The descriptor `D`.** It describes the **sender's own observed channel**, and has exactly these members:

| member | type | profile value |
|---|---|---|
| `id` | integer 0–65534 | 0 (control), 1 (data) |
| `negotiated` | boolean | `true` |
| `ordered` | boolean | `true` |
| `protocol` | string, ≤ 255 characters | `""` |
| `maxRetransmits` | `null` or integer 0–65535 | `null` |
| `maxPacketLifeTime` | `null` or integer 0–65535 | `null` |

**Absent data.** `lyne-data` is `null` when the sender created no data channel.

**Integers.** An integer is written without a fraction or an exponent (`0`, never `0.0` or `0e0`). Any other
number makes the descriptor invalid (§20.5 rule 5), so that every implementation reads the same text the same way.

**Format.** The frame is UTF-8 JSON, at most 1024 bytes, in strict JSON (§2.1). Conformance op `ll.make` builds
the profile frame of a compliant endpoint.

**Not signed.** Frames are not signed: the Line is already authenticated end to end, because the DTLS fingerprints sit
in signed SDP (LP 0.1 §7.3 rule 6).

**What the frame can and cannot prove.** It declares the sender's parameters. A sender that lies only misdescribes its
own channels, and §20.6 checks wire-observable faults independently of it.

### 20.5 Verifying the peer's frame (first failure wins; op `ll.frame`)

Input: the first text received on `lyne-control`, and whether the Grant includes `data`.

1. More than 1024 bytes, not strict JSON, or not an object → `LINE_PROFILE_INVALID` (400).
2. `lyne` is not a string → `LINE_PROFILE_INVALID`. If it matches `^lp02\.liveline/([1-9][0-9]{0,5})$` with a version other than 1 → `MODULE_VERSION_UNSUPPORTED` (400). Any other value than `"lp02.liveline/1"` → `LINE_PROFILE_INVALID`.
3. The members are not exactly `lyne`, `t` and `channels`, or `t` is not `"profile"` → `LINE_PROFILE_INVALID`.
4. `channels` is not an object with exactly the members `lyne-control` and `lyne-data` → `LINE_PROFILE_INVALID`.
5. A value of `channels` that is neither `null` nor a descriptor of §20.4 (exact members, types and ranges) → `LINE_PROFILE_INVALID`.
6. `lyne-control` is `null` (no control channel) → `LINE_PROFILE_MISMATCH` (409).
7. `lyne-data` is not `null` and the Grant does not include `data` → `CHANNEL_NOT_GRANTED` (LP 0.1 §8.3 rule 3).
8. The `lyne-control` descriptor differs from `{ id 0, negotiated true, ordered true, protocol "", maxRetransmits null, maxPacketLifeTime null }` → `LINE_PROFILE_MISMATCH`.
9. The Grant includes `data` and `lyne-data` is `null`, or the `lyne-data` descriptor differs from the same values with `id` 1 → `LINE_PROFILE_MISMATCH`.
10. Accepted.

`ll.local` applies rules 5–9 to an endpoint's **own** descriptors (§20.3 rule 2).

### 20.6 The Line with a negotiated profile (op `ll.session`)

**Holding traffic.** Until the peer's frame is verified, an endpoint sends no LP 0.1 object on `lyne-control` and nothing
on `lyne-data`: it holds them, in order, and sends them after verification. A `lyne-data` message received before
verification is held, at most 64 messages; it is delivered after verification and discarded on failure. A 65th
held message → `LINE_PROFILE_INVALID` (the peer sent data without waiting for its own verification).

**Failures that end the Line.** Each one ends the Line with a signed `bye` carrying the code (LP 0.1 §8.4; over
signaling when `lyne-control` is not open):

1. the peer's frame fails §20.5 → its code;
2. the first message on `lyne-control` is not a frame of this module (e.g. an LP 0.1 object first; §20.5 decides its code), or, after verification, a `lyne-control` text matches the regular expression `"lyne"\s*:\s*"lp02\.liveline/` anywhere (a second frame, out of turn) → `LINE_PROFILE_INVALID`;
3. the peer announces an **in-band** data channel (DCEP; the browser's `datachannel` event):
   - labelled `lyne-control` or `lyne-data` → `LINE_PROFILE_MISMATCH` (a peer that created them with `negotiated: false`);
   - any other label → `CHANNEL_NOT_GRANTED` (LP 0.1 §8.3 rule 3);
4. no valid frame within `PROFILE_TIMEOUT` = 10 s after the endpoint's own `lyne-control` opened → `LINE_PROFILE_MISMATCH`.

   This covers a peer that put control on another stream id, created no control channel, or sends nothing: on a negotiated channel such traffic never arrives on stream 0.
5. `lyne-control` not open within `SETUP_TIMEOUT` = 30 s after ICE connected → `LINE_PROFILE_MISMATCH`.

**What these checks catch.** With negotiated channels nothing is announced on the wire. A peer whose stream ids,
ordering or reliability differ is caught by its frame (§20.5), and if it sends no frame, by rule 4 or by its DCEP
announcement (rule 3). No configuration that differs from §20.1 interoperates silently.

### 20.7 Every Line is fresh

**Per Line.** The frames and the verification state belong to one `line_seq`. They are transient, held in memory, and
never stored. A new `line_seq` (a reconnect or a fresh Line) creates new channels with the same ids and parameters, and
exchanges new frames.

**A page reload.** A reload loses the Line capability (LP 0.1 §5.4: S and `PRK_line` are never stored), so a fresh Line
needs a fresh Grant use. Nothing of this module survives the reload or is reused.

### 20.8 Errors

| code | status | when |
|---|---|---|
| `LINE_PROFILE_INVALID` | 400 | a profile frame that is malformed, out of turn, or repeated (§20.5 rules 1–5, §20.6 rule 2) |
| `LINE_PROFILE_MISMATCH` | 409 | parameters that differ from §20.1, a missing channel, an in-band channel with a LYNE label, or no frame in time (§20.3, §20.5, §20.6) |

Reused codes:

- `CHANNEL_NOT_GRANTED` (LP 0.1 §8.3; it ends the Line);
- `MODULE_VERSION_UNSUPPORTED` (400);
- `MODULE_NOT_NEGOTIATED` (409);
- `MODULE_UNSUPPORTED` (409).

### 20.9 Privacy and security

- **What a frame carries.** Six channel parameters per channel: no identifier, no address, no content. It is Line traffic, transient (LP 0.1 §8.5), and never persisted, logged or audited.
- **Why `lyne-control` must be ordered and fully reliable.** The Result exchange (proposal, countersignature) and `bye` ride on it; reordering or loss would change their meaning. That is why §20.1 forbids unordered delivery and partial reliability for both channels.
- **No silent downgrade.** A peer that negotiated the profile cannot downgrade a Line to in-band or partially reliable channels without the Line ending (§20.2 rule 5, §20.6).
- **No downgrade of the negotiation itself.** Candidate §3.2 (the ratchet, signed documents) protects it. A provider can make the profile mandatory (§20.2 rule 4).

### 20.9a Compatibility

| pair | outcome |
|---|---|
| candidate-4 ↔ candidate-4 (both list and declare `lp02.liveline` /1) | profile NEGOTIATED: §20.3–§20.7 apply to every Line |
| candidate-4 ↔ candidate-3 / -2 / -1 / LP 0.1 | `lp02.liveline` absent (unknown to them; a candidate-3 client cannot declare it: `CLIENT_MODULES_INVALID`). Lines follow LP 0.1 §8.3; no frame is sent. A candidate-4 provider that requires the profile refuses with `MODULE_NOT_NEGOTIATED` |
| a frame `lp02.liveline/2` (a future version) to a /1 endpoint | `MODULE_VERSION_UNSUPPORTED` |

### 20.10 Conformance

Ops `ll.make`, `ll.local`, `ll.frame`, `ll.session`: `conformance/DRIVER.md`. Vectors: `vectors/liveline-vectors.json` (`LL-*`). The real-browser interoperability proof (two independent browser peers, both directions, adversarial configurations) is part of the candidate's evidence, not of its conformance kit.
