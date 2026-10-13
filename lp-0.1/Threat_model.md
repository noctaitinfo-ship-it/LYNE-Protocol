# LYNE Protocol (LP) 0.1 — Threat Model

| | |
|---|---|
| Document | `03_Protokoll/Threat_model.md` |
| Applies to | `PROTOCOL.md`, LP 0.1 draft 3 (Gate 1 contract repair) |
| Date | 2026-09-27 |
| Status | Private working draft; part of the Gate 1 review; not locked |

## Scope

Assets:

- Grant Secret S (the bearer secret, alive for at most 15 minutes), `line_salt`, `PRK_line` and the
  directional signaling keys `K_signal_p2c` and `K_signal_c2p` (the rendezvous and signaling
  secrets; memory-only in browser endpoints, PROTOCOL.md §5.4).
- Thing-keys (Client identity per Thing) and provider keys.
- The State chain and complete Results (the persistent record).
- Live Line content (media and `lyne-data`), which is never persisted.
- Metadata: who reaches which Provider, when, from which network address.

Adversaries: a holder of a copied or stolen link; a network attacker; a malicious or compromised
Provider; a malicious Client; a curious or compromised Rendezvous Service or TURN operator; a
software agent exceeding its authority; a co-tenant in a hosted runtime.

Trust assumptions: the Provider controls its backend and its `aud` origin; the Client endpoint
device is not compromised; the web PKI authenticates the `aud` origin; random generators are
cryptographically secure; the standard primitives of the LP 0.1 cryptographic profile (PROTOCOL.md
§2.6) are sound.

Every entry states the threat, its impact, the LP 0.1 mitigation (with section references to
PROTOCOL.md) and the residual risk that remains after mitigation.

## Mandatory threats

### T01 Grant theft

- **Threat:** An attacker obtains the delivery link (grant_id and S) before the legitimate Client
  redeems it: a photographed QR code, a forwarded link, a compromised delivery channel.
- **Impact:** The attacker redeems first, becomes the bound Client of the Thing, can read its State
  and can open Live Lines within the Grant's scope.
- **Mitigation:** One-time Redemption (§6.2 step 7): the legitimate Client immediately receives
  `GRANT_CONSUMED`, which is a theft signal to the Provider. The bearer phase ends at `redeem_by`,
  at most 15 minutes after issuance (§5.3), and Providers issue Grants on demand. The Grant is
  limited to one Thing, specific channels, `max_uses` and a short validity. S travels in the URL
  fragment, never in HTTP requests; the fragment is removed at once and S is deleted after
  Redemption (§5.4). The Provider can revoke the Binding, increment the epoch and issue a new Grant
  (§10.4).
- **Residual risk:** Theft during the bearer phase (at most 15 minutes) cannot be prevented by the
  protocol alone.
  Detection depends on the legitimate Client noticing `GRANT_CONSUMED` and on the Provider's own
  relationship to re-verify the Client.

### T02 First-redemption race

- **Threat:** Two parties holding the same link attempt Redemption concurrently.
- **Impact:** Without atomicity two Thing-keys could be bound, or the Grant's uses could be doubled.
- **Mitigation:** `ISSUED` → `REDEEMED` and the Binding are one atomic compare-and-set keyed by
  `grant_id` (§6.2 step 7). Exactly one attempt succeeds; all others receive `GRANT_CONSUMED`
  without any state change. Challenges are single-use.
- **Residual risk:** Whoever wins the race is bound; if it is not the legitimate Client, the case
  becomes T01. Correctness depends on the Provider's storage offering an atomic conditional update.

### T03 Replay

- **Threat:** Captured protocol messages are sent again: Redemption statements, signal messages,
  Thing endpoint requests, States, Results.
- **Impact:** Duplicate Bindings, reopened Lines, repeated State transitions.
- **Mitigation:** Single-use challenge and non-`ISSUED` Grant (Redemption); a per-direction
  nonce-replay set for the active Line that rejects a repeated envelope (§7.3); per-sender `seq`,
  `sent_at`, bucketed `addr` and direction-bound signaling keys, so an envelope reflected back to
  its sender fails decryption (signal messages, §7.2); RFC 9421 `created` with a replay cache (Thing
  endpoint); `version` and `prev_state_hash` (State); one complete Result per (`grant_id`,
  `line_seq`); atomic use accounting per `line_seq` (§10.7).
- **Residual risk:** Replay protection depends on correct Provider state. A Provider restored from an
  old backup could accept a challenge again within `CHALLENGE_TTL`; the short TTL limits this.

### T04 Copied QR/link

- **Threat:** The delivery link or QR code is copied after the legitimate Redemption (a photo of a
  printed code, a screenshot, browser history, a shared device).
- **Impact:** The copier tries to redeem, or to derive rendezvous addresses and join a Line.
- **Mitigation:** After Redemption the link yields `GRANT_CONSUMED`; after `redeem_by` an
  unredeemed link yields `GRANT_REDEMPTION_EXPIRED`. The endpoints delete S after Redemption and keep
  only `PRK_line`, which also requires `line_salt`, delivered only in the Redemption response
  (§5.4, §7.2); S alone therefore reveals no rendezvous address and no signaling key. Opening a
  Line requires the bound Thing-key (§8.2).
- **Residual risk:** A copy made before Redemption is T01. The link lets its holder fetch the Grant
  object and so learn `thing_id` and the Grant metadata (purpose, channels, validity); `purpose` MUST
  NOT contain personal data (§5.1).

### T05 MITM

- **Threat:** An attacker intercepts first contact (a phishing link to a look-alike origin), the
  Redemption exchange, or Live Line signaling.
- **Impact:** Impersonation of the Provider, key substitution, eavesdropping on a Line.
- **Mitigation:** The Client's trust in the provider key is anchored in the TLS-authenticated `aud`
  origin from which the Grant is fetched, which must equal `aud` (§6.2 step 1). Redemption runs over
  HTTPS with a Thing-key signature and an HMAC proof bound to `client_thing_pub`. Every SDP is signed
  by a LYNE key, so DTLS fingerprints are authenticated end to end and relays cannot insert
  themselves (§7.3). The provider key is pinned per Thing (§3.2 rule 5).
- **Residual risk:** First-contact trust is only as strong as the Client's judgement of the origin
  and of the delivery context; a convincing phishing origin with a valid certificate defeats it.
  LP 0.1 has no out-of-band verification of provider keys.

### T06 Clock skew

- **Threat:** Endpoint clocks differ, or an attacker manipulates a Client clock.
- **Impact:** Premature rejection, acceptance after expiry, missed rendezvous buckets.
- **Mitigation:** The Provider's clock is authoritative for validity; `MAX_CLOCK_SKEW` (300 s) is
  tolerated only for `not_before` and freshness, never for `exp` (§10.6). Rendezvous readers check
  the adjacent buckets; `RDV_BUCKET` of 300 s covers a skew up to 300 s (§7.2).
- **Residual risk:** Clients whose clocks are off by more than `MAX_CLOCK_SKEW` fail to connect (an
  availability issue, not a safety issue). A manipulated Client clock cannot extend authority because
  the Provider enforces `exp`.

### T07 Device loss

- **Threat:** The Client endpoint that holds the Thing-key is lost, stolen, reset, or its storage is
  cleared.
- **Impact:** Loss of access to the Thing and its Results; a thief may read the State and open Lines
  within valid Grants.
- **Mitigation:** The Thing-key is non-extractable and limited to one Thing (§6.1). The Provider can
  revoke the Binding with an epoch increment (§10.4) and issue a new Grant through its own
  relationship. Results and the State chain are also held by the Provider.
- **Residual risk:** LP 0.1 defines no Client backup and no multi-device synchronization (non-goal
  v0.1, PROTOCOL.md Appendix B, B.5). S and `line_salt` live only in page memory, so a closed page
  or a lost device also loses the current Grant's capability; the Provider issues a new Grant
  (§5.4). Recovery depends entirely on the Provider re-establishing the Client. A stolen unlocked
  device exposes the Thing until the Provider revokes the Binding.

### T08 Provider compromise

- **Threat:** An attacker gains control of the Provider's backend or provider key.
- **Impact:** Forged Things, States, Grants and Results for that Provider; Grants issued to the
  attacker; access to States and audit records. The attacker cannot decrypt past Lines (DTLS-SRTP
  keys are ephemeral) and cannot forge Client signatures.
- **Mitigation:** Provider keys are protected by key management outside the protocol (master plan
  AE3/AE4). Audit records hold no content and no content is stored anywhere, so none can leak.
  Clients pin the provider key per Thing.
- **Residual risk:** LP 0.1 has no provider key rotation and no compromise signalling towards
  Clients (non-goal v0.1, PROTOCOL.md §10 item 8, Appendix B, B.4). The Provider freezes or revokes
  the affected Thing relationships, and a new provider key requires a new Thing. Until Clients learn
  of the compromise through the Provider's own channels, objects signed with the stolen key still
  verify for its existing Things.

### T09 Malicious provider

- **Threat:** A legitimate Provider abuses the protocol: it issues overly broad Grants, records
  Lines, presents a false Result, correlates Clients across Things, or refuses to anchor Results.
- **Impact:** Loss of privacy for the Client; disputes over outcomes.
- **Mitigation:** The Grant's scope (channels, validity, purpose) is visible to the Client before
  Redemption, and the Client can decline. A Result needs the Client's signature, so the Provider
  cannot complete a Result alone (§9.4). An anchored State must match its Result and the Client
  verifies it (§9.5). One Thing-key per Thing prevents linking across Providers through LYNE
  identifiers.
- **Residual risk:** A Provider can record Lines by external means, withhold State updates, and link
  the Things of one Client through its own knowledge (it knows to whom it delivered each link).
  LP 0.1 limits provider power but does not remove it; contractual and legal controls (master plan
  AG6/AG7) lie outside the protocol.

### T10 Malicious client

- **Threat:** A Client abuses a Grant: exceeding its scope, flooding, repudiating, attempting State
  transitions it is not allowed to make, forwarding the link.
- **Impact:** Harassment inside the Grant window, Provider resource consumption, disputes.
- **Mitigation:** Grants are bounded (channels, `max_uses`, `line_max_seconds`, `exp`). The Provider
  enforces every limit and can revoke at any time, closing active Lines within
  `REVOCATION_CLOSE_MAX` (§10.2). Client State proposals are restricted (§4.3 rule 3). Without a
  Grant the Client has no way to reach the Provider, because no address exists. Rate limits apply.
- **Residual risk:** Inside a valid Grant a Client can behave badly for up to `line_max_seconds`. A
  link forwarded before Redemption hands the Grant to someone else (T01).

### T11 Agent overreach

- **Threat:** A software agent operating an endpoint, in either role, attempts actions beyond the
  Grant: widening purpose or channels, extending time, increasing uses, delegating to other agents,
  or retaining content.
- **Impact:** Communication beyond what the Provider authorized; uncontrolled spread of authority.
- **Mitigation:** Grant fields are signed by the Provider, so any modification invalidates the
  signature (tested by `examples/tampered/grant.channels-widened.json`). The Provider enforces
  channels, uses and time on its own side regardless of what an endpoint claims (§8.2). LP 0.1 has
  no delegation, and exporting or sharing a Thing-key is forbidden (§14.3). The non-persistence rule
  applies to agents (§14.5).
- **Residual risk:** An agent holding a valid Thing-key can do anything a human Client could do
  inside the Grant. Whether an agent retains content internally cannot be verified by the protocol.

### T12 Rendezvous enumeration

- **Threat:** An attacker probes the Rendezvous Service for active addresses to discover or disrupt
  Lines.
- **Impact:** Discovery of activity; injection or deletion of envelopes.
- **Mitigation:** `addr` is a 256-bit HKDF output depending on `PRK_line` and on the direction
  (§7.2). Retrieval needs the exact `addr` and no listing exists (§7.4). Envelopes are encrypted
  with the direction's key (`K_signal_p2c` or `K_signal_c2p`) under the address as AAD, repeated
  nonces are rejected, and the signal messages inside are signed, so injected or replayed envelopes
  are rejected (§7.3). Rate limits apply per source.
- **Residual risk:** A malicious Rendezvous Service can drop envelopes (denial of service) and
  observe metadata (T13).

### T13 Metadata correlation

- **Threat:** Runtime operators or network observers correlate timing, network addresses and volume
  across rendezvous polls, TURN allocations and Thing endpoint requests.
- **Impact:** Inference of who talks to which Provider and when; linking of one Client's Things by
  network address.
- **Mitigation:** Rendezvous addresses rotate per bucket and envelopes carry no identifier visible to
  the service (§7.3); logs are minimal and deleted after `RDV_TTL` (§7.4); one Thing-key per Thing;
  TURN credentials are short-lived and scoped per Provider (§8.6).
- **Residual risk:** Network metadata (addresses, timing) remains visible to the Rendezvous Service,
  TURN and the Provider. LP 0.1 provides no network anonymity. The master plan states this openly
  (§0: rendezvous and TURN see technical metadata).

### T14 TURN leakage

- **Threat:** A TURN server logs or leaks relayed-traffic metadata, or TURN credentials are reused.
- **Impact:** Metadata exposure; unauthorized relay use.
- **Mitigation:** TURN relays DTLS-SRTP and DTLS-protected SCTP packets it cannot decrypt;
  credentials are short-lived (not beyond `exp`) and Provider-scoped; operators MUST NOT keep
  metadata beyond operational necessity (§8.6).
- **Residual risk:** For relayed Lines, TURN necessarily sees both endpoints' network addresses,
  timing and volume.

### T15 DoS

- **Threat:** Flooding of the challenge and Redemption endpoints, the Thing endpoint, the Rendezvous
  Service or TURN; attempts to exhaust Grants through Redemption attempts.
- **Impact:** Legitimate Clients cannot redeem or connect.
- **Mitigation:** Rate limits per `grant_id` and per source (§6.2 step 9); little work before
  authentication (issuing a challenge is cheap, full verification only for well-formed statements);
  rendezvous storage bounded by `RDV_TTL` and per-source quotas; TURN allocations require
  credentials. Failed Redemption attempts never change the Grant status.
- **Residual risk:** Volumetric attacks on public endpoints need infrastructure-level protection
  outside LP 0.1 (master plan AE6/AE7).

### T16 Cross-tenant access

- **Threat:** In a hosted runtime that serves several Providers, one tenant reads or affects another
  tenant's Things, Grants, Bindings or rendezvous traffic.
- **Impact:** Privacy breach, forged State, revocation of another tenant's Grants.
- **Mitigation:** Every object is bound to a provider key (`provider_pub`, `issuer`) and verified.
  Rendezvous addresses are pseudorandom per Grant and cannot be listed per tenant. A hosted runtime
  MUST scope all storage and interfaces per tenant and reject cross-tenant requests (master plan
  AB7/AE2).
- **Residual risk:** Tenant isolation in a hosted runtime is an implementation property, tested
  during productization (AB7, 20 cases). LP 0.1 cannot guarantee it by protocol alone.

### T17 Result repudiation

- **Threat:** A party later denies having agreed to a Result.
- **Impact:** A dispute over the outcome.
- **Mitigation:** Both parties sign the identical JCS payload (§2.3, §9.3). The Client key is bound
  to the Thing through a Provider-signed Redemption Receipt and audit record. The anchored State
  references the Result, and incomplete Results never change State (§9.4).
- **Residual risk:** Signatures prove possession of a key, not the intent of a natural person, and
  they are not qualified electronic signatures. Legal effect needs a lawyer's assessment (human
  gate, `02_Uuring/Regulatsioon.md` §5). A party can claim key compromise (T07).

### T18 Key substitution

- **Threat:** An attacker substitutes a public key: the Client key during Redemption (a proxy
  replacing `client_thing_pub`), the provider key of a Grant, or keys in signaling.
- **Impact:** The attacker becomes the bound Client, or the Client trusts a forged Provider.
- **Mitigation:** `secret_proof` ties `client_thing_pub` to knowledge of S, so a proxy without S
  cannot produce a valid proof for another key, and the statement is signed by the Thing-key
  (§6.2). The Grant is fetched from, and matched to, the `aud` origin. The provider key is pinned per
  Thing (`KEY_MISMATCH`). Signal messages are signed by pinned or bound keys, and the `kid` of every
  JWS must match the key expected for the role (§2.3).
- **Residual risk:** An attacker who controls the `aud` origin (T08) or obtains the link before
  Redemption (T01) can substitute keys. LP 0.1 has no independent key transparency.

## Additional threats

### T19 Content retention by a participant or endpoint

- **Threat:** A participant records a Line by external means (screen or audio capture), or an
  endpoint implementation keeps media, `lyne-data` payloads or agent transcripts after the Line.
- **Impact:** The "no content storage" property fails for that Line.
- **Mitigation:** Conforming endpoints MUST NOT persist Line content (§8.5), including software
  endpoints (§14.5); runtime components cannot decrypt content; the Result is the only persistent
  artifact.
- **Residual risk:** Recording by a participant is technically impossible to prevent; LP 0.1 states
  this limit openly instead of claiming otherwise.

### T20 Canonicalization and signature confusion

- **Threat:** Two implementations serialize an object differently, or a verifier accepts a signature
  made for another object type or another key.
- **Impact:** Valid objects rejected, or forged objects accepted.
- **Mitigation:** JCS canonical form and a fixed protected header with `kid` (§2.3); schema-level
  `additionalProperties: false` on all four objects; non-integer numbers are forbidden; deterministic
  test vectors for signatures, hashes and derivations (`examples/valid/`, `tests/run_tests.py`).
- **Residual risk:** Implementations still need conformance testing across languages; the LP 0.1
  vectors are generated by one reference library only.

### T21 Fragment leakage

- **Threat:** The Grant Secret in the URL fragment leaks through browser history, the address bar,
  a screenshot, a camera or QR-scanner app's history, a shared device, or a third-party script on
  the redemption page.
- **Impact:** A second party can redeem the Grant during the bearer phase (T01).
- **Mitigation:** The redemption page reads S first and removes the fragment from the address bar
  and history at once (`history.replaceState`); it loads no third-party code and is served with a
  restrictive Content-Security-Policy and `Referrer-Policy: no-referrer`. S and `line_salt` stay in
  page memory only: they are never written to `localStorage`, `sessionStorage`, IndexedDB, the Cache
  API, service-worker caches, cookies, logs, analytics, crash telemetry or the URL query or path, and
  S is deleted after Redemption or at `redeem_by` (§5.4). The bearer phase lasts at most 15 minutes.
- **Residual risk:** Copies outside the endpoints' control (scanner history, screenshots, a
  photographed code) remain usable until Redemption or `redeem_by`; one-time Redemption makes a
  theft visible to the legitimate Client as `GRANT_CONSUMED`. A compromised browser or a malicious
  extension can read page memory; LP 0.1 cannot prevent that.

### T22 Signaling nonce reuse

- **Threat:** A sender reuses an AES-GCM nonce under the same directional signaling key (an
  implementation error, a weak random generator, restored state), or an attacker replays captured
  envelopes to a receiver.
- **Impact:** Nonce reuse under one GCM key reveals the XOR of the two plaintexts (SDP and ICE
  candidates, and so network addresses) and allows authentication tags to be forged under that
  key; a replay could repeat signaling steps.
- **Mitigation:** Every envelope uses a fresh 96-bit nonce from a cryptographically secure random
  generator, and a sender MUST NOT reuse a nonce under the same directional key (§7.3). The two
  directions use different keys (`K_signal_p2c`, `K_signal_c2p`) and therefore separate nonce
  spaces, and each Line has its own keys (`line_seq` enters the derivation), so each key encrypts
  only the few envelopes of one Line. The receiver keeps a nonce-replay set for the active Line and
  rejects a repeated nonce before decryption; the set is transient and deleted when the Line ends.
  The signal messages inside are signed with Ed25519, so even a forged envelope cannot carry a
  message that verifies.
- **Residual risk:** A broken random generator at a sender exposes that Line's signaling content
  (SDP, ICE candidates) to whoever collects the envelopes; signatures still prevent injection. LP 0.1
  cannot detect a broken generator.
