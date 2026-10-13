# LYNE Protocol — Changelog

## LP 0.1 draft 3 — lock metadata corrected (2026-09-27, BLOCK 006)

The header of `PROTOCOL.md` now records the lock: Status "PRIVATE LOCKED BASELINE FOR P0", Lock date
2026-09-27 and the lock scope (private technical baseline; not a public standard, not freedom-to-operate,
not trademark clearance; any later normative change requires a new LP version or draft). Appendix B records
that B.1 is decided and that the private lock is done. The normative text — sections 1–15 and Appendices A
and C — is byte-identical to the lock at commit 382d3ef (SHA-256 of that text:
b591c2f4a73d8beb42800d5c068602740fffdfaeac94ffad8e64e384776dd61a, checked by `tests/run_tests.py`). The git
tag `lp-0.1-private` points to the commit with the corrected metadata. No protocol semantics changed.

## LP 0.1 draft 3 — private lock as the P0 baseline (2026-09-27, BLOCK 005)

Under the owner rule recorded in `01_Idee/Otsused.md` on 2026-09-27 (a PASS of a stage's technical
gate closes the stage without a separate lock confirmation), ETAPP 1 is PASS and LP 0.1 draft 3 is
the private baseline for the P0 prototype. The locked text is `PROTOCOL.md` at commit 382d3ef (git
blob 54a850ba50e430a003987641790414fae940ae41); it is unchanged, so its header and Appendix B still
read as they did at the lock. This is not a public standard, not freedom-to-operate and not
production readiness; public or commercial release still needs B.6, B.11, Q-PUBLIC and later gates.

## LP 0.1 draft 3 — 2026-09-27 (Gate 1 contract repair, BLOCK 004R; private; not locked)

Closes the Gate 1 technical issues found in the owner's review of draft 2. Detail choices made by C
are marked "(C)".

### Changed

- Cryptographic profile (new §2.6): the canonical LP 0.1 core profile is Ed25519/EdDSA, SHA-256,
  HMAC-SHA256, HKDF-SHA256, AES-256-GCM, JCS, detached JWS, HTTP Message Signatures, WebRTC, ICE,
  STUN, TURN, DTLS-SRTP and SCTP/DTLS data channels — standard primitives only, no custom
  cryptography. WebAuthn is Provider Console authentication, not an LP 0.1 wire primitive; X25519 is
  not used directly and is not a required core primitive. Master §13 states the same profile.
- Error code: the redemption-window error is now `GRANT_REDEMPTION_EXPIRED` everywhere (§5.3, §5.4,
  §6.2, §15.4, threat model, tests, fixtures).
- Signaling keys (§7.2): the directional keys are `K_signal_p2c` and `K_signal_c2p`, derived with
  the HKDF label `LYNE/0.1/signal|`; the earlier abbreviated name and label are gone. The test
  vectors change accordingly.
- AES-GCM nonce rules (§7.3): nonces are exactly 96 random bits; a sender must not reuse a nonce
  under the same directional key; the two directions have separate keys and nonce spaces; a receiver
  keeps a transient, memory-only nonce-replay set for the active Line and rejects duplicates. A nonce
  enters the set only after its envelope authenticates, and a repeated fetch of the same envelope is
  not an error (C).
- Capability secrets (§5.4): S and `line_salt` (and `PRK_line` and its derived keys) are memory-only
  in browser endpoints and must not be written to `localStorage`, `sessionStorage`, IndexedDB, the
  Cache API, service-worker caches, cookies, logs, analytics, crash telemetry or the URL query or
  path. Losing the page loses the capability; there is no recovery or account mechanism, and the
  Provider issues a new Grant if needed. The non-extractable Thing-key is not a capability secret
  and may persist (C). §15.3 marks these secrets as transient, memory-only.
- Provider key compromise (§3.2 rule 5, new §10 item 8): no transparent rotation; a compromise
  freezes or revokes the affected Thing relationships; a new provider key requires a new Thing.
- Non-goals (§12): items 7 and 11–14 (custom cryptography, provider key rotation, recovery of
  capability secrets, transfer or forwarding of a Line, Grant or Binding, emergency channels). Items
  13 and 14 follow the full reading of A2R (its FAQ Q32–Q33 and §15) (C).
- Appendix B reclassified: B.1 is the only Gate 1 HUMAN GATE; B.2 RESOLVED IN 1B/004R; B.4, B.5 and
  B.10 NON-GOAL v0.1; B.6 HUMAN GATE BEFORE PUBLIC/COMMERCIAL RELEASE (not a private R&D or Gate 1
  blocker; no freedom-to-operate is claimed); B.7 RESOLVED FOR LP 0.1 PRIVATE LOCK after the full
  reading; B.8 and B.9 DEFERRED ETAPP 2; B.11 HUMAN GATE BEFORE PUBLIC/COMMERCIAL CLAIMS.
- Prior art (§13): both drafts read in full (`02_Uuring/Prior_art/FULL_READ_2026-09-27.md`), no
  material contradiction. Corrections from the reading: the PAP row now names its WebRTC audio and
  video calls and session attestations (its §13.8, §11.6); §5.2 cites A2R §9, not §13, for the
  candidate Grant fields.
- Threat model: T03, T04, T07, T08, T12 and T21 updated; T22 Signaling nonce reuse added.
- Tests: AES-GCM directional encryption and decryption, wrong-direction keys, duplicate and
  cross-direction nonces, tampered ciphertext and address; signed and encrypted signal-message
  fixtures; exact error code with a repository-wide check that the old code is gone; memory-only
  storage rules; exact Appendix B classes and closing statements; full-read record; crypto profile;
  secret-scan self-test and CI step order.
- CI: `scripts/secret-scan.py` (path and rule ID only, never values) runs after the foundation
  verification in `.github/workflows/protocol.yml`.

### Status

Technical Gate 1 issues closed. The private lock of LP 0.1 is blocked only by B.1 (the owner's lock
decision); public or commercial release is still blocked by B.6, B.11, Q-PUBLIC and later release
gates.

## LP 0.1 draft 2 — 2026-09-27 (ETAPP 1B hardening; private; not locked)

Hardening after the owner's review findings (BLOCK 004). The full BLOCK 004 text did not reach the
working session; the changes implement the twelve requirements restated in the BLOCK 004 RETRY
message, and every detail choice is listed here for review.

### Changed

- Rendezvous (§7.2, §7.3): signaling addresses and keys are separated by direction (`p2c`, `c2p`),
  derived from `PRK_line`; a receiver checks that `from` matches the inbound direction.
- Grant (§5): new required field `redeem_by`; bearer phase [`issued_at`, `redeem_by`) of at most
  `REDEEM_WINDOW_MAX` = 900 s; `not_before` now bounds Live Lines only; new error for a Redemption
  after `redeem_by` (named `GRANT_REDEMPTION_EXPIRED` since draft 3); Providers issue Grants on
  demand.
- New §5.4 fragment secret cleanup: read S once, remove the fragment with `history.replaceState`,
  no third-party code on the redemption page, S never logged, S replaced by `PRK_line` after
  Redemption and deleted at once after a final failure.
- Result over HTTP (§6.5, §9.3, Appendix A): the Client endpoint is always the HTTP requester; a
  Provider proposal is offered as `pending_result` in GetThing; SubmitResult carries the Client's
  countersignature or the Client's own proposal.
- Persistence wording: new §2.5 terms (persistent, retained until, transient, not held) used
  throughout; §15.3 table rewritten with them.
- Appendix B: every item classified as RESOLVED, DEFERRED, NON-GOAL or HUMAN GATE; locking is
  blocked only by B.1 (owner's lock decision), B.2 (primitive list in master §13) and B.6 (patent
  counsel for US10334037B2).
- Threat model: T01, T03, T04, T12 updated; T21 Fragment leakage added.
- Tests: the official `jsonschema` validator (Draft 2020-12, including metaschema checks) replaces
  the standard-library subset validator; new semantic-invalid fixture for the bearer window;
  direction vectors; checks for every hardening requirement and for the CI configuration.
- CI: `requirements-dev.txt` (pinned `jsonschema`, `cryptography`) and
  `.github/workflows/protocol.yml` for `protocol/**`.

### Status

ETAPP 1: NOT PASS until the owner decides B.1 and B.2 and patent counsel has reviewed B.6.

## LP 0.1 draft 1 — 2026-09-27 (ETAPP 1A foundation; private; not locked)

Status: ETAPP 1 is **NOT PASS**. It requires the owner's review (Gate 1) and a hardening block.

### Added

- `PROTOCOL.md` — sections 1–15: Motivation, Terminology, Thing, State, Grant, Redemption and
  Thing-bound Identity, Rendezvous, Live Line, Result, Revocation and Expiry, Security / Threat
  Model, Non-goals, Prior Art, Endpoint Neutrality, Protocol Lifecycle; Appendices A (HTTP binding,
  informative), B (open issues), C (references).
- `Threat_model.md` — 18 mandatory threats and 2 additional ones (T19 content retention, T20
  canonicalization), each with threat, impact, mitigation and residual risk.
- `Schemas/` — JSON Schema 2020-12 for Thing, State, Grant and Result.
- `examples/` — deterministic, really signed fixtures: `valid/` (one consistent lifecycle plus
  derivation vectors), `invalid/` (each violates exactly one schema rule), `tampered/` (schema-valid,
  signature must fail).
- `tests/` — `run_tests.py` (ETAPP 1A test suite), `gen_examples.py` (fixture generator),
  `lp_testlib.py` (encoding and derivation helpers for tests only).

### Decisions relative to the master plan §5b preview

- State `status` on the wire is `OPEN`, `WAITING` or `CLOSED`. LIVE and RESULT are lifecycle phases,
  not State values; the UI label "LYNE" denotes the LIVE phase.
- `waiting_on` replaces the preview's `WAITING(who)`; the preview's `DONE` is expressed as a Result
  with `next_state` `CLOSED`, or a Provider transition to `CLOSED`.
- Grant: the raw secret is never inside the object (`secret_commitment` instead); `aud`, `subject`,
  `issued_at` and `not_before` added; `line_max_seconds` corresponds to the preview's `window`;
  one-time Redemption is unconditional in LP 0.1 (the preview's `redeem_once`); `grant_id` also
  serves as the replay discriminator (A2R `jti`).
- Signatures: detached JWS with EdDSA over JCS; `kid` = JWK Thumbprint (RFC 7638).
- Rendezvous: HKDF with `line_salt` as salt, so a copied link does not reveal addresses after
  Redemption; `RDV_BUCKET` = 300 s.
- State ordering authority is the Provider (optimistic concurrency with `version` and
  `prev_state_hash`).
- Access to the Thing endpoint is authorized by the Binding; Grants bound only Live Lines.

### Tooling limits

- `jsonschema` is not installed on the development machine and no dependency was installed. The
  schemas are checked by a strict standard-library validator for the keyword subset they use; any
  other keyword fails the test instead of being ignored.
- Signatures, HKDF and HMAC are checked with the already-installed `cryptography` package.

### Run

```
python 03_Protokoll/tests/run_tests.py
python 03_Protokoll/tests/gen_examples.py --write   # only when examples must change
```

### Open issues

See `PROTOCOL.md`, Appendix B.
