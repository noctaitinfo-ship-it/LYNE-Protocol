# Specifications

This repository holds the specification texts as they are; this page only points to them. Nothing here restates or
overrides a specification.

## LP 0.1 — immutable baseline

| document | what it is |
|---|---|
| [`lp-0.1/PROTOCOL.md`](lp-0.1/PROTOCOL.md) | The LP 0.1 specification (draft 3): Thing (§3), State (§4), Grant (§5), Redemption and the Thing-bound key (§6), Rendezvous (§7), Live Line (§8), Result (§9), revocation and expiry (§10), security (§11), non-goals (§12), lifecycle (§15) |
| [`lp-0.1/Threat_model.md`](lp-0.1/Threat_model.md) | Threats, mitigations and residual risks of LP 0.1 |
| [`lp-0.1/Schemas/`](lp-0.1/Schemas/) | JSON Schemas: Thing, State, Grant, Result |
| [`lp-0.1/examples/`](lp-0.1/examples/) | Valid, invalid, semantically invalid and tampered objects; cryptographic vectors |
| [`lp-0.1/tests/`](lp-0.1/tests/) | LP 0.1's own tests, as locked |
| [`lp-0.1/CHANGELOG.md`](lp-0.1/CHANGELOG.md) | LP 0.1's draft history |

Every file in `lp-0.1/` is byte-identical to the canonical LP 0.1 source. The evidence is in
`release/LP-0.1-IDENTITY.json`: per file, its SHA-256 and git blob id, plus the core manifest aggregate.

## LP 0.2 candidate-4 — EXPERIMENTAL CANDIDATE

`lp02-private-candidate-4`, frozen 2026-10-08, revision 1; candidate hash
`1262503847e12101fc83e48712b22e405796591edc5f314643901256efe76525`. **It is not a standard, not final and not stable.**

| document | what it is |
|---|---|
| [`lp-0.2-candidate-4/SPEC.md`](lp-0.2-candidate-4/SPEC.md) | The candidate: LP 0.1 core unchanged + 15 negotiated optional modules (§20: the Live Line data-channel profile) and the `lyne-result-proof/1` format |
| [`lp-0.2-candidate-4/MODULES.md`](lp-0.2-candidate-4/MODULES.md) | Module summaries |
| [`lp-0.2-candidate-4/MINIMAL.md`](lp-0.2-candidate-4/MINIMAL.md) | The minimal implementable specification and the implementation profiles |
| [`lp-0.2-candidate-4/MODULE_INVENTORY.md`](lp-0.2-candidate-4/MODULE_INVENTORY.md) | Every module considered, including the ones SUPERSEDED, DEFERRED or REJECTED (those are **not** part of the candidate) |
| [`lp-0.2-candidate-4/ERROR_REGISTRY.json`](lp-0.2-candidate-4/ERROR_REGISTRY.json) | Every refusal code |
| [`lp-0.2-candidate-4/COMPATIBILITY.md`](lp-0.2-candidate-4/COMPATIBILITY.md), [`lp-0.2-candidate-4/PRIVACY.md`](lp-0.2-candidate-4/PRIVACY.md), [`lp-0.2-candidate-4/SECURITY.md`](lp-0.2-candidate-4/SECURITY.md) | The candidate's compatibility, privacy and security notes |
| [`lp-0.2-candidate-4/CANDIDATE.json`](lp-0.2-candidate-4/CANDIDATE.json), [`lp-0.2-candidate-4/MANIFEST.json`](lp-0.2-candidate-4/MANIFEST.json), [`lp-0.2-candidate-4/FREEZE.json`](lp-0.2-candidate-4/FREEZE.json) | The candidate's metadata, the SHA-256 of every file, the freeze record (candidate hash) |

Every file of `lp-0.2-candidate-4/` is byte-identical to the frozen candidate; `tests/check_candidate.py` checks it against the
candidate's own MANIFEST and freeze record.

## Normative language

The specifications use MUST, MUST NOT, SHOULD and MAY in the sense of RFC 2119 / RFC 8174. Where this package's own
documents (README, SECURITY, PRIVACY, …) and a specification differ, the specification wins.
