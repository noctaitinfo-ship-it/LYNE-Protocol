# Release notes

One section per release, newest first. A release is official only as a signed tag that verifies against
`allowed_signers` (`SIGNING.md`).

## `lp-0.1` and `lp-0.2-candidate-4` — the first public release of this repository

LYNE is communication infrastructure for matters between parties: no personal addresses, no inbox. A relationship is
a **Thing** with a signed **State**. Participation is a purpose-bound, time-limited **Grant**. Live interaction is a
temporary **Line**, and the outcome is a **Result** signed by both parties. The record is State and Result, never
the conversation.

### What is in it

| | tag | status |
|---|---|---|
| **LP 0.1** (draft 3) | `lp-0.1` | Immutable baseline. Byte-identical to the canonical LP 0.1 source (`release/LP-0.1-IDENTITY.json`). |
| **LP 0.2 candidate-4** | `lp-0.2-candidate-4` | Experimental candidate, not a standard. 15 optional, negotiated modules over the unchanged LP 0.1 core — including transport without history (`lp02.channel` /2) and the Live Line data-channel profile (`lp02.liveline` /1) — plus the portable Result proof format. |

The release also contains:

- **A conformance kit.** 632 vectors (1170 steps) in four sets; a stdlib-only runner with a line-based driver protocol,
  so any language can be tested; LP 0.1's own protocol checks.
- **Evidence.** Three implementations conform, two of them written from the specification text; they agree with
  each other under differential fuzzing (`evidence/`).
- **One command** that verifies the whole package: `python tests/verify_package.py`.

### Not in it

- No product source code and no reference implementation.
- No adoption claim.
- No trademark rights, no certification and no separate patent pledge: the specification text is under CC BY 4.0, and
  the schemas, vectors, examples and conformance code are under Apache-2.0 (`LICENSE.md`). The name and the visual
  identity are covered by `TRADEMARK_POLICY.md`.

### Verifying the download

Run `python tests/verify_package.py`. It checks every file against `release/SHA256SUMS`, LP 0.1 against its core
manifest, and the candidate's tree against its own `MANIFEST.json` and `FREEZE.json` (candidate hash). Then verify the signed tag (`release/SIGNING.md`).

### Status of review

- Not peer reviewed; not a standard of any standards body; no external implementation is known.
- No legal or patent review of this publication has been performed. LP 0.1 Appendix B (B.6) asks for a patent-counsel
  review before a public release; the author decided to publish without it. No freedom-to-operate is claimed.

Author: Margus Šuman (Estonia).
