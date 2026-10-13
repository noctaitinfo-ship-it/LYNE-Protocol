# Changelog

This is the changelog of the LYNE Protocol family as packaged here. Each version also keeps its own history:

- LP 0.1: [`lp-0.1/CHANGELOG.md`](lp-0.1/CHANGELOG.md), as locked;
- LP 0.2 candidate-4: [`lp-0.2-candidate-4/FREEZE.json`](lp-0.2-candidate-4/FREEZE.json) and [`lp-0.2-candidate-4/CANDIDATE.json`](lp-0.2-candidate-4/CANDIDATE.json).

## LP 0.2 candidate-4 — `lp02-private-candidate-4` (frozen 2026-10-08, revision 1) — the protocol publication candidate

**EXPERIMENTAL CANDIDATE.** It changes nothing in LP 0.1. It was frozen privately as the protocol publication
candidate; it is not a standard.

**Lineage.** Candidate-1 (frozen 2026-10-03; 13 modules) → candidate-2 (+ `lp02.channel` /1) → candidate-3 (`lp02.channel`
/2 replaces /1: Endpoint references minted by the runtime, no cross-Thing liveness oracle) → candidate-4 (+ `lp02.liveline`
/1, closing the WebRTC data-channel interoperability gap). Candidates 2 and 3 stay private, frozen evidence; candidate-4
contains candidate-1's content byte-identically and candidate-3's `lp02.channel` /2 unchanged.

**Modules.** 15 optional modules, each used only after negotiation:

| module | what it adds |
|---|---|
| `lp02.federation` | signed federation documents, deterministic negotiation, client module declaration, a downgrade ratchet |
| `lp02.admission` | Open Points, discovery descriptors, signed OPEN requests, admission policy |
| `lp02.referral` | pinned peers and federated referrals |
| `lp02.request` | structured requests: questions with answers on a Thing |
| `lp02.wake` | a bounded wake signal for a waiting Thing |
| `lp02.linecaps` | typed capabilities on a Line's data channel |
| `lp02.exit` | a customer leaving a Thing |
| `lp02.result` | an async Result without a Line |
| `lp02.delegation` | attenuated delegation chains with revocation |
| `lp02.recovery` | moving a relationship to a new device |
| `lp02.nonce` | many legitimate requests from one key in one second |
| `lp02.agreement` | a Result several actors agree to |
| `lp02.introduction` | introduction by context |
| `lp02.channel` /2 | transport without history: Endpoint references minted by the runtime per Thing (never an address, no cross-Thing answer), deliveries, attempts, receipts |
| `lp02.liveline` /1 | the Live Line WebRTC data-channel profile: `lyne-control` id 0 and `lyne-data` id 1, negotiated, ordered, fully reliable, protocol `""`; explicit failure, never a silent fallback |

It also keeps the portable evidence format `lyne-result-proof/1`.

**Evidence.** 632 conformance vectors in four sets. Three implementations conform, two of them written from the
specification alone; the Live Line profile is also proven between two independent browser peers (`evidence/`).

## LP 0.1 draft 3 — immutable baseline (locked 2026-09-27)

The core:

- Thing (§3), State (§4), Grant (§5);
- Redemption and the Thing-bound key (§6);
- Rendezvous (§7), Live Line (§8), Result (§9);
- revocation and expiry (§10).

LP 0.1's own draft history is in its changelog.

## This package

- **Revision 3 (2026-10-13) — prepared for the first public release.** No normative byte changed: LP 0.1 and
  candidate-4 are as in revision 2. Status wording for publication; attribution (author Margus Šuman, Estonia;
  Nocta OÜ as affiliation and project operator); citation metadata for Zenodo (`.zenodo.json`, agreeing with
  `CITATION.cff`); a quick start; the legal-review status (`PATENT_POLICY_PENDING.md`); versioned release notes.
- **Unpublished package candidate, revision 2 (2026-10-08).** It is assembled from the canonical sources: LP 0.1 byte
  for byte, and the frozen candidate-4 byte for byte. Revision 1 (2026-10-07) carried candidate-1's kit; revision 2
  replaces it by candidate-4, which contains it.
- **Revision 2, licenses.** The specification text and documentation are under CC BY 4.0; the schemas, vectors,
  examples and conformance code are under Apache-2.0 (`LICENSE.md`, `REUSE.toml`). Governance, contributing,
  trademark and patent policies are added. (At revision 2 no tag, release or DOI existed.)
