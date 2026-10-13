# LYNE Protocol

> **Status.** LP 0.1 is the immutable baseline. LP 0.2 candidate-4 is an experimental candidate, not a standard.
> A version of this repository is an official release only as a signed tag that verifies against
> [`release/allowed_signers`](release/allowed_signers) ([`release/SIGNING.md`](release/SIGNING.md)). Release history:
> [`release/RELEASE_NOTES.md`](release/RELEASE_NOTES.md).

LYNE is **communication infrastructure** for matters between parties: a provider and a customer, a landlord and a
technician, or anyone who has a reason to deal with someone else for a while.

It is **not** a chat, a messenger, email, a phone system, an inbox, a social network, an AI assistant, or a universal
address for a person.

> There is no address to message.
> There is only a reason to OPEN a Thing.

> The address is not the person.
> The conversation is not the record.

## The model

| object | what it is |
|---|---|
| **THING** | The matter itself: one relationship between parties about one subject (a repair, a booking, a claim). Signed by the provider; it has an id and no owner address. |
| **STATE** | Where the Thing stands now: a signed, versioned, hash-chained record (status, who it waits on, the next action, a deadline). Each change is a new State version. |
| **GRANT** | A purpose-bound, time-limited, usually one-time capability that lets one party take part in a Thing (redeem it, open a Line). Authority comes from holding a valid Grant, not from knowing an address. |
| **LINE** | A temporary, end-to-end live connection (data, voice, video) opened under a Grant for a bounded time. It ends; its content MUST NOT be persisted by any party (LP 0.1 §8.5). |
| **RESULT** | The outcome, signed by both parties. It anchors the next State. (The LP 0.2 candidate adds a portable Result proof that anyone can verify offline.) |

What persists is **State + Result**: what was decided and who signed it. The content of a conversation is not the
persistent record; a Line is transport, not history.

## How a relationship begins

In the LP 0.2 candidate (module `lp02.admission`; experimental, see below), a relationship starts without anyone's
address:

```
INTENT → DISCOVER → VERIFY → ADMIT → THING
```

1. **Intent.** A party has a reason (a repair, an appointment).
2. **Discover.** It finds a provider's published Open Point: a purpose, not a person.
3. **Verify.** It verifies the provider's signed descriptor.
4. **Admit.** It sends a signed OPEN request. The provider's admission policy decides (for example a one-time
   admission code, or a referral from a trusted provider).
5. **Thing.** Only an admitted OPEN creates a Thing.

Nothing reaches a party except a signed OPEN to a point it published itself, which its policy is free to refuse. That is
the anti-spam property: there is no inbox to reach.

## Versions in this repository

| version | status | tree | what it is |
|---|---|---|---|
| **LP 0.1** (draft 3) | **immutable baseline** | [`lp-0.1/`](lp-0.1/) | The core: Thing, State, Grant, redemption and the Thing-bound key, rendezvous, Live Line, Result. Byte-identical to the canonical LP 0.1 source (`release/LP-0.1-IDENTITY.json`). |
| **LP 0.2 candidate-4** | **EXPERIMENTAL CANDIDATE** | [`lp-0.2-candidate-4/`](lp-0.2-candidate-4/) | The frozen protocol publication candidate (`lp02-private-candidate-4`, 2026-10-08): 15 optional, negotiated modules over the unchanged LP 0.1 core (federation and negotiation, admission, referral, request, wake, line capabilities, exit, async Result, delegation, recovery, nonce, agreement, introduction, channel /2, the Live Line data-channel profile) and the portable Result proof format. **Not a standard, not final, not stable.** |

LP 0.2 candidate-4 is included byte for byte as frozen, so that it can be read, implemented and tested exactly as it
is (`tests/check_candidate.py` proves the copy against its own MANIFEST and freeze record). It contains candidate-1's
content unchanged. It may change, or be abandoned, in a later candidate. LP 0.1 does not change. Because its files are
byte for byte as frozen, they keep the label they were frozen with (`lp02-private-candidate-4`, "unpublished"): that
label records the state at the freeze, not the state of this repository.

**Reading the frozen texts.** They are published exactly as locked, so some lines record their own history:

- LP 0.1's header ("PRIVATE LOCKED BASELINE FOR P0") and the closing line of its Appendix B ("PUBLIC/COMMERCIAL RELEASE:
  still blocked by B.6, B.11, Q-PUBLIC …") give the status at the lock. Today: B.6 — see *Patents and legal review*
  below; B.11 is not waived and is respected (no evidentiary or legal-effect claim is made for a Result); Q-PUBLIC
  concerns the author's product, not this specification.
- Folder and file names of the author's private working repository (numbered folders, for example LP 0.1's source
  folder), a commit id, and labels such as "MASTER", "OWNER" or "block NN" are references to that repository and
  its decision log. They are names only; the files they name
  are not part of this publication, and nothing in the protocol depends on them. LP 0.1's identity records
  (`release/LP-0.1-IDENTITY.json`, `release/lp-0.1-core.sha256`) keep the source paths because the hashes are over them.

## Start here

| you want to | read |
|---|---|
| understand the protocol | [`SPEC.md`](SPEC.md) → [`lp-0.1/PROTOCOL.md`](lp-0.1/PROTOCOL.md) → [`lp-0.2-candidate-4/SPEC.md`](lp-0.2-candidate-4/SPEC.md) |
| know what is guaranteed | [`SECURITY.md`](SECURITY.md), [`PRIVACY.md`](PRIVACY.md) |
| interoperate across versions | [`COMPATIBILITY.md`](COMPATIBILITY.md), [`VERSIONING.md`](VERSIONING.md) |
| test your implementation | [`CONFORMANCE.md`](CONFORMANCE.md) |
| verify this package | `python tests/verify_package.py` (needs `pip install -r tests/requirements.txt`) |
| see what changed | [`CHANGELOG.md`](CHANGELOG.md) |
| cite it | [`CITATION.cff`](CITATION.cff) (below) |

## Quick start

```
python -m pip install -r tests/requirements.txt
python tests/verify_package.py                        # the whole package: LYNE-PROTOCOL PACKAGE: PASS
python lp-0.2-candidate-4/conformance/run_candidate4.py --driver ./my-driver --name MINE   # your implementation (CONFORMANCE.md)
```

1. Read [`lp-0.1/PROTOCOL.md`](lp-0.1/PROTOCOL.md): the five objects and their lifecycle (§15).
2. Check your objects against [`lp-0.1/Schemas/`](lp-0.1/Schemas/) and the examples in [`lp-0.1/examples/`](lp-0.1/examples/), and your
   cryptography against `lp-0.1/examples/valid/vectors.json`.
3. For LP 0.2 candidate-4, write a driver for your implementation ([`lp-0.2-candidate-4/conformance/DRIVER.md`](lp-0.2-candidate-4/conformance/DRIVER.md))
   and run the vectors (`CONFORMANCE.md`).

Layout:

- `lp-0.1/` and `lp-0.2-candidate-4/` are the version trees.
- `schemas/`, `vectors/` and `examples/` are indexes into those trees.
- `tests/` holds this package's checks.
- `evidence/` holds the independent-implementation evidence.
- `release/` holds the manifest, checksums and release notes.

## What this repository is not

- It is not the LYNE product, and it contains no product source code.
- It is not a reference implementation; implementations are tested against it (`CONFORMANCE.md`).
- It does not claim adoption. What exists is stated in [`evidence/`](evidence/).

## Licenses, governance, name

- **Licenses.** Two licenses, each for its own part ([`LICENSE.md`](LICENSE.md), per file in `REUSE.toml`):
  - the **specification text and documentation** are under **CC BY 4.0**;
  - the **schemas, test vectors, examples and conformance code** are under **Apache-2.0** (with [`NOTICE`](NOTICE)).
- **Official status.** Only versions released through [`GOVERNANCE.md`](GOVERNANCE.md), with Protocol Steward approval
  and a signed release, are "the official LYNE Protocol". Forks, pull requests and implementations are not official
  by existing. Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **The name and the visual identity.** "LYNE" and the LYNE visual identity are identifiers of the official project
  operated by Margus Šuman / Nocta OÜ. The licenses grant no trademark rights ([`TRADEMARK_POLICY.md`](TRADEMARK_POLICY.md)).
  A truthful statement such as "implements LYNE Protocol 0.1" is fine. "Official LYNE", "LYNE certified" or
  "approved by LYNE" is not, without written permission.
- **Patents and legal review.** No separate patent pledge ([`PATENT_POLICY_PENDING.md`](PATENT_POLICY_PENDING.md)).
  No legal or patent review of this publication has been performed. LP 0.1 Appendix B (B.6) asks for a patent-counsel
  review before a public release; the author decided to publish without it. No freedom-to-operate is claimed.

## Author

The LYNE Protocol was designed and written by **Margus Šuman** (Estonia), its original author and **Protocol
Steward** (`AUTHORS`, `GOVERNANCE.md`). Nocta OÜ (Estonia) is the author's affiliation and operates the LYNE project.

## How to cite

Cite the exact version you used. The machine-readable form is [`CITATION.cff`](CITATION.cff); an archived copy of each
release, with a DOI, is on Zenodo (the DOI is listed here once the release is archived).

> Šuman, M. (2026). *LYNE Protocol 0.1* [Protocol specification and conformance kit]. Signed tag `lp-0.1`.

For LP 0.2 candidate-4, cite it as an experimental candidate: *LYNE Protocol 0.2, candidate 4 (experimental)*, tag
`lp-0.2-candidate-4`.
