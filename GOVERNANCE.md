# Governance

## Protocol Steward

| | |
|---|---|
| **Protocol Steward** | Margus Šuman |
| **Affiliation** | Nocta OÜ (operator of the LYNE project) |
| **Country** | Estonia |

The Protocol Steward is the originator and author of the LYNE Protocol (`AUTHORS`) and holds the final decision on
everything official.

## Roles and change control

Every role below is held by the **Protocol Steward**. A role can be delegated only by a recorded decision of the
Steward that names the person and the scope; until such a decision exists, nobody else holds it.

| role | decides | how a decision becomes effective |
|---|---|---|
| **Protocol Steward** | everything official; holds every role below | a recorded decision (see *Decisions and records*) |
| **Specification change controller** | any change to a normative text: a version, a candidate, a module and its rules | the official change rule below, then the release authority |
| **Registry change controller** | any value a LYNE implementation must recognise: module ids and versions, `typ` values, error codes and their statuses, member names, Live Line data-channel labels and parameters | the same as a specification change: a registry value is part of the normative text of the version that defines it |
| **Release authority** | which version or candidate is released, its tag and its release assets | a signed tag (`release/SIGNING.md`) |
| **Release signer** | the only one who may sign a canonical release | the holder of an active key in `release/allowed_signers`, which lists the Protocol Steward's key only |

A registration with an outside body (for example IANA, a DID method registry or a port assignment) is never implied by
this document. Each one would be a separate, recorded decision of the Protocol Steward.

## What "official" means

**The official LYNE Protocol** means only the specifications, candidates, versions, compatibility declarations, tags
and releases issued through this governance process.

## The official change rule

> No normative protocol change becomes an official LYNE specification, candidate, version, compatibility
> declaration, tag or release without explicit approval by the Protocol Steward.

A pull request, fork, issue, implementation or experiment is **not** an official LYNE protocol change merely because
it exists, because it is merged somewhere, or because it is widely used.

A normative change becomes official only when all of these hold:

1. **Normative diff reviewed.** The exact change to the normative text is written down and reviewed.
2. **Conformance evidence.** New or changed rules have vectors, and implementations pass them.
3. **Compatibility, security and privacy review.** Its effect on existing versions, negotiation, the threat model and
   the privacy properties is assessed (`COMPATIBILITY.md`, `SECURITY.md`, `PRIVACY.md`).
4. **Version assignment.** It is placed in a new candidate or a new version (see below).
5. **Protocol Steward approval.** Explicit and recorded.
6. **Signed official release.** Where a release applies, it is a signed tag and release (`release/SIGNING.md`).

## Immutability

- **Published versions never change.** An official release tag is never moved, rewritten or deleted.
- **A change is always a new version or candidate.**
  - LP 0.1 remains immutable. A normative change can never become "LP 0.1, edited"; it must become a later version
    or candidate.
  - A frozen candidate (now `lp02-private-candidate-4`) stays as frozen. A change to it is the next candidate.
- **Corrections follow the same path.** A correction of a published version is a new version or candidate, with the
  correction recorded in its changelog (`VERSIONING.md`).

## Decisions and records

- **Where decisions are recorded.** The Protocol Steward's decisions on normative matters are recorded with the
  version they concern: its changelog, its freeze record, and its release.
- **What counts as a decision.** A discussion, a vote or a contribution is input. The recorded approval is the
  decision.

## Implementations and compatibility claims

- **Who can implement.** Anyone may implement the protocol under the licenses (`LICENSE.md`).
- **What an implementation may claim.** It may describe itself truthfully, for example "implements LYNE Protocol
  0.1". It may not claim official status, approval or certification without separate written authorization
  (`TRADEMARK_POLICY.md`).
- **No certification program.** None exists.

## Changes to this governance

Only the Protocol Steward changes this document, by a recorded decision. Earlier versions remain in the history of
the repository.
