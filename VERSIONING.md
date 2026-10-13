# Versioning

One repository, one protocol family, many immutable versions: LP 0.1, LP 0.2 candidates, later LP versions.

## Rules

1. **A published version never changes.** It is never overwritten, never retagged and never edited in place. A
   correction or a new feature is a new version, never a silent change to an old one.
2. **A tag is never moved or deleted** once pushed. If a tag was wrong, a new tag is made and the wrong one is
   documented, not rewritten.
3. **New normative changes require a new version** (or a new candidate). LP 0.1 is never changed retrospectively.
4. **Candidates are numbered and frozen.** A change to a frozen candidate makes the next candidate; the earlier one
   stays as frozen. The current candidate is `lp02-private-candidate-4` (`lp-0.2-candidate-4/FREEZE.json`); candidates 1–3
   stay frozen as they were.
5. **Compatibility is explicit.** Versions interoperate only through negotiation (`COMPATIBILITY.md`). There is no
   silent downgrade: an unsupported version or required module is refused, never guessed or imitated.
6. **Every version carries** its specification snapshot, schemas, vectors, examples, tests, its changelog entry, the
   authorship metadata and a manifest of SHA-256 hashes.

## Tag and release names

| version | tag | release title | status |
|---|---|---|---|
| LP 0.1 (draft 3) | `lp-0.1` | LYNE Protocol 0.1 | immutable baseline |
| LP 0.2 candidate-4 | `lp-0.2-candidate-4` | LYNE Protocol 0.2 — candidate 4 (experimental) | experimental candidate |
| later candidates | `lp-0.2-candidate-<n>` | … candidate n (experimental) | — |
| a final LP 0.2 | `lp-0.2` | LYNE Protocol 0.2 | not declared; only if the Protocol Steward approves one (`GOVERNANCE.md`) |

- **Signing.** Tags are annotated and signed with the Protocol Steward's dedicated SSH signing key, shown as
  Verified by GitHub (`release/SIGNING.md`).
- **Release assets.** Each release carries `release/manifest.json` and `release/SHA256SUMS` of that tree.
- **Making a release.** Creating a tag or a release requires Protocol Steward approval (`GOVERNANCE.md`). A tag in
  the table above exists only once it verifies against `release/allowed_signers` (`release/SIGNING.md`).
- **One GitHub release per published package state.** The first public release is on `lp-0.1`; `lp-0.2-candidate-4`
  is a signed tag on the same commit. Each GitHub release is archived on Zenodo with its own version DOI.
