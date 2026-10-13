# Contributing

## Welcome

These are welcome:

- issues: questions, ambiguities in the text, errors;
- proposals for new modules or changes;
- reports from implementers: a vector that seems wrong, a rule that cannot be implemented as written.

Pull requests may be reviewed.

## How a contribution is treated

- **No normative contribution becomes official merely by a merge proposal.** A pull request that changes normative
  text, a schema or a vector is a proposal. It becomes part of an official specification only through
  [`GOVERNANCE.md`](GOVERNANCE.md): normative diff review, conformance evidence, compatibility / security / privacy
  review, version assignment, and **Protocol Steward approval**, which is mandatory for every normative merge and
  release.
- **Frozen releases are never altered.** A contribution must not change the bytes of a published version, of LP 0.1,
  or of a frozen candidate (`lp-0.1/`, `lp-0.2-candidate-4/`). A proposed change goes to a later version or
  candidate. `python tests/verify_package.py` fails on any change to them.
- **Editorial fixes follow the same rule.** A fix to explanatory text (README, these policies) may be accepted
  directly; a fix to a frozen text becomes part of the next version.

## Provenance and licensing of contributions

- **Your own work, under the file's license.** Contribute only work you have the right to contribute. A contribution
  to a file is offered under that file's license: CC BY 4.0 for specification text and documentation, Apache-2.0 for
  schemas, vectors and conformance code (`LICENSE.md`).
- **Third-party material.** Name its source and license in the pull request. Material under a license incompatible
  with the file's license cannot be accepted.
- **No assignment.** Your copyright stays yours. Nothing here assigns it to Nocta OÜ or to anyone else.
- **Substantial normative text.** Before accepting substantial third-party normative text, the Protocol Steward may
  require a separate contributor agreement. No such agreement exists or applies today.
- **Authorship.** Accepted contributions are credited in the changelog of the version that includes them. The
  originator and authorship of the protocol (`AUTHORS`) do not change.

## Security issues

Do not open a public issue for a vulnerability; see [`SECURITY.md`](SECURITY.md).
