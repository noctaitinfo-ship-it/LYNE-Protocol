# Licenses

This repository uses **two licenses, each for its own part**. It is not dual-licensed: every file is under exactly
one of them, as `REUSE.toml` declares per path.

| part | license | files |
|---|---|---|
| **Specification text and documentation** — normative and explanatory | **CC BY 4.0** — [`LICENSES/CC-BY-4.0.txt`](LICENSES/CC-BY-4.0.txt) | every `*.md` file (including `lp-0.1/PROTOCOL.md`, `lp-0.1/Threat_model.md` and the candidate's `spec/*.md`), `AUTHORS`, `CITATION.cff` |
| **Schemas, test vectors, examples, machine-readable registries and records, conformance code** | **Apache-2.0** — [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt), with [`NOTICE`](NOTICE) | every `*.json` file (schemas, vectors, examples, the error registry, the freeze record, release records), every `*.py` file (tests, runners, generators), `release/SHA256SUMS`, `release/lp-0.1-core.sha256`, `release/allowed_signers`, `release/revoked_signers`, `tests/requirements.txt`, `NOTICE`, `REUSE.toml`, `.gitattributes` |

The license texts in `LICENSES/` are reproduced verbatim under their own terms.

Copyright 2026 Margus Šuman (Estonia).

## What the licenses do not grant

- **No trademark rights.** "LYNE" and the LYNE visual identity are identifiers of the official project operated by
  Margus Šuman / Nocta OÜ. Neither license grants any right to them (CC BY 4.0 §2(b)(2); Apache-2.0 §6). See
  [`TRADEMARK_POLICY.md`](TRADEMARK_POLICY.md).
- **No official status.** A copy, fork or modified version of the specification or the conformance kit is not an
  official LYNE specification. Official status comes only through [`GOVERNANCE.md`](GOVERNANCE.md).
- **No patent pledge beyond the licenses.** Apache-2.0 §3 gives its patent license for the Apache-licensed files.
  CC BY 4.0 excludes patent rights (§2(b)(2)). No separate LYNE-wide patent pledge has been made
  ([`PATENT_POLICY_PENDING.md`](PATENT_POLICY_PENDING.md)).

## Attribution

When you reuse the specification text, credit it as:

> LYNE Protocol (version), © Margus Šuman, CC BY 4.0

Then link the license and say whether you changed it. When you redistribute Apache-licensed files, keep their
notices and the `NOTICE` file, as Apache-2.0 §4 requires.
