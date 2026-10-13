# LP 0.2 — private protocol candidate-4 (`lp02-private-candidate-4`)

> **PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1.** MASTER decision 2026-10-08. Not in the publication package,
> no public tag, release or DOI. LP 0.1 (`03_Protokoll/`), candidate-1 (`../LP_0_2_PRIVATE`), candidate-2
> (`../LP_0_2_CANDIDATE2`) and candidate-3 (`../LP_0_2_CANDIDATE3`, the predecessor, frozen) are unchanged.

**Candidate-4 = candidate-3 (unchanged) + `lp02.liveline/1`.** The Live Line's data channels get an interoperable,
negotiated profile (LP02-B1): `lyne-control` id 0 and `lyne-data` id 1 (DATA only), negotiated, ordered, fully reliable,
protocol `""` — labels, not IANA names; every incompatible configuration fails explicitly.

| path | what |
|---|---|
| `SPEC.md` | the normative text: candidate-3's, plus §1 row and profiles, §10 liveline codes, §11 candidate-4 conformance, §20 `lp02.liveline/1` |
| `MINIMAL.md`, `MODULES.md`, `MODULE_INVENTORY.md` | profiles, per-module rules, the inventory |
| `ERROR_REGISTRY.json` | every code, status and module, from SPEC §10 and the vectors |
| `COMPATIBILITY.md`, `PRIVACY.md`, `SECURITY.md` | compatibility (incl. candidate-3 ↔ candidate-4), privacy model, security model |
| `schemas/` | candidate-3's schemas and the liveline profile frame schema |
| `vectors/` | `lp02-vectors.json` (candidate-1, byte-identical) + `channel2-vectors.json` (candidate-3's) + `liveline-vectors.json` + `negotiation-vectors.json`, each with its generator |
| `examples/` | one valid object of each kind, from the vectors |
| `conformance/` | `DRIVER.md`, `run_conformance.py`, `run_candidate4.py` |
| `CANDIDATE.json`, `MANIFEST.json`, `FREEZE.json` | metadata (predecessor hash), the hash of every file, the private freeze |
