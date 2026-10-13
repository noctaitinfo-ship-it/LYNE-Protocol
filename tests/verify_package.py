#!/usr/bin/env python3
"""Verifies this LYNE-Protocol package — one command, one verdict.

  P1  every required file of the package is present
  P2  release/SHA256SUMS: every file matches its checksum, and every file of the package is listed
  P3  LP 0.1 identity: every lp-0.1/ file equals the canonical LP 0.1 core manifest (SHA-256, and the aggregate)
  P4  LP 0.1's own protocol checks pass (tests/lp01_protocol_checks.py; needs tests/requirements.txt)
  P5  the LP 0.2 publication candidate (lp-0.2-candidate-4/) IS the frozen lp02-private-candidate-4: every file matches its
      MANIFEST, the candidate hash matches FREEZE (tests/check_candidate.py)
  P6  every JSON Schema parses and is a valid schema
  P7  the vectors cover every conformance category, and CONFORMANCE.md states the coverage the vectors have
  P8  with --driver: an implementation passes the candidate's conformance vectors (the candidate's own runner)
  P9  no secret, credential, capability link, private path or private infrastructure in any file
  P10 the release manifest agrees with the trees, the checksums, the freeze record and the authorship metadata
  P11 truthful status: LP 0.2 is never called stable / final / a standard; no adoption claim; the license structure is
      the declared one (LICENSE.md + LICENSES/), never a single whole-repository license file
  P12 every relative link in the package's own documents resolves inside the package
  P13 license boundary: REUSE.toml gives every file exactly ONE license; specification text resolves to CC BY 4.0;
      schemas, vectors, examples and conformance code to Apache-2.0; the license texts are the official ones
  P14 trademark and governance: no document grants trademark rights or claims a registration; official / certified /
      approved wording appears only as a prohibition; no CLA, copyright assignment or patent pledge is made; the
      official change rule and the Protocol Steward are stated
  P15 citation and status: .zenodo.json agrees with CITATION.cff; the legal-review status is stated; no claim of a
      legal or patent review, freedom-to-operate, peer review or standardization

Usage: python tests/verify_package.py [--driver "<command>" [--modules a,b,…]]
Exit 0 = LYNE-PROTOCOL PACKAGE: PASS.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PKG = Path(__file__).resolve().parent.parent
REQUIRED = ["README.md", "SPEC.md", "VERSIONING.md", "SECURITY.md", "PRIVACY.md", "COMPATIBILITY.md", "CONFORMANCE.md", "CHANGELOG.md",
            "AUTHORS", "CITATION.cff", "LICENSE.md", "LICENSES/CC-BY-4.0.txt", "LICENSES/Apache-2.0.txt", "NOTICE", "REUSE.toml",
            "GOVERNANCE.md", "CONTRIBUTING.md", "TRADEMARK_POLICY.md", "PATENT_POLICY_PENDING.md", ".gitattributes", "schemas/README.md", "vectors/README.md", "examples/README.md",
            "tests/verify_package.py", "tests/lp01_protocol_checks.py", "tests/coverage.py", "tests/requirements.txt", "evidence/README.md",
            "evidence/implementations.json", "release/manifest.json", "release/SHA256SUMS", "release/RELEASE_NOTES.md", "release/SIGNING.md",
            "release/lp-0.1-core.sha256", "release/LP-0.1-IDENTITY.json", "lp-0.1/PROTOCOL.md", "tests/check_candidate.py",
            "lp-0.2-candidate-4/SPEC.md", "lp-0.2-candidate-4/FREEZE.json", "lp-0.2-candidate-4/MANIFEST.json", "lp-0.2-candidate-4/CANDIDATE.json",
            "lp-0.2-candidate-4/conformance/run_candidate4.py", "lp-0.2-candidate-4/conformance/run_conformance.py",
            "lp-0.2-candidate-4/vectors/lp02-vectors.json", "lp-0.2-candidate-4/vectors/liveline-vectors.json", "release/allowed_signers",
            ".zenodo.json"]
AUTHORED_DOCS = ["README.md", "SPEC.md", "VERSIONING.md", "SECURITY.md", "PRIVACY.md", "COMPATIBILITY.md", "CONFORMANCE.md", "CHANGELOG.md",
                 "LICENSE.md", "GOVERNANCE.md", "CONTRIBUTING.md", "TRADEMARK_POLICY.md", "PATENT_POLICY_PENDING.md",
                 "evidence/README.md", "release/RELEASE_NOTES.md", "release/SIGNING.md"]
# the official license texts (SHA-256 of https://www.apache.org/licenses/LICENSE-2.0.txt and
# https://creativecommons.org/licenses/by/4.0/legalcode.txt, as published)
LICENSE_TEXTS = {"Apache-2.0": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
                 "CC-BY-4.0": "9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411"}
# what each part MUST resolve to (P13): specification text and documentation → CC BY 4.0; code and data → Apache-2.0
MUST_BE = [(r"^lp-0\.1/(PROTOCOL|Threat_model|CHANGELOG)\.md$", "CC-BY-4.0"), (r"^lp-0\.2-candidate-4/[A-Z_]+\.md$", "CC-BY-4.0"),
           (r"^lp-0\.2-candidate-4/conformance/DRIVER\.md$", "CC-BY-4.0"), (r"^[A-Z_]+\.md$", "CC-BY-4.0"),
           (r"\.schema\.json$", "Apache-2.0"), (r"^lp-0\.2-candidate-4/vectors/", "Apache-2.0"), (r"^lp-0\.1/examples/.*\.json$", "Apache-2.0"),
           (r"^lp-0\.2-candidate-4/examples/.*\.json$", "Apache-2.0"), (r"\.py$", "Apache-2.0"), (r"ERROR_REGISTRY\.json$", "Apache-2.0")]


def glob_rx(pattern):
    """A REUSE.toml path glob as a regular expression: ** any path (also across /), * anything but /, ? one character."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile("^" + out + "$")
# The IMMUTABLE candidate-4 tree (lp-0.2-candidate-4/, byte for byte the frozen lp02-private-candidate-4) NAMES the
# directories of the development repository its implementations and its draft live in — name only: the named directory
# is not part of this package and nothing of its content is. One more match is not a name at all: the marker text occurs
# by chance inside a deterministic SHA-256 digest of a channel vector (R4 regenerates it). Each is an exact exception.
_C4 = "lp-0.2-candidate-4/"
_IMPL, _LAB, _CHANCE = "04_" + "Prototuup", "Future_" + "lab", "PIA" + "3"
C4_NAME_ONLY = {(_C4 + "CANDIDATE.json", "private path", _LAB), (_C4 + "CANDIDATE.json", "private path", _IMPL),
                (_C4 + "conformance/DRIVER.md", "private path", _IMPL), (_C4 + "SPEC.md", "private path", _IMPL),
                (_C4 + "vectors/channel2-vectors.json", "private path", _CHANCE)}
results = []


LEGAL_STATUS = ("No legal or patent review of this publication has been performed. LP 0.1 Appendix B (B.6) asks for a patent-counsel "
                "review before a public release; the author decided to publish without it. No freedom-to-operate is claimed.")


def zenodo_vs_cff(root):
    """The fields Zenodo shows (.zenodo.json) against the citation (CITATION.cff); returns the names that differ."""
    try:
        zen = json.loads((root / ".zenodo.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [".zenodo.json unreadable"]
    cff = (root / "CITATION.cff").read_text(encoding="utf-8")
    top = cff.split("\nreferences:")[0] + "\n"
    field = lambda k: (re.search(rf'^{k}: "(.*)"$', top, re.M) or [None, None])[1]
    names = [f"{f}, {g}" for f, g in re.findall(r'- family-names: "(.*)"\n\s+given-names: "(.*)"', top)]
    m = re.search(r"^keyword[s]:\n((?:  - .*\n)+)", top, re.M)
    kws = [k.strip() for k in re.findall(r"^  - (.*)$", m.group(1), re.M)] if m else []
    ab = re.search(r"^abstrac[t]: >-\n((?:  .*\n)+)", top, re.M)
    abstract = " ".join(ab.group(1).split()) if ab else None
    problems = []
    for k, ok in (("title", zen.get("title") == field("title")), ("version", zen.get("version") == field("version")),
                  ("creators", [c.get("name") for c in zen.get("creators", [])] == names),
                  ("affiliation", [c.get("affiliation") for c in zen.get("creators", [])] == re.findall(r'affiliation: "(.*)"', top)),
                  ("orcid", [c["orcid"] for c in zen.get("creators", []) if c.get("orcid")] == re.findall(r'orcid: "https://orcid.org/(.*)"', top)),
                  ("keywords", zen.get("keywords") == kws), ("description", " ".join(str(zen.get("description", "")).split()) == abstract),
                  ("type", zen.get("upload_type") == "software" and zen.get("access_right") == "open"),
                  ("license", zen.get("license") == "other-open" and "CC BY 4.0" in zen.get("notes", "") and "Apache-2.0" in zen.get("notes", ""))):
        if not ok:
            problems.append(k)
    return problems


def check(key, name, ok, detail=""):
    results.append(bool(ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {key} {name}" + (f" -- {detail}" if detail and not ok else ""))


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def files():
    return sorted(p for p in PKG.rglob("*") if p.is_file() and ".git" not in p.relative_to(PKG).parts and "__pycache__" not in p.parts)


def rel(p):
    return p.relative_to(PKG).as_posix()


def run(cmd):
    p = subprocess.run(cmd, cwd=PKG, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, (p.stdout + p.stderr).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver")
    ap.add_argument("--modules")
    a = ap.parse_args()

    missing = [f for f in REQUIRED if not (PKG / f).is_file()]
    check("P1", f"required files present ({len(REQUIRED)})", not missing, f"missing: {missing}")

    sums = {}
    for line in (PKG / "release" / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        h, f = line.split("  ", 1)
        sums[f] = h
    bad = [f for f, h in sums.items() if not (PKG / f).is_file() or sha(PKG / f) != h]
    unlisted = [rel(p) for p in files() if rel(p) not in sums and rel(p) != "release/SHA256SUMS"]
    check("P2", f"checksums: {len(sums)} files match release/SHA256SUMS, none unlisted", not bad and not unlisted, f"differ: {bad[:5]} unlisted: {unlisted[:5]}")

    core, declared = {}, None
    for line in (PKG / "release" / "lp-0.1-core.sha256").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([0-9a-f]{64})\s+03_Protokoll/(\S+)$", line)
        if m:
            core[m.group(2)] = m.group(1)
        d = re.search(r"aggregate ([0-9a-f]{64})", line)
        if d:
            declared = d.group(1)
    agg = hashlib.sha256()
    for p in sorted(core):
        agg.update(f"03_Protokoll/{p}".encode("utf-8") + b"\0" + bytes.fromhex(core[p]))
    differ = [p for p, h in core.items() if not (PKG / "lp-0.1" / p).is_file() or sha(PKG / "lp-0.1" / p) != h]
    extra = [rel(p) for p in (PKG / "lp-0.1").rglob("*") if p.is_file() and p.relative_to(PKG / "lp-0.1").as_posix() not in core]
    identity = json.loads((PKG / "release" / "LP-0.1-IDENTITY.json").read_text(encoding="utf-8"))
    check("P3", f"LP 0.1 byte-identical to its canonical core manifest ({len(core)} files, aggregate {agg.hexdigest()[:12]}…)",
          not differ and not extra and agg.hexdigest() == declared == identity["computed_aggregate"] and len(identity["files"]) == len(core),
          f"differ: {differ[:5]} extra: {extra[:5]} aggregate: {agg.hexdigest()} vs {declared}")

    code, out = run([sys.executable, "tests/lp01_protocol_checks.py"])
    check("P4", "LP 0.1's own protocol checks: " + (out.splitlines()[-1] if out else "no output"), code == 0, out[-600:])

    code, out = run([sys.executable, "tests/check_candidate.py"])
    check("P5", "LP 0.2 publication candidate: " + (out.splitlines()[-1] if out else "no output"), code == 0, out[-600:])

    try:
        import jsonschema
    except ImportError:
        jsonschema = None
    schema_problems = []
    for p in sorted(PKG.glob("lp-*/**/*.schema.json")):
        try:
            s = json.loads(p.read_text(encoding="utf-8"))
            if jsonschema:
                jsonschema.validators.validator_for(s).check_schema(s)
        except Exception as e:  # noqa: BLE001 — every failure is a finding
            schema_problems.append(f"{rel(p)}: {e}")
    n_schemas = len(list(PKG.glob("lp-*/**/*.schema.json")))
    check("P6", f"{n_schemas} JSON Schemas parse and are valid schemas" + ("" if jsonschema else " (parse only: jsonschema not installed)"),
          not schema_problems and n_schemas > 0 and jsonschema is not None, "; ".join(schema_problems[:3]) or "install tests/requirements.txt")

    sys.path.insert(0, str(PKG / "tests"))
    import coverage
    try:
        cov = coverage.coverage()
    except ValueError as e:  # a vector file that is not JSON is a finding, not a crash
        cov = {"categories": [], "lp02_vectors": -1}
        check("P7", "vectors parse", False, str(e)[:200])
    else:
        empty = [r["category"] for r in cov["categories"] if r["steps"] == 0]
        stated = (PKG / "CONFORMANCE.md").read_text(encoding="utf-8")
        check("P7", f"vectors cover all {len(cov['categories'])} categories; CONFORMANCE.md states that coverage",
              not empty and coverage.markdown(cov) in stated, f"empty: {empty}" if empty else "CONFORMANCE.md coverage table is out of date (python tests/coverage.py --markdown)")

    if a.driver:
        cmd = [sys.executable, "lp-0.2-candidate-4/conformance/run_candidate4.py", "--driver", a.driver, "--name", "UNDER-TEST"]
        if a.modules:
            cmd += ["--modules", a.modules]
        code, out = run(cmd)
        check("P8", "conformance of the implementation under test: " + (out.splitlines()[-2] if len(out.splitlines()) > 1 else out), code == 0, out[-800:])
    else:
        print("[----] P8 conformance of an implementation: run with --driver \"<your driver command>\" (CONFORMANCE.md)")

    secret_rules = [
        ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
        ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
        ("API key", re.compile(r"\b(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})")),
        # a capability link on a real host; reserved names (RFC 2606 / 6761: .example, .test, .invalid, localhost) reach nothing
        ("capability link", re.compile(r"https?://(?![^/\s\"')]*(\.example|\.test|\.invalid|localhost|127\.0\.0\.1)[/:])[^\s\"')]+/(l|mv|r|s|o)/[A-Za-z0-9_-]{22}[^\s\"')]*#[A-Za-z0-9_.-]{16,}")),
        ("production host", re.compile("|".join(re.escape(a + b) for a, b in [("lyne", ".link"), ("workers", ".dev"), ("cloud", "flare"), ("wran", "gler")]), re.I)),
        # the markers are assembled from parts, so that this file does not contain them itself
        ("private path", re.compile(r"[A-Za-z]:\\(?=[A-Za-z])|/home/[a-z]|" + "|".join(re.escape(a + b) for a, b in [
            ("/Use", "rs/"), ("04_", "Prototuup"), ("03_Protokoll/", "Agent_Profile"), ("00_", "LYVE"), ("Otsused", ".md"), ("Testi", "logid"),
            ("PIA", "3"), ("PIA-", "control"), ("C--", "PIA"), ("Future_", "lab"), ("07_", "Avalik"), ("02_", "Uuring"), ("01_", "Idee"),
            ("05_", "Turg"), ("06_", "Oiguslik")]))),
        ("credential assignment", re.compile(r"(PASSWORD|SECRET|TOKEN|PIN)\s*[=:]\s*['\"]?[A-Za-z0-9+/_-]{6,}", re.I)),
        # an e-mail address that reaches someone; the reserved documentation domains (RFC 2606: example.com / .net / .org) do not
        ("e-mail address", re.compile(r"[A-Za-z0-9._%+-]+@(?!example\.(?:com|net|org)\b)[A-Za-z0-9.-]+\.(com|org|net|ee|io|dev)\b")),
    ]
    # Documented exceptions, each an exact (file, rule, matched text). Only IMMUTABLE texts — the LP 0.1 baseline and the
    # frozen candidate kit — may have one: they are reproduced byte for byte, so a name they mention stays. Each is a NAME
    # of a document or directory of the development repository; the named file is not part of this package and nothing of
    # its content is. Everything else in the package must be clean.
    names = {"master": "00_" + "LYVE", "decisions": "Otsused" + ".md", "impl": "04_" + "Prototuup", "ideas": "01_" + "Idee", "research": "02_" + "Uuring"}
    allowed = {
        ("lp-0.1/CHANGELOG.md", "private path", names["decisions"]), ("lp-0.1/PROTOCOL.md", "private path", names["decisions"]),
        ("lp-0.1/PROTOCOL.md", "private path", names["master"]), ("lp-0.1/tests/run_tests.py", "private path", names["master"]),
        ("lp-0.1/tests/run_tests.py", "private path", names["decisions"]), ("lp-0.1/PROTOCOL.md", "private path", names["research"]),
        ("lp-0.1/PROTOCOL.md", "private path", names["ideas"]), ("lp-0.1/CHANGELOG.md", "private path", names["ideas"]),
        ("lp-0.1/CHANGELOG.md", "private path", names["research"]), ("lp-0.1/tests/run_tests.py", "private path", names["ideas"]),
        ("lp-0.1/tests/run_tests.py", "private path", names["research"]), ("lp-0.1/Threat_model.md", "private path", names["research"]),
        ("lp-0.1/Threat_model.md", "private path", names["ideas"]),
    } | C4_NAME_ONLY
    hits, excused = [], 0
    for p in files():
        if p.suffix.lower() in (".png", ".ico"):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for name, rx in secret_rules:
            for m in rx.finditer(text):
                if (rel(p), name, m.group(0)) in allowed:
                    excused += 1
                    continue
                hits.append(f"{rel(p)}: {name} ({m.group(0)[:40]})")
                break
    check("P9", f"no secret, credential, capability link, private path or private infrastructure ({len(files())} files scanned; "
          f"{excused} name-only mentions in immutable texts, each listed)", not hits, "; ".join(hits[:6]))

    manifest = json.loads((PKG / "release" / "manifest.json").read_text(encoding="utf-8"))
    freeze = json.loads((PKG / "lp-0.2-candidate-4" / "FREEZE.json").read_text(encoding="utf-8"))
    meta = json.loads((PKG / "lp-0.2-candidate-4" / "CANDIDATE.json").read_text(encoding="utf-8"))
    v01, v02 = manifest["versions"]
    authors = (PKG / "AUTHORS").read_text(encoding="utf-8")
    cff = (PKG / "CITATION.cff").read_text(encoding="utf-8")
    consistent = (v01["aggregate_sha256"] == agg.hexdigest() and v01["files"] == len(core) and v02["modules"] == meta["modules"]
                  and v02["revision"] == freeze["revision"] and v02["candidate_hash"] == freeze["candidate_hash"] and v02["vector_counts"] == meta["vector_counts"]
                  and sum(meta["vector_counts"].values()) == cov["lp02_vectors"] and manifest.get("revision") == 3
                  and manifest["files"] == len(sums) + 1 == len(files())
                  and manifest["license"] == {"specification-text": "CC-BY-4.0", "schemas-vectors-conformance-code": "Apache-2.0", "per-file": "REUSE.toml"}
                  and all(x in authors for x in ("Margus Šuman", "Estonia", "Affiliation: Nocta OÜ"))
                  and all(x in cff for x in ('family-names: "Šuman"', 'given-names: "Margus"', 'affiliation: "Nocta OÜ"', 'country: "EE"'))
                  and freeze["label"] == v02["label"] == "lp02-private-candidate-4" and freeze["published"] is False)
    check("P10", "release manifest agrees with the trees, checksums, freeze record and authorship", consistent)

    overclaim = []
    for doc in AUTHORED_DOCS:
        t = (PKG / doc).read_text(encoding="utf-8")
        for m in re.finditer(r"[^\n]*\b(LP 0\.2|candidate)[^\n]*", t):
            line = m.group(0)
            if re.search(r"\b(stable|final|standard|production)\b", line, re.I) and not re.search(r"\b(not|never|no|only if|unless)\b", line, re.I):
                overclaim.append(f"{doc}: {line.strip()[:90]}")
        for m in re.finditer(r"industry standard|widely adopted|adopted by|de facto", t, re.I):
            overclaim.append(f"{doc}: {m.group(0)}")
    # one declared structure: LICENSE.md (the scope) + LICENSES/ (the texts); never a single file that reads as a license
    # of the whole repository, never the pending note, and CITATION.cff names licenses per reference, not one for all
    stray = [rel(p) for p in PKG.iterdir() if p.is_file() and re.match(r"(LICEN[CS]E|COPYING)", p.name, re.I) and p.name != "LICENSE.md"]
    whole = re.search(r"^license:", cff, re.M)
    check("P11", "truthful status: LP 0.2 never stable/final/standard, no adoption claim; licenses only as declared (LICENSE.md + LICENSES/)",
          not overclaim and not stray and not whole, "; ".join(overclaim[:4]) or f"stray license files: {stray}" + (" ; CITATION.cff has one top-level license" if whole else ""))

    broken = []
    for doc in AUTHORED_DOCS + ["schemas/README.md", "vectors/README.md", "examples/README.md"]:
        base = (PKG / doc).parent
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", (PKG / doc).read_text(encoding="utf-8")):
            if re.match(r"[a-z]+:", target):
                continue
            if not (base / target).resolve().exists() or PKG.resolve() not in (base / target).resolve().parents and (base / target).resolve() != PKG.resolve():
                broken.append(f"{doc} -> {target}")
    check("P12", "every relative link in the package's documents resolves inside the package", not broken, "; ".join(broken[:5]))

    # P13 license boundary
    import tomllib
    reuse = tomllib.loads((PKG / "REUSE.toml").read_text(encoding="utf-8"))
    annotations = [([glob_rx(g) for g in a["path"]], a["SPDX-License-Identifier"]) for a in reuse["annotations"]]
    problems, by_license = [], {}
    for p in files():
        r = rel(p)
        if r.startswith("LICENSES/"):
            continue  # the license texts, under their own terms
        hits = [lic for rxs, lic in annotations if any(rx.match(r) for rx in rxs)]
        if len(hits) != 1:
            problems.append(f"{r}: {len(hits)} licenses {hits}")
            continue
        by_license[hits[0]] = by_license.get(hits[0], 0) + 1
        for pattern, want in MUST_BE:
            if re.search(pattern, r) and hits[0] != want:
                problems.append(f"{r}: {hits[0]}, must be {want}")
    used = {lic for _, lic in annotations}
    for lic, h in LICENSE_TEXTS.items():
        t = PKG / "LICENSES" / f"{lic}.txt"
        if not t.is_file() or sha(t) != h:
            problems.append(f"LICENSES/{lic}.txt is not the official text")
    extra_texts = sorted({p.stem for p in (PKG / "LICENSES").glob("*")} - set(LICENSE_TEXTS))
    if used != set(LICENSE_TEXTS) or extra_texts:
        problems.append(f"licenses used {sorted(used)}, texts beyond the two: {extra_texts}")
    check("P13", "license boundary: every file has exactly one license — " + ", ".join(f"{k} {v}" for k, v in sorted(by_license.items()))
          + "; spec text → CC BY 4.0, code/schemas/vectors → Apache-2.0; official license texts", not problems, "; ".join(problems[:6]))

    # P14 trademark and governance wording
    wording = []
    negation = re.compile(r"\b(no|not|never|nothing|neither|nor|without|unless|false|grants? no)\b", re.I)
    for doc in AUTHORED_DOCS + ["NOTICE", "AUTHORS", "CITATION.cff"]:
        t = (PKG / doc).read_text(encoding="utf-8")
        for sentence in re.split(r"(?<=[.!?:])\s+|\n\s*[-|]", t):
            low = sentence.lower()
            if re.search(r"(grant|licen[cs]e)s?\b.{0,80}\btrademark|\btrademark.{0,40}\b(granted|licensed)\b", low) and not negation.search(sentence):
                wording.append(f"{doc}: trademark grant? '{sentence.strip()[:70]}'")
            if re.search(r"®|registered trademark", sentence) and not negation.search(sentence):
                wording.append(f"{doc}: registration claim '{sentence.strip()[:70]}'")
            if re.search(r"(official lyne implementation|lyne certified|certified by lyne|approved by lyne|endorsed by lyne)", low) and doc not in ("TRADEMARK_POLICY.md", "GOVERNANCE.md", "README.md"):
                wording.append(f"{doc}: official/certified claim '{sentence.strip()[:70]}'")
            if re.search(r"\b(contributor license agreement|\bCLA\b|assigns? (its|the|all|your)? ?copyright)", sentence, re.I) and not negation.search(sentence):
                wording.append(f"{doc}: CLA / assignment '{sentence.strip()[:70]}'")
            # a patent commitment hides easily behind a "not" ("pledges not to assert"): any pledge / covenant / non-assertion
            # wording counts, except the explicit statements that NO separate pledge exists
            if re.search(r"pledge|covenant|non-?assert|not (to )?assert|will not sue|promises? .{0,30}patent", low) \
                    and not re.search(r"no separate|no patent pledge|nothing in this repository|has been made|beyond those|would be a separate", low):
                wording.append(f"{doc}: patent commitment '{sentence.strip()[:70]}'")
    gov = (PKG / "GOVERNANCE.md").read_text(encoding="utf-8")
    tm = (PKG / "TRADEMARK_POLICY.md").read_text(encoding="utf-8")
    rule = ("No normative protocol change becomes an official LYNE specification, candidate, version, compatibility\n> declaration, "
            "tag or release without explicit approval by the Protocol Steward.")
    stated = (rule in gov and "| **Protocol Steward** | Margus Šuman |" in gov and "| **Affiliation** | Nocta OÜ (operator of the LYNE project) |" in gov
              and "do not\n  grant trademark rights" in tm and '"Implements LYNE Protocol 0.1"' in tm and "no certification program" in tm.lower())
    check("P14", "trademark and governance: no trademark grant or registration claim, official/certified wording only as a prohibition, "
          "no CLA / assignment / patent pledge; the official change rule and the Protocol Steward stated", not wording and stated,
          "; ".join(wording[:4]) or "GOVERNANCE.md / TRADEMARK_POLICY.md lack a required statement")

    # P15 citation and status: Zenodo's metadata agrees with CITATION.cff; the legal-review status is stated where a reader
    # looks; no document claims a legal / patent review, freedom-to-operate, peer review or a standard that does not exist
    zen_problems = zenodo_vs_cff(PKG)
    legal_where = [d for d in ("README.md", "PATENT_POLICY_PENDING.md", "release/RELEASE_NOTES.md")
                   if LEGAL_STATUS not in " ".join((PKG / d).read_text(encoding="utf-8").split())]
    claims = []
    for doc in AUTHORED_DOCS + ["CITATION.cff", ".zenodo.json", "AUTHORS", "NOTICE"]:
        t = (PKG / doc).read_text(encoding="utf-8")
        for sentence in re.split(r"(?<=[.!?])\s+|\n\s*[-|>]", t):
            low = " ".join(sentence.lower().split())
            if re.search(r"\b(no|not|never|without|nor|neither)\b", low):
                continue
            if re.search(r"(legal|patent|counsel)[- ](review|clearance|opinion)s?\b.{0,60}\b(completed|performed|passed|done|obtained|cleared|confirmed)"
                         r"|\b(cleared|reviewed) by (patent )?counsel|freedom[- ]to[- ]operate (is|was|has been) (confirmed|established|cleared)"
                         r"|\bpeer[- ]reviewed\b|\b(ietf|w3c|iso) standard\b", low):
                claims.append(f"{doc}: '{sentence.strip()[:70]}'")
    check("P15", "citation and status: .zenodo.json agrees with CITATION.cff; the legal-review status is stated; no claim of a legal or "
          "patent review, freedom-to-operate, peer review or standardization", not zen_problems and not legal_where and not claims,
          "; ".join([f".zenodo.json differs: {', '.join(zen_problems)}"] * bool(zen_problems) + [f"status missing in {legal_where}"] * bool(legal_where) + claims[:3]))

    ok = all(results)
    print(f"\nLYNE-PROTOCOL PACKAGE: {'PASS' if ok else 'FAIL'} ({sum(results)}/{len(results)} checks)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
