#!/usr/bin/env python3
"""Checks the LP 0.2 publication candidate in this package — lp-0.2-candidate-4/ — standard library only.

The tree is the frozen private candidate `lp02-private-candidate-4`, byte for byte. It carries its own integrity record:
MANIFEST.json (the SHA-256 of every file, CRLF-normalised) and FREEZE.json (the candidate hash = SHA-256 of the
canonical JSON of MANIFEST.files). This check proves the copy here IS that frozen candidate:

  C1 every file the MANIFEST names is present and matches its SHA-256; no file is present that the MANIFEST does not name
  C2 the candidate hash recomputed from the MANIFEST equals FREEZE.candidate_hash, and FREEZE names the MANIFEST's SHA-256
  C3 the freeze record says PRIVATE_FROZEN_CANDIDATE, unpublished, label lp02-private-candidate-4, and the expected hash
  C4 CANDIDATE.json agrees (label, unpublished, predecessor, the modules — lp02.liveline version 1 among them)
  C5 every vector file parses and its count matches CANDIDATE.json; every vector names a module and has steps

Usage: python tests/check_candidate.py      Exit 0 = CANDIDATE-4 COPY: PASS
"""

import hashlib
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
PKG = Path(__file__).resolve().parent.parent
TREE = PKG / "lp-0.2-candidate-4"
LABEL = "lp02-private-candidate-4"
EXPECTED_HASH = "1262503847e12101fc83e48712b22e405796591edc5f314643901256efe76525"
results = []


def check(key, name, ok, detail=""):
    results.append(bool(ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {key} {name}" + (f" -- {detail}" if detail and not ok else ""))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def norm(p):
    return p.read_bytes().replace(b"\r\n", b"\n")


def main():
    man = json.loads(norm(TREE / "MANIFEST.json"))
    fz = json.loads(norm(TREE / "FREEZE.json"))
    meta = json.loads(norm(TREE / "CANDIDATE.json"))
    present = sorted(p.relative_to(TREE).as_posix() for p in TREE.rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    bad = [r for r, h in man["files"].items() if not (TREE / r).is_file() or sha(norm(TREE / r)) != h]
    extra = sorted(set(present) - set(man["files"]) - {"MANIFEST.json", "FREEZE.json"})
    check("C1", f"{len(man['files'])} files match the candidate's MANIFEST; nothing unlisted", not bad and not extra, f"differ {bad[:4]} extra {extra[:4]}")
    chash = sha(json.dumps(man["files"], sort_keys=True, separators=(",", ":")).encode())
    check("C2", f"candidate hash recomputed: {chash[:16]}… = FREEZE.candidate_hash; FREEZE names the MANIFEST",
          chash == fz.get("candidate_hash") and fz.get("manifest_sha256") == sha(norm(TREE / "MANIFEST.json")))
    check("C3", "freeze record: PRIVATE_FROZEN_CANDIDATE, unpublished, lp02-private-candidate-4, the expected hash",
          fz.get("status") == "PRIVATE_FROZEN_CANDIDATE" and fz.get("published") is False and fz.get("label") == LABEL and chash == EXPECTED_HASH)
    check("C4", "CANDIDATE.json agrees: label, unpublished, predecessor candidate-3, lp02.liveline version 1",
          meta.get("label") == LABEL and meta.get("published") is False and meta.get("predecessor", {}).get("label") == "lp02-private-candidate-3"
          and meta.get("modules", {}).get("lp02.liveline") == 1 and meta.get("modules", {}).get("lp02.channel") == 2)
    sets = {"lp02": "lp02-vectors.json", "channel2": "channel2-vectors.json", "liveline": "liveline-vectors.json", "negotiation": "negotiation-vectors.json"}
    probs = []
    for key, name in sets.items():
        try:
            v = json.loads(norm(TREE / "vectors" / name))
        except ValueError as e:
            probs.append(f"{name}: not JSON ({e})")
            continue
        if v.get("count") != len(v["vectors"]) or meta["vector_counts"].get(key) != len(v["vectors"]):
            probs.append(f"{name}: count")
        if any(not x.get("module") or not x.get("steps") for x in v["vectors"]):
            probs.append(f"{name}: a vector without module or steps")
    check("C5", "vector files parse; counts " + ", ".join(f"{k} {meta['vector_counts'].get(k)}" for k in sets) + " match CANDIDATE.json", not probs, str(probs))
    ok = all(results)
    print(f"CANDIDATE-4 COPY: {'PASS' if ok else 'FAIL'} ({sum(results)}/{len(results)})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
