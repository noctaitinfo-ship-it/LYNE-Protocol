#!/usr/bin/env python3
"""lp02-private-candidate-4 — the conformance run (PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1).

ONE vector set for every implementation: vectors/lp02-vectors.json (candidate-1, byte-identical), channel2-vectors.json
(SPEC §19, lp02.channel/2), liveline-vectors.json (SPEC §20, lp02.liveline/1) and negotiation-vectors.json (candidate-3
<-> candidate-4 <-> candidate-1 <-> LP 0.1). Every vector runs under the candidate-4 profile: `context.candidate` =
"lp02-private-candidate-4" (DRIVER.md), except a vector whose context names another profile (negotiation vectors for a
candidate-1 or candidate-3 party) — those prove no party is silently moved to another candidate.

  python run_candidate4.py --driver "<cmd>" --name X [--modules m1,m2]        one implementation
  python run_candidate4.py --driver "<cmd>" --driver2 "<cmd>" --name X --name2 Y [--modules …]   + step-by-step differential

--modules: an implementation of a declared profile (MINIMAL.md) runs every vector of the modules it implements; the
channel, liveline and negotiation vectors are always included.
"""

import argparse
import copy
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from run_conformance import check, run_driver  # noqa: E402  (candidate-1's runner, unchanged)

CANDIDATE = "lp02-private-candidate-4"
SETS = ["lp02-vectors.json", "channel2-vectors.json", "liveline-vectors.json", "negotiation-vectors.json"]


def load(modules=None):
    out = []
    for name in SETS:
        for v in json.loads((HERE.parent / "vectors" / name).read_text(encoding="utf-8"))["vectors"]:
            if name == "lp02-vectors.json" and modules and v["module"] not in modules:
                continue
            v = copy.deepcopy(v)
            if name != "negotiation-vectors.json":
                v["context"] = {**v.get("context", {}), "candidate": CANDIDATE}
            out.append(v)
    return out


def key(r):
    return (r.get("outcome"), r.get("code"), json.dumps(r.get("result"), sort_keys=True))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)
    ap.add_argument("--name", default="A")
    ap.add_argument("--driver2")
    ap.add_argument("--name2", default="B")
    ap.add_argument("--modules")
    a = ap.parse_args()
    vectors = load(set(a.modules.split(",")) if a.modules else None)
    steps = sum(len(v["steps"]) for v in vectors)
    ans = run_driver(a.driver, vectors)
    fails = check(vectors, ans)
    print(f"{a.name}: {steps - len(fails)}/{steps} steps conform ({len(vectors)} vectors, candidate-4 profile)")
    for f in fails[:10]:
        print("  FAIL", json.dumps(f)[:300])
    ok = not fails
    if a.driver2:
        ans2 = run_driver(a.driver2, vectors)
        f2 = check(vectors, ans2)
        diffs = [(v["id"], i) for v in vectors for i, (x, y) in enumerate(zip(ans[v["id"]], ans2[v["id"]])) if key(x) != key(y)]
        print(f"{a.name2}: {steps - len(f2)}/{steps} steps conform; differential {a.name} <-> {a.name2}: {len(diffs)} disagreements")
        for d in diffs[:10]:
            print("  DIFF", d)
        ok = ok and not f2 and not diffs
    print(f"CANDIDATE-4 CONFORMANCE: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
