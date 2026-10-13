#!/usr/bin/env python3
"""LP 0.2 conformance runner (PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1).

Feeds every vector of vectors/lp02-vectors.json to an implementation's driver (tests/DRIVER.md) and compares outcome,
code and the listed result fields. With --differential it runs two drivers on the same vectors and also reports every
step on which they disagree with each other — a disagreement means the specification is ambiguous or one
implementation is wrong; it is never hidden.

Usage:
  python run_conformance.py --driver "<your driver command>" [--name A] [--modules m1,m2]
  python run_conformance.py --differential --driver "<cmd A>" --driver2 "<cmd B>" [--json-out report.json]
"""

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent / "vectors" / "lp02-vectors.json"


def run_driver(cmd, vectors):
    # posix=False keeps Windows backslashes; a quoted token (a path with spaces) is unquoted here — block 60's clean room
    # found a quoted driver path handed to the driver with its quotes
    argv = cmd if isinstance(cmd, list) else [t[1:-1] if len(t) > 1 and t[0] == t[-1] and t[0] in "\"'" else t for t in shlex.split(cmd, posix=False)]
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=sys.stderr, text=True, encoding="utf-8", bufsize=1)
    answers = {}
    for v in vectors:
        proc.stdin.write(json.dumps({"id": v["id"], "context": v["context"], "steps": [{"op": s["op"], "input": s["input"]} for s in v["steps"]]}) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise SystemExit(f"driver ended before answering {v['id']}")
        out = json.loads(line)
        if out.get("id") != v["id"]:
            raise SystemExit(f"driver answered {out.get('id')} for {v['id']}")
        answers[v["id"]] = out.get("results", [])
    proc.stdin.close()
    proc.wait(timeout=30)
    return answers


def subset(expected, actual):
    """Every key of `expected` is in `actual` with an equal value (dicts compared recursively, the same way)."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and subset(v, actual[k]) for k, v in expected.items())
    return expected == actual


def check(vectors, answers):
    failures = []
    for v in vectors:
        got = answers.get(v["id"], [])
        for i, s in enumerate(v["steps"]):
            e = s["expect"]
            a = got[i] if i < len(got) else {"outcome": "MISSING"}
            ok = a.get("outcome") == e["outcome"]
            if ok and "code" in e:
                ok = a.get("code") == e["code"]
            if ok and "result" in e:
                ok = subset(e["result"], a.get("result"))
            if not ok:
                failures.append({"id": v["id"], "step": i, "op": s["op"], "expected": e, "got": a})
    return failures


def comparable(step_expect, answer):
    out = {"outcome": answer.get("outcome"), "code": answer.get("code")}
    if "result" in step_expect and isinstance(answer.get("result"), dict):
        out["result"] = {k: answer["result"].get(k) for k in step_expect["result"]}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)
    ap.add_argument("--driver2")
    ap.add_argument("--name", default="A")
    ap.add_argument("--name2", default="B")
    ap.add_argument("--differential", action="store_true")
    ap.add_argument("--vectors", default=str(VECTORS))
    ap.add_argument("--json-out")
    ap.add_argument("--modules", help="only the vectors of these modules (comma-separated) — an implementation of a profile (block 60)")
    args = ap.parse_args()
    doc = json.loads(Path(args.vectors).read_text(encoding="utf-8"))
    vectors = doc["vectors"]
    if args.modules:
        keep = set(args.modules.split(","))
        vectors = [v for v in vectors if v["module"] in keep]
    steps = sum(len(v["steps"]) for v in vectors)
    report = {"vectors": len(vectors), "steps": steps, "implementations": {}}
    runs = [(args.name, args.driver)] + ([(args.name2, args.driver2)] if args.driver2 else [])
    answers = {}
    for name, cmd in runs:
        answers[name] = run_driver(cmd, vectors)
        fails = check(vectors, answers[name])
        unsupported = sum(1 for r in answers[name].values() for a in r if a.get("outcome") == "UNSUPPORTED")
        report["implementations"][name] = {"failures": fails, "passed_steps": steps - len(fails), "unsupported_steps": unsupported}
        print(f"{name}: {steps - len(fails)}/{steps} steps conform ({len(vectors)} vectors){'' if not unsupported else f', {unsupported} unsupported'}")
        for f in fails[:40]:
            print(f"  FAIL {f['id']}[{f['step']}] {f['op']}: expected {json.dumps(f['expected'])} got {json.dumps(f['got'])}")
    if args.differential and len(runs) == 2:
        diffs = []
        a, b = answers[args.name], answers[args.name2]
        for v in vectors:
            for i, s in enumerate(v["steps"]):
                ra = comparable(s["expect"], a[v["id"]][i] if i < len(a[v["id"]]) else {})
                rb = comparable(s["expect"], b[v["id"]][i] if i < len(b[v["id"]]) else {})
                if ra != rb:
                    diffs.append({"id": v["id"], "step": i, "op": s["op"], args.name: ra, args.name2: rb})
        report["differential"] = {"disagreements": diffs, "compared_steps": steps}
        print(f"differential {args.name} vs {args.name2}: {len(diffs)} disagreements on {steps} steps")
        for d in diffs[:40]:
            print(f"  DIFF {d['id']}[{d['step']}] {d['op']}: {args.name} {json.dumps(d[args.name])} / {args.name2} {json.dumps(d[args.name2])}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    bad = any(r["failures"] or r["unsupported_steps"] for r in report["implementations"].values()) or bool(report.get("differential", {}).get("disagreements"))
    print("CONFORMANCE: " + ("FAIL" if bad else "PASS"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
