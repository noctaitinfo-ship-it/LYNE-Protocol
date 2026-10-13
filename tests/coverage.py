#!/usr/bin/env python3
"""What the conformance vectors cover, by category — standard library only.

Classifies every step of the LP 0.2 candidate-4 vectors — all four sets: candidate-1's core set, channel /2, liveline,
negotiation — (and the LP 0.1 example set) into the categories an
implementer asks about: positive, negative, canonicalization, signature, expiry, replay, wrong actor, wrong authority,
wrong Thing, wrong version, required module unsupported, downgrade. A step may fall into several categories.

Usage: python tests/coverage.py              → a table
       python tests/coverage.py --markdown   → the table as Markdown (as in CONFORMANCE.md)
       python tests/coverage.py --json       → counts and example vector ids
"""

import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PKG = Path(__file__).resolve().parent.parent
VECTOR_SETS = [PKG / "lp-0.2-candidate-4" / "vectors" / n for n in ("lp02-vectors.json", "channel2-vectors.json", "liveline-vectors.json", "negotiation-vectors.json")]
LP01_EXAMPLES = PKG / "lp-0.1" / "examples"

# (category, rule over (vector id, op, outcome, code)) — codes and ops as the candidate's error registry names them
CATEGORIES = [
    ("positive (ACCEPT)", lambda i, op, out, code: out == "ACCEPT"),
    ("negative (REFUSE / IGNORE)", lambda i, op, out, code: out in ("REFUSE", "IGNORE")),
    ("canonicalization (strict JSON, JCS, RFC 9421 content digest)", lambda i, op, out, code: op in ("json.parse", "rfc9421.verify") or code in ("INVALID_JSON", "DIGEST_MISMATCH") or "noncanonical" in i),
    ("signature", lambda i, op, out, code: op == "jws.verify" or bool(code and re.search(r"SIGNATURE", code))),
    ("expiry / staleness", lambda i, op, out, code: bool(code and re.search(r"EXPIRED|_STALE$|^OPEN_STALE$", code)) or bool(re.search(r"expir", i, re.I))),
    ("replay", lambda i, op, out, code: bool(code and re.search(r"REPLAY|_USED$", code)) or bool(re.search(r"replay", i, re.I))),
    ("wrong actor", lambda i, op, out, code: code in ("OPEN_ACTOR_NOT_ADMITTED", "NOT_YOUR_TURN", "INTRO_TARGET_MISMATCH", "CAP_DIRECTION", "TRUST_ORIGIN_MISMATCH") or bool(re.search(r"wrong-actor", i))),
    ("wrong authority (key, scope, revoked, widened)", lambda i, op, out, code: code in ("KEY_MISMATCH", "KEY_REVOKED", "DELEGATION_DENIED", "DELEGATION_WIDENS", "DELEGATION_SCOPE", "DELEGATION_REVOKED", "PROOF_AUTHORITY", "PROOF_SCOPE", "RESULT_SCOPE", "INTRO_SCOPE", "RECOVERY_REVOKED") or bool(re.search(r"wrong-key|other-key|forged", i))),
    ("wrong Thing", lambda i, op, out, code: bool(re.search(r"wrong-thing|other-thing|cross-thing|different-thing", i))),
    ("live-line data-channel profile (lp02.liveline)", lambda i, op, out, code: op.startswith("ll.") or code in ("LINE_PROFILE_INVALID", "LINE_PROFILE_MISMATCH")),
    ("wrong version", lambda i, op, out, code: code in ("VERSION_UNSUPPORTED", "MODULE_VERSION_UNSUPPORTED") or bool(code and code.endswith("EPOCH_STALE")) or bool(re.search(r"version|-v2|other-v", i))),
    ("required module unsupported / not negotiated", lambda i, op, out, code: code in ("MODULE_UNSUPPORTED", "MODULE_NOT_NEGOTIATED", "NONCE_REQUIRED")),
    ("downgrade attack", lambda i, op, out, code: code == "FED_DOWNGRADE" or "downgrade" in i or i == "NC-omitted-required"),
]


def lp02_steps():
    for f in VECTOR_SETS:
        for v in json.loads(f.read_text(encoding="utf-8"))["vectors"]:
            for s in v["steps"]:
                yield v["id"], s["op"], s["expect"]["outcome"], s["expect"].get("code")


def coverage():
    rows = []
    steps = list(lp02_steps())
    for name, rule in CATEGORIES:
        hits = [(i, op, out, code) for i, op, out, code in steps if rule(i, op, out, code)]
        ids = sorted({h[0] for h in hits})
        rows.append({"category": name, "steps": len(hits), "vectors": len(ids), "examples": ids[:4]})
    lp01 = {d.name: len(list(d.glob("*.json"))) for d in sorted(LP01_EXAMPLES.iterdir()) if d.is_dir()}
    return {"lp02_vectors": len({s[0] for s in steps}), "lp02_steps": len(steps), "categories": rows, "lp01_examples": lp01}


def markdown(c):
    lines = [f"LP 0.2 candidate-4 (all four vector sets): {c['lp02_vectors']} vectors, {c['lp02_steps']} steps.", "",
             "| category | steps | vectors | e.g. |", "|---|---:|---:|---|"]
    for r in c["categories"]:
        lines.append(f"| {r['category']} | {r['steps']} | {r['vectors']} | {', '.join(f'`{x}`' for x in r['examples'])} |")
    lines += ["", "LP 0.1 examples: " + ", ".join(f"{k} {v}" for k, v in c["lp01_examples"].items()) + "."]
    return "\n".join(lines)


if __name__ == "__main__":
    c = coverage()
    if "--json" in sys.argv:
        print(json.dumps(c, indent=1))
    elif "--markdown" in sys.argv:
        print(markdown(c))
    else:
        for r in c["categories"]:
            print(f"{r['category']:<62} {r['steps']:>4} steps  {r['vectors']:>4} vectors")
