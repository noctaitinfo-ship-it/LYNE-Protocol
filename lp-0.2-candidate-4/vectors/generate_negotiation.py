#!/usr/bin/env python3
"""lp02-private-candidate-4 — VERSION-NEGOTIATION vectors (PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1).

candidate-3 <-> candidate-4 (+ candidate-1, LP 0.1): candidate-4 = candidate-3 + lp02.liveline/1 (the Live Line WebRTC
data-channel profile, a client-side module depending on lp02.federation). The module is used only when BOTH documents
list a common version and its dependency; a candidate-3 party stays candidate-3 (no silent upgrade), and a candidate-4
party meeting it applies no profile (no silent imitation); a replayed older document that drops the module is a downgrade
the ratchet refuses; a forged document cannot add it. Client declarations: under the candidate-4 profile `lp02.liveline`
(version 1) is a client-side module; under candidate-3 / candidate-1 it is unknown and refused.

The vector context member `candidate` selects the profile (conformance/DRIVER.md); absent = candidate-1.
Same deterministic test keys, JCS and detached-JWS profile as candidate-1's generator (SPEC §2). Standalone.
Output: negotiation-vectors.json next to this file.
"""

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NOW = 1790000000
OUT = Path(__file__).resolve().parent / "negotiation-vectors.json"
C4 = "lp02-private-candidate-4"
C3 = "lp02-private-candidate-3"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jcs(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class Key:
    def __init__(self, label):
        self.sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("LP02 TEST KEY " + label).encode()).digest())
        self.pub = b64u(self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.kid = b64u(hashlib.sha256(jcs({"crv": "Ed25519", "kty": "OKP", "x": self.pub})).digest())


def sign(obj, typ, key):
    body = {k: v for k, v in obj.items() if k != "signature"}
    header = b64u(jcs({"alg": "EdDSA", "kid": key.kid, "typ": typ}))
    return {**obj, "signature": header + ".." + b64u(key.sk.sign((header + "." + b64u(jcs(body))).encode()))}


PROV_A, PROV_B = Key("provider A"), Key("provider B")
A, B = "https://a.example", "https://b.example"
C1_MODULES = {"lp02.federation": [1], "lp02.admission": [1], "lp02.request": [1], "lp02.wake": [1], "lp02.linecaps": [1], "lp02.referral": [1], "lp02.exit": [1]}
C3_MODULES = {**C1_MODULES, "lp02.channel": [2]}
C4_MODULES = {**C3_MODULES, "lp02.liveline": [1]}
C1_RESULT = {k: 1 for k in C1_MODULES}
C3_RESULT = {**C1_RESULT, "lp02.channel": 2}
C4_RESULT = {**C3_RESULT, "lp02.liveline": 1}


def doc(key, origin, modules, lp=("0.1", "0.2"), issued=NOW - 60):
    d = {"v": "lp02.federation/1", "origin": origin, "tenant": "default", "implementation": {"name": "vector", "version": "1"},
         "lp": list(lp), "modules": json.loads(json.dumps(modules)), "provider_pub": key.pub, "issued_at": issued, "expires_at": issued + 3600}
    return sign(d, "lp02.federation", key)


def step(op, inp, outcome, code=None, result=None):
    e = {"outcome": outcome}
    if code:
        e["code"] = code
    if result is not None:
        e["result"] = result
    return {"op": op, "input": inp, "expect": e}


V = []


def vec(vid, steps, note, candidate=C4, **ctx):
    context = {"now": NOW, **({"candidate": candidate} if candidate else {}), **ctx}
    V.append({"id": vid, "module": "lp02.federation", "note": note, "context": context, "steps": steps})


def neg(local, remote, outcome="ACCEPT", code=None, result=None, required=None):
    return step("fed.negotiate", {"local": local, "remote": remote, **({"required": required} if required else {})}, outcome, code, result)


def cm(modules, outcome="ACCEPT", code=None):
    return step("fed.client_modules", {"body": {"v": "lp02.federation/1", "modules": modules}}, outcome, code,
                {"modules": modules} if outcome == "ACCEPT" else None)


LOC_C4, LOC_C3 = doc(PROV_A, A, C4_MODULES), doc(PROV_A, A, C3_MODULES)
REM_C4, REM_C3, REM_C1 = doc(PROV_B, B, C4_MODULES), doc(PROV_B, B, C3_MODULES), doc(PROV_B, B, C1_MODULES)
REM_LP01 = doc(PROV_B, B, {}, lp=["0.1"])

vec("C4N-c4-c4", [neg(LOC_C4, REM_C4, result={"lp": "0.2", "modules": C4_RESULT}, required=["lp02.liveline", "lp02.channel"])],
    "two candidate-4 parties: lp02.liveline version 1 (and lp02.channel version 2) negotiated")
vec("C4N-c4-local-c3-remote", [neg(LOC_C4, REM_C3, result={"lp": "0.2", "modules": C3_RESULT})],
    "candidate-4 meets candidate-3: lp02.liveline is absent — the candidate-4 party applies no profile (LP 0.1 §8.3 alone), never imitates it")
vec("C4N-c3-remote-required", [neg(LOC_C4, REM_C3, "REFUSE", "MODULE_UNSUPPORTED", required=["lp02.liveline"])],
    "a candidate-4 party that requires the profile refuses a candidate-3 peer")
vec("C4N-c3-local-c4-remote", [neg(LOC_C3, REM_C4, result={"lp": "0.2", "modules": C3_RESULT})],
    "a candidate-3 party meeting a candidate-4 peer: lp02.liveline is unknown to it and ignored (no silent upgrade)", candidate=C3)
vec("C4N-c3-local-c4-remote-required", [neg(LOC_C3, REM_C4, "REFUSE", "MODULE_UNSUPPORTED", required=["lp02.liveline"])],
    "a candidate-3 party cannot negotiate the profile even when asked to", candidate=C3)
vec("C4N-c1-peer", [neg(LOC_C4, REM_C1, result={"lp": "0.2", "modules": C1_RESULT})], "a candidate-1 peer: candidate-1's set, no channel, no profile")
vec("C4N-lp01-peer", [neg(LOC_C4, REM_LP01, result={"lp": "0.1", "modules": {}})], "an LP 0.1 peer: no module at all; Lines follow LP 0.1 §8.3")
vec("C4N-peer-liveline-1-and-2", [neg(LOC_C4, doc(PROV_B, B, {**C3_MODULES, "lp02.liveline": [1, 2]}), result={"lp": "0.2", "modules": C4_RESULT})],
    "a peer that supports /1 and a future /2: the highest common version, 1")
vec("C4N-peer-liveline-2-only", [neg(LOC_C4, doc(PROV_B, B, {**C3_MODULES, "lp02.liveline": [2]}), result={"lp": "0.2", "modules": C3_RESULT})],
    "a peer with a future /2 only: no common version, absent — never a silent /1 imitation")
vec("C4N-missing-dependency", [neg(LOC_C4, doc(PROV_B, B, {"lp02.liveline": [1]}), result={"lp": "0.2", "modules": {}})],
    "a document listing lp02.liveline without lp02.federation: the dependency is missing, the module is absent")
newer, older = doc(PROV_B, B, C4_MODULES, issued=NOW - 10), doc(PROV_B, B, C3_MODULES, issued=NOW - 100)
vec("C4N-downgrade-replay", [neg(LOC_C4, newer, result={"lp": "0.2", "modules": C4_RESULT}), neg(LOC_C4, older, "REFUSE", "FED_DOWNGRADE")],
    "a replayed older document of the same peer without the profile: a downgrade, refused", ratchet={})
vec("C4N-forged-upgrade", [neg(LOC_C4, {**REM_C3, "modules": C4_MODULES}, "REFUSE", "FED_DOC_INVALID")],
    "a candidate-3 document rewritten to claim lp02.liveline after signing: refused")
vec("C4N-cm-c4-liveline", [cm({"lp02.request": [1], "lp02.linecaps": [1], "lp02.liveline": [1]})], "candidate-4 profile: the client declares lp02.liveline/1")
vec("C4N-cm-c4-liveline-and-channel", [cm({"lp02.channel": [2], "lp02.liveline": [1]})], "candidate-4 profile: candidate-3's channel /2 and the profile")
vec("C4N-cm-c3-liveline", [cm({"lp02.liveline": [1]}, "REFUSE", "CLIENT_MODULES_INVALID")], "candidate-3 profile: lp02.liveline is unknown, refused", candidate=C3)
vec("C4N-cm-c1-liveline", [cm({"lp02.liveline": [1]}, "REFUSE", "CLIENT_MODULES_INVALID")], "candidate-1 profile: unknown, refused", candidate=None)
vec("C4N-cm-c4-thread", [cm({"lp02.thread": [1]}, "REFUSE", "CLIENT_MODULES_INVALID")], "lp02.thread is not a module of any candidate")

if __name__ == "__main__":
    OUT.write_text(json.dumps({"kind": "lyne-lp02-vectors/1", "candidate": C4, "status": "PRIVATE - EXPERIMENTAL - UNPUBLISHED - NOT LP 0.1",
                               "now": NOW, "count": len(V), "vectors": V}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(V)} vectors -> {OUT}")
