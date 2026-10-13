#!/usr/bin/env python3
"""Generates the LP 0.2 conformance vectors (PRIVATE · EXPERIMENTAL · UNPUBLISHED · NOT LP 0.1).

Independent of both implementations: its own JCS, b64u, kid, detached JWS and RFC 9421 code (SPEC.md §2), deterministic
test keys from labels, a fixed clock. Output: vectors/lp02-vectors.json. Run: python generate.py
"""

import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

NOW = 1790000000
OUT = Path(__file__).resolve().parent / "lp02-vectors.json"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jcs(v):
    # the LP value subset: strings, integers, booleans, null, arrays, objects (and non-integer numbers only where the
    # vector deliberately breaks the rule; Python and JavaScript print them identically for the values used here)
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Key:
    def __init__(self, label):
        self.sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("LP02 TEST KEY " + label).encode()).digest())
        raw = self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pub = b64u(raw)
        self.kid = b64u(hashlib.sha256(jcs({"crv": "Ed25519", "kty": "OKP", "x": self.pub})).digest())


def sign(obj, typ, key):
    body = {k: v for k, v in obj.items() if k != "signature"}
    header = b64u(jcs({"alg": "EdDSA", "kid": key.kid, "typ": typ}))
    sig = key.sk.sign((header + "." + b64u(jcs(body))).encode())
    out = dict(obj)
    out["signature"] = header + ".." + b64u(sig)
    return out


def rid(label):
    return b64u(hashlib.sha256(("LP02 ID " + label).encode()).digest()[:16])


def digest_of(body):
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode() + ":"


def http_sign(key, method, uri, created, body=None):
    params = f'("@method" "@target-uri"{" " + chr(34) + "content-digest" + chr(34) if body else ""});created={created};keyid="{key.kid}";alg="ed25519"'
    lines = [f'"@method": {method}', f'"@target-uri": {uri}']
    headers = {}
    if body:
        d = digest_of(body)
        lines.append(f'"content-digest": {d}')
        headers["content-digest"] = d
    lines.append(f'"@signature-params": {params}')
    sig = key.sk.sign("\n".join(lines).encode())
    headers["signature-input"] = "sig1=" + params
    headers["signature"] = "sig1=:" + base64.b64encode(sig).decode() + ":"
    return headers


PROV_A = Key("provider A")
PROV_B = Key("provider B")
OTHER = Key("someone else")
CLIENT = Key("client of thing T")
OPENER = Key("one-time opener")
A = "https://a.example"
B = "https://b.example"
ALL_MODULES = {"lp02.federation": [1], "lp02.admission": [1], "lp02.request": [1], "lp02.wake": [1], "lp02.linecaps": [1], "lp02.referral": [1], "lp02.exit": [1]}
V = []


def vec(id_, module, steps, context=None, note=""):
    V.append({"id": id_, "module": module, "note": note, "context": {"now": NOW, **(context or {})}, "steps": steps})


def step(op, input_, outcome, code=None, result=None):
    e = {"outcome": outcome}
    if code:
        e["code"] = code
    if result is not None:
        e["result"] = result
    return {"op": op, "input": input_, "expect": e}


# ---------------------------------------------------------------- common: JSON and JWS

vec("X-json-ok", "common", [step("json.parse", {"text": '{"a":1,"b":{"c":[1,2]}}'}, "ACCEPT")])
vec("X-json-dupkey", "common", [step("json.parse", {"text": '{"a":1,"a":2}'}, "REFUSE", "INVALID_JSON")], note="SPEC 2.1.1")
vec("X-json-dupkey-nested", "common", [step("json.parse", {"text": '{"a":{"b":1,"b":1}}'}, "REFUSE", "INVALID_JSON")])
vec("X-json-escaped-dup", "common", [step("json.parse", {"text": '{"a":1,"\\u0061":2}'}, "REFUSE", "INVALID_JSON")], note="the same name written two ways")
vec("X-json-malformed", "common", [step("json.parse", {"text": '{"a":1,'}, "REFUSE", "INVALID_JSON")])
obj = sign({"v": "lp02.wake/1", "x": 1}, "lp02.wake", PROV_A)
vec("X-jws-ok", "common", [step("jws.verify", {"object": obj, "pub": PROV_A.pub, "typ": "lp02.wake"}, "ACCEPT")])
vec("X-typ-mismatch", "common", [step("jws.verify", {"object": obj, "pub": PROV_A.pub, "typ": "lp02.referral"}, "REFUSE", "SIGNATURE_INVALID")], note="SPEC 2.2.4 domain separation")
vec("X-jws-other-key", "common", [step("jws.verify", {"object": obj, "pub": OTHER.pub, "typ": "lp02.wake"}, "REFUSE", "SIGNATURE_INVALID")])
t = dict(obj); t["x"] = 2
vec("X-jws-tampered", "common", [step("jws.verify", {"object": t, "pub": PROV_A.pub, "typ": "lp02.wake"}, "REFUSE", "SIGNATURE_INVALID")])
hdr = obj["signature"].split("..")
extra = b64u(jcs({"alg": "EdDSA", "crit": [], "kid": PROV_A.kid, "typ": "lp02.wake"}))
nc_header = b64u(json.dumps({"typ": "lp02.wake", "kid": PROV_A.kid, "alg": "EdDSA"}, separators=(",", ":")).encode())
nc_sig = PROV_A.sk.sign((nc_header + "." + b64u(jcs({k: v for k, v in obj.items() if k != "signature"}))).encode())
vec("X-jws-noncanonical-header", "common", [step("jws.verify", {"object": {**obj, "signature": nc_header + ".." + b64u(nc_sig)}, "pub": PROV_A.pub, "typ": "lp02.wake"}, "REFUSE", "SIGNATURE_INVALID")],
    note="SPEC 2.2.2: the header is JCS-serialized; a validly signed header in another member order is refused")
vec("X-jws-extra-header", "common", [step("jws.verify", {"object": {**obj, "signature": extra + ".." + hdr[1]}, "pub": PROV_A.pub, "typ": "lp02.wake"}, "REFUSE", "SIGNATURE_INVALID")])

# ---------------------------------------------------------------- lp02.federation


def doc(key, origin, lp=("0.1", "0.2"), modules=None, issued=NOW - 60, expires=None, **over):
    d = {"v": "lp02.federation/1", "origin": origin, "tenant": "default", "implementation": {"name": "vector", "version": "1"},
         "lp": list(lp), "modules": copy.deepcopy(ALL_MODULES if modules is None else modules), "provider_pub": key.pub,
         "issued_at": issued, "expires_at": (issued + 3600) if expires is None else expires}
    d.update(over)
    return sign(d, "lp02.federation", key)


LOCAL = doc(PROV_A, A)
REMOTE = doc(PROV_B, B)
full = {k: 1 for k in ALL_MODULES}
vec("F-ok", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": REMOTE, "required": ["lp02.admission", "lp02.referral"]}, "ACCEPT", result={"lp": "0.2", "modules": full})])
old = doc(PROV_B, B, lp=["0.1"], modules={})
vec("F-lp01-peer", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": old}, "ACCEPT", result={"lp": "0.1", "modules": {}})], note="LP 0.1 stays usable")
vec("F-lp01-required", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": old, "required": ["lp02.request"]}, "REFUSE", "MODULE_UNSUPPORTED")], note="never imitated")
vec("F-no-common-lp", "lp02.federation", [step("fed.negotiate", {"local": doc(PROV_A, A, lp=["0.2"]), "remote": old}, "REFUSE", "VERSION_UNSUPPORTED")])
vec("F-unknown-module", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, modules={**ALL_MODULES, "lp02.future": [1]})}, "ACCEPT", result={"modules": full})], note="unknown modules are ignored")
vec("F-module-version-gap", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, modules={**ALL_MODULES, "lp02.admission": [2]})}, "ACCEPT",
    result={"modules": {k: 1 for k in ALL_MODULES if k not in ("lp02.admission", "lp02.referral")}})], note="no common admission version; referral loses its dependency")
vec("F-highest-common", "lp02.federation", [step("fed.negotiate", {"local": doc(PROV_A, A, modules={"lp02.federation": [1], "lp02.request": [1, 2]}),
    "remote": doc(PROV_B, B, modules={"lp02.federation": [1], "lp02.request": [1, 2, 3]})}, "ACCEPT", result={"modules": {"lp02.federation": 1, "lp02.request": 2}})])
tam = dict(REMOTE); tam["lp"] = ["0.1"]
vec("F-tampered", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": tam}, "REFUSE", "FED_DOC_INVALID")])
vec("F-typ", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": sign({k: v for k, v in REMOTE.items() if k != "signature"}, "lp02.referral", PROV_B)}, "REFUSE", "FED_DOC_INVALID")])
vec("F-unknown-member", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, note="hello")}, "REFUSE", "FED_DOC_INVALID")])
vec("F-v2", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, v="lp02.federation/2")}, "REFUSE", "MODULE_VERSION_UNSUPPORTED")])
vec("F-other-v", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, v="lyne-federation/0.1-exp")}, "REFUSE", "FED_DOC_INVALID")])
vec("F-expired", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, issued=NOW - 3700, expires=NOW - 100)}, "REFUSE", "FED_DOC_STALE")])
vec("F-expires-now", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, issued=NOW - 3600, expires=NOW)}, "REFUSE", "FED_DOC_STALE")], note="edge: expires_at <= now")
vec("F-future", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, issued=NOW + 301)}, "REFUSE", "FED_DOC_STALE")])
vec("F-skew-edge", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, issued=NOW + 300)}, "ACCEPT")], note="edge: issued_at = now + 300")
vec("F-longlife", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, issued=NOW - 10, expires=NOW - 10 + 86401)}, "REFUSE", "FED_DOC_INVALID")])
vec("F-nonint", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, issued=NOW - 0.5)}, "REFUSE", "FED_DOC_INVALID")], note="SPEC 2.1.2 integers only")
vec("F-expect-origin", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": REMOTE, "expect_origin": "https://c.example"}, "REFUSE", "FED_DOC_INVALID")])
vec("F-pin-key", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": REMOTE, "expect_pub": OTHER.pub}, "REFUSE", "FED_DOC_INVALID")], note="a pinned origin with another key")
newer = doc(PROV_B, B, issued=NOW - 10)
older = doc(PROV_B, B, issued=NOW - 100, modules={"lp02.federation": [1]})
vec("F-downgrade-replay", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": newer}, "ACCEPT"),
    step("fed.negotiate", {"local": LOCAL, "remote": older}, "REFUSE", "FED_DOWNGRADE")], context={"ratchet": {}}, note="SPEC 3.2.4")
vec("F-newer-fewer", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, issued=NOW - 100)}, "ACCEPT"),
    step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, issued=NOW - 10, modules={"lp02.federation": [1]})}, "ACCEPT", result={"modules": {"lp02.federation": 1}})],
    context={"ratchet": {}}, note="a peer's own newer document may list fewer modules")
vec("CM-ok", "lp02.federation", [step("fed.client_modules", {"body": {"v": "lp02.federation/1", "modules": {"lp02.request": [1], "lp02.exit": [1]}}}, "ACCEPT")])
vec("CM-provider-module", "lp02.federation", [step("fed.client_modules", {"body": {"v": "lp02.federation/1", "modules": {"lp02.admission": [1]}}}, "REFUSE", "CLIENT_MODULES_INVALID")])
vec("CM-empty", "lp02.federation", [step("fed.client_modules", {"body": {"v": "lp02.federation/1", "modules": {"lp02.request": []}}}, "REFUSE", "CLIENT_MODULES_INVALID")])
vec("CM-v2", "lp02.federation", [step("fed.client_modules", {"body": {"v": "lp02.federation/2", "modules": {}}}, "REFUSE", "MODULE_VERSION_UNSUPPORTED")])
vec("CM-v2-extra", "lp02.federation", [step("fed.client_modules", {"body": {"v": "lp02.federation/2", "modules": {}, "x": 1}}, "REFUSE", "CLIENT_MODULES_INVALID")],
    note="members first, then the version (found by implementation C, block 57)")
vec("CM-extra", "lp02.federation", [step("fed.client_modules", {"body": {"v": "lp02.federation/1", "modules": {}, "message": "hi"}}, "REFUSE", "CLIENT_MODULES_INVALID")])

# ---------------------------------------------------------------- lp02.admission


def descriptor(key=PROV_A, typ="lp02.descriptor", **over):
    d = {"v": "lp02.admission/1", "aud": A, "tenant": "default", "provider_pub": key.pub, "issued_at": iso(NOW - 60), "valid_until": iso(NOW + 3000), "points": []}
    d.update(over)
    return sign(d, typ, key)


vec("D-ok", "lp02.admission", [step("adm.descriptor", {"descriptor": descriptor(), "expect_pub": PROV_A.pub}, "ACCEPT")])
d = descriptor(); d["points"] = [{"point_id": rid("x")}]
vec("D-tampered", "lp02.admission", [step("adm.descriptor", {"descriptor": d}, "REFUSE", "FED_DOC_INVALID")])
vec("D-stale", "lp02.admission", [step("adm.descriptor", {"descriptor": descriptor(valid_until=iso(NOW))}, "REFUSE", "FED_DOC_STALE")])
vec("D-wrong-key", "lp02.admission", [step("adm.descriptor", {"descriptor": descriptor(), "expect_pub": OTHER.pub}, "REFUSE", "KEY_MISMATCH")])
vec("D-typ", "lp02.admission", [step("adm.descriptor", {"descriptor": descriptor(typ="lp02.open")}, "REFUSE", "FED_DOC_INVALID")])
vec("D-v2", "lp02.admission", [step("adm.descriptor", {"descriptor": descriptor(v="lp02.admission/2")}, "REFUSE", "MODULE_VERSION_UNSUPPORTED")])

PID = rid("point P")
POINT = {"point_id": PID, "label": "Plumbing desk", "service": "repair.plumbing", "purposes": [{"code": "leak", "label": "A leak"}, {"code": "quote", "label": "A quote"}],
         "admission": {"mode": "public", "humans": "allow", "agents": "allow", "referral": False, "max_pending": 50, "max_open": 500},
         "grant": {"channels": ["data"], "line_max_seconds": 600, "lifetime_seconds": 3600}, "status": "ACTIVE", "valid_until": iso(NOW + 7 * 86400)}  # block 53: every point has a finite expiry


def point(**adm):
    p = copy.deepcopy(POINT)
    p["admission"].update(adm)
    return p


def open_req(key=OPENER, typ="lp02.open", drop=None, nonce_label="n1", **over):
    r = {"v": "lp02.admission/1", "aud": A, "point_id": PID, "purpose": "leak", "actor": "human", "opener_pub": key.pub, "nonce": rid(nonce_label), "created": NOW}
    r.update(over)
    if drop:
        r.pop(drop)
    return sign(r, typ, key)


def adm(id_, req, outcome, code=None, ctx=None, note=""):
    vec(id_, "lp02.admission", [step("adm.open", {"request": req}, outcome, code, {"admitted": True} if outcome == "ACCEPT" else None)], {"origin": A, "point": POINT, "codes": [], "peers": [], **(ctx or {})}, note)


adm("O-ok", open_req(), "ACCEPT")
vec("O-replay", "lp02.admission", [step("adm.open", {"request": open_req()}, "ACCEPT"), step("adm.open", {"request": open_req()}, "REFUSE", "OPEN_REPLAY")], {"origin": A, "point": POINT, "codes": [], "peers": []})
adm("O-stale", open_req(created=NOW - 301), "REFUSE", "OPEN_STALE")
adm("O-skew-edge", open_req(created=NOW - 300), "ACCEPT", note="edge: created = now - 300")
adm("O-future", open_req(created=NOW + 301), "REFUSE", "OPEN_STALE")
bad = open_req(); bad["purpose"] = "quote"
adm("O-changed-after-signing", bad, "REFUSE", "OPEN_SIGNATURE_INVALID")
adm("O-typ", open_req(typ="lp02.descriptor"), "REFUSE", "OPEN_SIGNATURE_INVALID")
r = open_req(); r2 = dict(r); r2["opener_pub"] = OTHER.pub
adm("O-wrong-actor-key", r2, "REFUSE", "OPEN_SIGNATURE_INVALID", note="the signature must be by opener_pub")
adm("O-cross-provider", open_req(aud=B), "REFUSE", "OPEN_INVALID", note="an OPEN for provider B used at A")
adm("O-cross-point", open_req(point_id=rid("another point")), "REFUSE", "OPEN_INVALID")
adm("O-point-revoked", open_req(), "REFUSE", "OPEN_POINT_UNKNOWN", ctx={"point": {**POINT, "status": "REVOKED"}})
adm("O-point-expired", open_req(), "REFUSE", "OPEN_POINT_UNKNOWN", ctx={"point": {**POINT, "valid_until": iso(NOW - 1)}})
adm("O-v2", open_req(v="lp02.admission/2"), "REFUSE", "MODULE_VERSION_UNSUPPORTED")
# ---- block 53: no permanent point — a null expiry is never "forever"; a point may end with its first admission
adm("O-point-no-expiry", open_req(), "REFUSE", "OPEN_POINT_UNKNOWN", ctx={"point": {**POINT, "valid_until": None}}, note="no finite expiry: not open (never 'forever')")
ONCE = {**POINT, "admission": {**POINT["admission"], "expire_on_first": True}}
vec("O-once", "lp02.admission", [step("adm.open", {"request": open_req(nonce_label="once-1")}, "ACCEPT", None, {"admitted": True}),
    step("adm.open", {"request": open_req(nonce_label="once-2")}, "REFUSE", "OPEN_POINT_UNKNOWN")], {"origin": A, "point": ONCE, "codes": [], "peers": []},
    note="EXPIRE_ON_FIRST_ADMISSION: the point is gone once the relationship exists")
vec("O-not-once", "lp02.admission", [step("adm.open", {"request": open_req(nonce_label="many-1")}, "ACCEPT", None, {"admitted": True}),
    step("adm.open", {"request": open_req(nonce_label="many-2")}, "ACCEPT", None, {"admitted": True})], {"origin": A, "point": POINT, "codes": [], "peers": []})
PV = {k: v for k, v in POINT.items() if k in ("point_id", "label", "service", "purposes")}
PV.update({"admission": {"mode": "public", "humans": "allow", "agents": "allow"}, "channels": ["data"], "valid_until": iso(NOW + 86400), "open": f"{A}/o/{PID}"})
vec("D-point-expiring", "lp02.admission", [step("adm.descriptor", {"descriptor": descriptor(points=[PV]), "expect_pub": PROV_A.pub}, "ACCEPT")])
vec("D-point-no-expiry", "lp02.admission", [step("adm.descriptor", {"descriptor": descriptor(points=[{**PV, "valid_until": None}]), "expect_pub": PROV_A.pub}, "REFUSE", "FED_DOC_INVALID")],
    note="a descriptor never advertises a permanent point")
adm("O-other-v", open_req(v="lyne-open/0.1-exp"), "REFUSE", "OPEN_INVALID")
adm("O-content", open_req(message="call me"), "REFUSE", "OPEN_INVALID", note="no free text")
adm("O-unknown-member", open_req(extra=1), "REFUSE", "OPEN_INVALID")
adm("O-missing-member", open_req(drop="nonce"), "REFUSE", "OPEN_INVALID")
adm("O-purpose-unknown", open_req(purpose="sale"), "REFUSE", "OPEN_PURPOSE_UNKNOWN")
adm("O-actor-not-admitted", open_req(actor="agent"), "REFUSE", "OPEN_ACTOR_NOT_ADMITTED", ctx={"point": point(agents="deny")})
adm("O-actor-invalid", open_req(actor="robot"), "REFUSE", "OPEN_INVALID")
adm("O-nonint", open_req(created=NOW + 0.5), "REFUSE", "OPEN_INVALID")
adm("O-token-required", open_req(), "REFUSE", "OPEN_TOKEN_REQUIRED", ctx={"point": point(mode="token")})
# SPEC 4.2 order (37F): the point's policy before any cryptography — several faults at once, the policy one wins
forged = open_req(); forged["purpose"] = "leak"; forged["nonce"] = rid("forged")  # the signature no longer matches
adm("O-order-actor-before-signature", dict(forged, actor="agent"), "REFUSE", "OPEN_ACTOR_NOT_ADMITTED", ctx={"point": point(agents="deny")}, note="37F: policy before cryptography")
adm("O-order-token-before-signature", dict(forged, admit=b64u(b"y" * 32)), "REFUSE", "OPEN_TOKEN_INVALID", ctx={"point": point(mode="token")}, note="37F: an unknown code costs no signature check")
adm("O-order-required-before-stale", open_req(created=NOW - 301), "REFUSE", "OPEN_TOKEN_REQUIRED", ctx={"point": point(mode="token")}, note="37F: a token point refuses a code-less request before freshness")
adm("O-order-referral-before-signature", dict(forged, fed_referral={"v": "lp02.referral/1"}), "REFUSE", "OPEN_REFERRAL_INVALID", note="37F: a point without referral refuses before cryptography")
CODE = b64u(hashlib.sha256(b"LP02 admission code").digest())
adm("O-token-ok", open_req(admit=CODE), "ACCEPT", ctx={"point": point(mode="token"), "codes": [{"code": CODE, "uses_remaining": 1, "expires": NOW + 600}]})
adm("O-token-unknown", open_req(admit=b64u(b"x" * 32)), "REFUSE", "OPEN_TOKEN_INVALID", ctx={"point": point(mode="token"), "codes": [{"code": CODE, "uses_remaining": 1, "expires": NOW + 600}]})
adm("O-token-expired", open_req(admit=CODE), "REFUSE", "OPEN_TOKEN_INVALID", ctx={"point": point(mode="token"), "codes": [{"code": CODE, "uses_remaining": 1, "expires": NOW - 1}]})
vec("O-token-reuse", "lp02.admission", [step("adm.open", {"request": open_req(admit=CODE, nonce_label="t1")}, "ACCEPT"), step("adm.open", {"request": open_req(admit=CODE, nonce_label="t2")}, "REFUSE", "OPEN_TOKEN_INVALID")],
    {"origin": A, "point": point(mode="token"), "codes": [{"code": CODE, "uses_remaining": 1, "expires": NOW + 600}], "peers": []})
adm("O-precedence", dict(open_req(created=NOW - 400), signature="eyJ..AAAA"), "REFUSE", "OPEN_STALE", note="stale and badly signed: the earlier check wins (SPEC 4.2 order)")

# ---------------------------------------------------------------- lp02.referral (inside OPEN at B)


def referral(key=PROV_A, typ="lp02.referral", nonce="r1", **over):
    r = {"v": "lp02.referral/1", "iss": A, "aud": B, "point_id": PID, "purpose": "leak", "nonce": rid(nonce), "exp": NOW + 3000}
    r.update(over)
    return sign(r, typ, key)


def open_at_b(ref, nonce="b1", **over):
    r = {"v": "lp02.admission/1", "aud": B, "point_id": PID, "purpose": "leak", "actor": "human", "opener_pub": OPENER.pub, "nonce": rid(nonce), "created": NOW, "fed_referral": ref}
    r.update(over)
    return sign(r, "lp02.open", OPENER)


PIN_A = {"origin": A, "provider_pub": PROV_A.pub, "points": [PID], "modules": {"lp02.admission": 1, "lp02.referral": 1, "lp02.federation": 1}}
B_CTX = {"origin": B, "point": point(mode="token", referral=True), "codes": [], "peers": [PIN_A]}


def ref(id_, req, outcome, code=None, ctx=None, note=""):
    vec(id_, "lp02.referral", [step("adm.open", {"request": req}, outcome, code, {"admitted": True} if outcome == "ACCEPT" else None)], {**B_CTX, **(ctx or {})}, note)


ref("R-ok", open_at_b(referral()), "ACCEPT")
vec("R-replay", "lp02.referral", [step("adm.open", {"request": open_at_b(referral(), nonce="b1")}, "ACCEPT"), step("adm.open", {"request": open_at_b(referral(), nonce="b2")}, "REFUSE", "OPEN_REFERRAL_USED")], B_CTX)
ref("R-unpinned", open_at_b(referral()), "REFUSE", "OPEN_REFERRAL_UNTRUSTED", ctx={"peers": []})
ref("R-point-not-allowed", open_at_b(referral()), "REFUSE", "OPEN_REFERRAL_UNTRUSTED", ctx={"peers": [{**PIN_A, "points": [rid("other point")]}]})
ref("R-no-module", open_at_b(referral()), "REFUSE", "OPEN_REFERRAL_UNTRUSTED", ctx={"peers": [{**PIN_A, "modules": {"lp02.admission": 1, "lp02.federation": 1}}]}, note="pinned, but referral not negotiated")
ref("R-forged-key", open_at_b(referral(key=OTHER)), "REFUSE", "OPEN_REFERRAL_UNTRUSTED", note="A's origin, another key")
tr = referral(); tr["purpose"] = "quote"
ref("R-tampered", open_at_b(tr, purpose="quote"), "REFUSE", "OPEN_REFERRAL_UNTRUSTED")
ref("R-typ", open_at_b(referral(typ="lp02.open")), "REFUSE", "OPEN_REFERRAL_UNTRUSTED")
ref("R-cross-provider", open_at_b(referral(aud="https://c.example")), "REFUSE", "OPEN_REFERRAL_INVALID", note="a referral to C used at B")
ref("R-purpose-mismatch", open_at_b(referral(), purpose="quote"), "REFUSE", "OPEN_REFERRAL_INVALID")
ref("R-expired", open_at_b(referral(exp=NOW)), "REFUSE", "OPEN_REFERRAL_INVALID")
ref("R-exp-too-far", open_at_b(referral(exp=NOW + 3600 + 301)), "REFUSE", "OPEN_REFERRAL_INVALID")
ref("R-v2", open_at_b(referral(v="lp02.referral/2")), "REFUSE", "MODULE_VERSION_UNSUPPORTED")
ref("R-extra", open_at_b(referral(customer="x")), "REFUSE", "OPEN_REFERRAL_INVALID", note="a referral cannot name the customer")
ref("R-with-admit", open_at_b(referral(), admit=CODE), "REFUSE", "OPEN_REFERRAL_INVALID")
ref("R-point-without-referral", open_at_b(referral()), "REFUSE", "OPEN_REFERRAL_INVALID", ctx={"point": point(mode="token", referral=False)})

# ---------------------------------------------------------------- RFC 9421 (SPEC 2.3)

TID = rid("thing T")
URI = f"{A}/t/{TID}/requests"
BIND = {"client_kid": CLIENT.kid, "client_thing_pub": CLIENT.pub}


def hv(id_, steps, binding=BIND, note=""):
    vec(id_, "common.rfc9421", steps, {"binding": binding}, note)


def hreq(method="GET", uri=URI, body="", key=CLIENT, created=NOW, sign_body=None, headers=None):
    h = http_sign(key, method, uri, created, sign_body if sign_body is not None else (body if body and body.strip() not in ("", "{}") else None))
    if headers:
        h.update(headers)
    return {"method": method, "target_uri": uri, "headers": h, "body": body}


hv("H-ok", [step("rfc9421.verify", hreq(), "ACCEPT")])
WURI = f"{A}/t/{TID}/wake/{rid('w1')}"
BODY = '{"url":"https://agent.example/w/abc"}'
hv("H-digest-ok", [step("rfc9421.verify", hreq("POST", WURI, BODY), "ACCEPT")])
hv("H-empty-object", [step("rfc9421.verify", hreq("POST", f"{A}/t/{TID}/leave", "{}"), "ACCEPT")], note="{} needs no digest")
nod = http_sign(CLIENT, "POST", WURI, NOW, None)
hv("H-body-without-digest", [step("rfc9421.verify", {"method": "POST", "target_uri": WURI, "headers": nod, "body": BODY}, "REFUSE", "DIGEST_MISMATCH")], note="SPEC 2.3 (g)")
sw = hreq("POST", WURI, BODY)
sw["body"] = '{"url":"https://evil.example/w/abc"}'
hv("H-body-swapped", [step("rfc9421.verify", sw, "REFUSE", "DIGEST_MISMATCH")])
fmt = hreq("POST", WURI, BODY); fmt["headers"]["content-digest"] = fmt["headers"]["content-digest"].replace("sha-256=:", "sha-256= :")
hv("H-digest-format", [step("rfc9421.verify", fmt, "REFUSE", "DIGEST_MISMATCH")], note="exactly one sha-256 value, no whitespace")
hv("H-stale", [step("rfc9421.verify", hreq(created=NOW - 301), "REFUSE", "SIGNATURE_INVALID")])
hv("H-skew-edge", [step("rfc9421.verify", hreq(created=NOW + 300), "ACCEPT")])
hv("H-replay", [step("rfc9421.verify", hreq(), "ACCEPT"), step("rfc9421.verify", hreq(), "REFUSE", "SIGNATURE_INVALID")])
hv("H-other-key", [step("rfc9421.verify", hreq(key=OTHER), "REFUSE", "KEY_MISMATCH")], note="wrong actor")
hv("H-no-binding", [step("rfc9421.verify", hreq(), "REFUSE", "KEY_MISMATCH")], binding=None)
xt = hreq(); xt["target_uri"] = f"{A}/t/{rid('thing U')}/requests"
hv("H-cross-thing", [step("rfc9421.verify", xt, "REFUSE", "SIGNATURE_INVALID")], note="signed for Thing T, presented for Thing U")
xm = hreq(); xm["method"] = "POST"
hv("H-method", [step("rfc9421.verify", xm, "REFUSE", "SIGNATURE_INVALID")])
bh = hreq(); bh["headers"]["signature-input"] = bh["headers"]["signature-input"].replace('alg="ed25519"', 'alg="hmac-sha256"')
hv("H-bad-headers", [step("rfc9421.verify", bh, "REFUSE", "SIGNATURE_INVALID")])
xa = hreq(uri=f"{B}/t/{TID}/requests"); xa["target_uri"] = URI
hv("H-cross-provider", [step("rfc9421.verify", xa, "REFUSE", "SIGNATURE_INVALID")], note="signed for provider B's origin")

# ---------------------------------------------------------------- lp02.request

TEMPLATE = {"code": "visit-slot", "label": "Choose a visit time", "waiting_on": "client", "role": None, "options": [{"code": "tue", "label": "Tuesday"}, {"code": "wed", "label": "Wednesday"}],
            "deadline_seconds": 86400, "on_deadline": {"action": "escalate"}}
RID = rid("request R")


def thing(**over):
    t = {"thing_id": TID, "state": {"version": 3, "status": "WAITING", "waiting_on": "client", "next_action": "Choose a visit time"}, "binding": {"client_kid": CLIENT.kid},
         "declared": {"modules": {"lp02.request": [1], "lp02.wake": [1], "lp02.exit": [1]}}, "left": False,
         "grants": [{"grant_id": rid("g1"), "status": "REDEEMED", "active_line": False}], "templates": [TEMPLATE],
         "requests": [{"request_id": RID, "thing_id": TID, "template": "visit-slot", "label": "Choose a visit time", "waiting_on": "client", "role": None, "options": TEMPLATE["options"],
                       "deadline": iso(NOW + 80000), "on_deadline": {"action": "escalate"}, "status": "OPEN", "created_at": iso(NOW - 100), "state_version": 3}], "wakes": []}
    t.update(over)
    return t


def q(id_, op, input_, outcome, code=None, result=None, **thing_over):
    vec(id_, "lp02.request", [step(op, input_, outcome, code, result)], {"thing": thing(**thing_over)})


ANS = {"status": "WAITING", "waiting_on": "provider", "next_action": "Choose a visit time: Wednesday", "deadline": None}
q("Q-answer-ok", "req.answer", {"request_id": RID, "option": "wed", "by": "client"}, "ACCEPT", result={"next_state": ANS})
q("Q-not-your-turn", "req.answer", {"request_id": RID, "option": "wed", "by": "provider"}, "REFUSE", "NOT_YOUR_TURN")
q("Q-option-unknown", "req.answer", {"request_id": RID, "option": "sun", "by": "client"}, "REFUSE", "OPTION_UNKNOWN")
q("Q-unknown", "req.answer", {"request_id": rid("no such request"), "option": "wed", "by": "client"}, "REFUSE", "REQUEST_UNKNOWN")
q("Q-wrong-thing", "req.answer", {"request_id": RID, "option": "wed", "by": "client"}, "REFUSE", "REQUEST_UNKNOWN",
  requests=[{**thing()["requests"][0], "thing_id": rid("thing U")}])
q("Q-decided", "req.answer", {"request_id": RID, "option": "wed", "by": "client"}, "REFUSE", "REQUEST_DECIDED",
  requests=[{**thing()["requests"][0], "status": "ANSWERED", "answer": "tue"}])
q("Q-state-conflict", "req.answer", {"request_id": RID, "option": "wed", "by": "client"}, "REFUSE", "REQUEST_DECIDED",
  state={"version": 4, "status": "WAITING", "waiting_on": "provider", "next_action": "Something else"})
vec("Q-twice", "lp02.request", [step("req.answer", {"request_id": RID, "option": "wed", "by": "client"}, "ACCEPT", result={"next_state": ANS}),
    step("req.answer", {"request_id": RID, "option": "tue", "by": "client"}, "REFUSE", "REQUEST_DECIDED")], {"thing": thing()}, note="exactly one answer decides")
CREATED = {"status": "WAITING", "waiting_on": "client", "next_action": "Choose a visit time", "deadline": iso(NOW + 86400)}
q("Q-create-ok", "req.create", {"template": "visit-slot"}, "ACCEPT", result={"next_state": CREATED}, requests=[], state={"version": 2, "status": "OPEN", "waiting_on": None, "next_action": None})
q("Q-create-not-declared", "req.create", {"template": "visit-slot"}, "REFUSE", "MODULE_NOT_NEGOTIATED", requests=[], declared=None,
  state={"version": 2, "status": "OPEN", "waiting_on": None, "next_action": None})
q("Q-create-other-version", "req.create", {"template": "visit-slot"}, "REFUSE", "MODULE_NOT_NEGOTIATED", requests=[], declared={"modules": {"lp02.request": [2]}},
  state={"version": 2, "status": "OPEN", "waiting_on": None, "next_action": None})
q("Q-create-left", "req.create", {"template": "visit-slot"}, "REFUSE", "CLIENT_LEFT", requests=[], left=True, state={"version": 2, "status": "OPEN", "waiting_on": None, "next_action": None})
q("Q-create-no-binding", "req.create", {"template": "visit-slot"}, "REFUSE", "BINDING_MISSING", requests=[], binding=None, state={"version": 2, "status": "OPEN", "waiting_on": None, "next_action": None})
q("Q-create-open-exists", "req.create", {"template": "visit-slot"}, "REFUSE", "REQUEST_OPEN")

# ---------------------------------------------------------------- lp02.wake

WID = rid("wake W")


def wsub(id_, body, outcome, code=None, wake_id=WID, local=False, **thing_over):
    vec(id_, "lp02.wake", [step("wake.subscribe", {"wake_id": wake_id, "body": body}, outcome, code)], {"thing": thing(**thing_over), "local": local})


wsub("W-sub-ok", {"url": "https://agent.example/w/abc", "max_per_day": 5}, "ACCEPT")
wsub("W-sub-default-cap", {"url": "https://agent.example/w/abc"}, "ACCEPT")
wsub("W-sub-ip", {"url": "https://203.0.113.9/w"}, "REFUSE", "WAKE_INVALID")
wsub("W-sub-http", {"url": "http://agent.example/w"}, "REFUSE", "WAKE_INVALID")
wsub("W-sub-credentials", {"url": "https://user:pw@agent.example/w"}, "REFUSE", "WAKE_INVALID")
wsub("W-sub-extra", {"url": "https://agent.example/w", "note": "x"}, "REFUSE", "WAKE_INVALID")
wsub("W-sub-cap-high", {"url": "https://agent.example/w", "max_per_day": 101}, "REFUSE", "WAKE_INVALID")
wsub("W-sub-cap-float", {"url": "https://agent.example/w", "max_per_day": 2.5}, "REFUSE", "WAKE_INVALID")
wsub("W-sub-id", {"url": "https://agent.example/w"}, "REFUSE", "WAKE_INVALID", wake_id="short")
wsub("W-sub-left", {"url": "https://agent.example/w"}, "REFUSE", "CLIENT_LEFT", left=True)
wsub("W-sub-closed", {"url": "https://agent.example/w"}, "REFUSE", "THING_CLOSED", state={"version": 9, "status": "CLOSED", "waiting_on": None, "next_action": None})
wsub("W-sub-other-thing", {"url": "https://agent.example/w"}, "REFUSE", "WAKE_INVALID", wakes=[{"wake_id": WID, "thing_id": rid("thing U")}])
wsub("W-sub-limit", {"url": "https://agent.example/w"}, "REFUSE", "WAKE_LIMIT", wakes=[{"wake_id": rid("w a"), "thing_id": TID}, {"wake_id": rid("w b"), "thing_id": TID}])
wsub("W-sub-local", {"url": "http://127.0.0.1:9999/w"}, "ACCEPT", local=True)


def signal(key=PROV_A, typ="lp02.wake", sent=NOW, **over):
    s = {"v": "lp02.wake/1", "wake_id": WID, "event": "thing.changed", "sent_at": iso(sent)}
    s.update(over)
    return sign(s, typ, key)


REG = {WID: {"provider_pub": PROV_A.pub, "last_sent_at": None}}


def wv(id_, sig, outcome, code=None, reg=REG):
    vec(id_, "lp02.wake", [step("wake.verify", {"signal": sig}, outcome, code)], {"registered": reg})


wv("W-sig-ok", signal(), "ACCEPT")
vec("W-sig-replay", "lp02.wake", [step("wake.verify", {"signal": signal()}, "ACCEPT"), step("wake.verify", {"signal": signal()}, "REFUSE", "WAKE_REPLAY")], {"registered": REG}, note="duplicate delivery")
wv("W-sig-older", signal(sent=NOW - 60), "REFUSE", "WAKE_REPLAY", reg={WID: {"provider_pub": PROV_A.pub, "last_sent_at": iso(NOW)}})
wv("W-sig-unknown", signal(wake_id=rid("not mine")), "REFUSE", "WAKE_UNKNOWN")
wv("W-sig-forged", signal(key=OTHER), "REFUSE", "WAKE_UNVERIFIED")
wv("W-sig-typ", signal(typ="lp02.referral"), "REFUSE", "WAKE_UNVERIFIED")
wv("W-sig-content", signal(thing_id=TID), "REFUSE", "WAKE_INVALID", )
wv("W-sig-v2", signal(v="lp02.wake/2"), "REFUSE", "MODULE_VERSION_UNSUPPORTED")
wv("W-sig-event", signal(event="message.new"), "REFUSE", "WAKE_INVALID")

# ---------------------------------------------------------------- lp02.exit

GRANTS = [{"grant_id": rid("g1"), "status": "REDEEMED", "active_line": False}, {"grant_id": rid("g2"), "status": "ISSUED", "active_line": False},
          {"grant_id": rid("g3"), "status": "EXHAUSTED", "active_line": False}, {"grant_id": rid("g4"), "status": "EXPIRED", "active_line": False}]
EXIT_STATE = {"status": "WAITING", "waiting_on": "provider", "next_action": "The customer left: Choose a visit time", "deadline": None}
vec("E-ok", "lp02.exit", [step("exit.leave", {"kid": CLIENT.kid}, "ACCEPT", result={"left": True, "next_state": EXIT_STATE,
    "grants": {rid("g1"): "REVOKED", rid("g2"): "REVOKED", rid("g3"): "REVOKED", rid("g4"): "EXPIRED"}})], {"thing": thing(grants=GRANTS)})
vec("E-line-active", "lp02.exit", [step("exit.leave", {"kid": CLIENT.kid}, "REFUSE", "LINE_ACTIVE")],
    {"thing": thing(grants=[{"grant_id": rid("g3"), "status": "EXHAUSTED", "active_line": True}])}, note="a Line holds the State: end it first")
vec("E-other-key", "lp02.exit", [step("exit.leave", {"kid": OTHER.kid}, "REFUSE", "KEY_MISMATCH")], {"thing": thing()})
vec("E-idempotent", "lp02.exit", [step("exit.leave", {"kid": CLIENT.kid}, "ACCEPT", result={"left": True}), step("exit.leave", {"kid": CLIENT.kid}, "ACCEPT", result={"left": True})], {"thing": thing()})
vec("E-then-request", "lp02.exit", [step("exit.leave", {"kid": CLIENT.kid}, "ACCEPT"), step("req.create", {"template": "visit-slot"}, "REFUSE", "CLIENT_LEFT")],
    {"thing": thing(requests=[], state={"version": 2, "status": "OPEN", "waiting_on": None, "next_action": None})}, note="nothing new may wait on the client")
vec("E-then-wake", "lp02.exit", [step("exit.leave", {"kid": CLIENT.kid}, "ACCEPT"), step("wake.subscribe", {"wake_id": WID, "body": {"url": "https://agent.example/w"}}, "REFUSE", "CLIENT_LEFT")],
    {"thing": thing(), "local": False})

# ---------------------------------------------------------------- lp02.linecaps

MAN = {"expires_s": 600, "caps": [
    {"kind": "struct", "code": "meter", "label": "Meter", "from": "client", "max_records": 2, "fields": [{"code": "kwh", "label": "kWh", "type": "number", "min": 0, "max": 100}]},
    {"kind": "file", "code": "photo", "label": "Photo", "from": "client", "types": ["image/png"], "max_bytes": 8388608, "max_files": 3},
    {"kind": "stream", "code": "bar", "label": "Pressure", "from": "client", "unit": "bar", "min": 0, "max": 16, "max_hz": 2},
    {"kind": "control", "code": "valve", "label": "Valve", "from": "provider", "commands": [{"code": "close", "label": "Close", "params": []}]}]}


def f(**o):
    return json.dumps({"lyne": "lp02.linecaps/1", **o}, separators=(",", ":"))


vec("LC-manifest-ok", "lp02.linecaps", [step("lc.manifest", {"manifest": MAN}, "ACCEPT")])
for name, mut in [("control-both", lambda m: m["caps"][3].update({"from": "both"})), ("text-param", lambda m: m["caps"][3]["commands"][0].update({"params": [{"code": "w", "label": "W", "type": "text", "max_chars": 5}]})),
                  ("file-too-big", lambda m: m["caps"][1].update({"max_bytes": 8388609})), ("rate-high", lambda m: m["caps"][2].update({"max_hz": 51})),
                  ("unknown-kind", lambda m: m["caps"][0].update({"kind": "chat"})), ("extra-member", lambda m: m.update({"note": "x"})), ("dup-codes", lambda m: m["caps"][1].update({"code": "meter"}))]:
    mm = copy.deepcopy(MAN)
    mut(mm)
    vec(f"LC-manifest-{name}", "lp02.linecaps", [step("lc.manifest", {"manifest": mm}, "REFUSE", "MANIFEST_INVALID")])


def prov_session(*frames):
    """A provider endpoint: hello, its manifest, the client's accept of everything, then the given client frames."""
    steps = [step("lc.open", {"side": "provider"}, "ACCEPT"), step("lc.receive", {"text": f(t="hello", versions=[1]), "at_ms": 0}, "ACCEPT"),
             step("lc.propose", {"manifest": MAN, "at_ms": 0}, "ACCEPT"), step("lc.receive", {"text": f(t="accept", caps=["meter", "photo", "bar", "valve"]), "at_ms": 0}, "ACCEPT")]
    return steps + list(frames)


def rec(text, at, outcome, code=None, result=None):
    return step("lc.receive", {"text": text, "at_ms": at}, outcome, code, result)


vec("LC-no-hello", "lp02.linecaps", [step("lc.open", {"side": "provider"}, "ACCEPT"), step("lc.propose", {"manifest": MAN, "at_ms": 0}, "REFUSE", "MODULE_NOT_NEGOTIATED")], note="an LP 0.1 client never says hello")
vec("LC-hello-unknown-version", "lp02.linecaps", [step("lc.open", {"side": "provider"}, "ACCEPT"), rec(f(t="hello", versions=[7]), 0, "ACCEPT"),
    step("lc.propose", {"manifest": MAN, "at_ms": 0}, "REFUSE", "MODULE_NOT_NEGOTIATED")])
vec("LC-second-hello", "lp02.linecaps", prov_session(rec(f(t="hello", versions=[1]), 10, "REFUSE", "CAP_UNEXPECTED")))
vec("LC-struct-ok", "lp02.linecaps", prov_session(rec(f(t="struct", cap="meter", values={"kwh": 12}), 10, "ACCEPT", result={"violations": 0})))
vec("LC-struct-range", "lp02.linecaps", prov_session(rec(f(t="struct", cap="meter", values={"kwh": 101}), 10, "REFUSE", "CAP_INVALID")))
vec("LC-struct-extra", "lp02.linecaps", prov_session(rec(f(t="struct", cap="meter", values={"kwh": 1, "note": "x"}), 10, "REFUSE", "CAP_INVALID")))
vec("LC-struct-limit", "lp02.linecaps", prov_session(rec(f(t="struct", cap="meter", values={"kwh": 1}), 10, "ACCEPT"), rec(f(t="struct", cap="meter", values={"kwh": 2}), 20, "ACCEPT"),
    rec(f(t="struct", cap="meter", values={"kwh": 3}), 30, "REFUSE", "CAP_LIMIT")))
vec("LC-not-accepted", "lp02.linecaps", prov_session(rec(f(t="struct", cap="nothing", values={}), 10, "REFUSE", "CAP_NOT_ACCEPTED")))
vec("LC-direction", "lp02.linecaps", prov_session(rec(f(t="command", cap="valve", id="abcdefgh", command="close", params={}), 10, "REFUSE", "CAP_DIRECTION")))
vec("LC-expired", "lp02.linecaps", prov_session(rec(f(t="struct", cap="meter", values={"kwh": 1}), 600001, "REFUSE", "CAP_EXPIRED")))
vec("LC-expiry-edge", "lp02.linecaps", prov_session(rec(f(t="struct", cap="meter", values={"kwh": 1}), 600000, "ACCEPT")))
vec("LC-dupkey", "lp02.linecaps", prov_session(rec('{"lyne":"lp02.linecaps/1","t":"struct","cap":"meter","cap":"photo","values":{}}', 10, "REFUSE", "CAP_MALFORMED")))
vec("LC-nested-lyne", "lp02.linecaps", prov_session(rec('{"x":{"lyne":"lp02.linecaps/1","t":"struct"}}', 10, "REFUSE", "CAP_MALFORMED")), note="SPEC 7.5: matched by the regex, not a top-level frame")
vec("LC-version9", "lp02.linecaps", prov_session(rec(json.dumps({"lyne": "lp02.linecaps/9", "t": "struct", "cap": "meter", "values": {}}), 10, "REFUSE", "CAP_MALFORMED")))
vec("LC-not-ours", "lp02.linecaps", prov_session(rec("Here is the photo of the boiler", 10, "IGNORE"), rec('{"jsonrpc":"2.0","method":"message/send","id":1}', 10, "IGNORE")))
vec("LC-unexpected-manifest", "lp02.linecaps", prov_session(rec(f(t="manifest", manifest=MAN), 10, "REFUSE", "CAP_UNEXPECTED")))
vec("LC-rate", "lp02.linecaps", prov_session(rec(f(t="sample", cap="bar", v=3, at=0), 1000, "ACCEPT"), rec(f(t="sample", cap="bar", v=3, at=0), 1399, "REFUSE", "CAP_RATE"),
    rec(f(t="sample", cap="bar", v=3, at=0), 1400, "ACCEPT")), note="edge: 0.8 x 500 ms = 400 ms after the last accepted sample")
vec("LC-sample-range", "lp02.linecaps", prov_session(rec(f(t="sample", cap="bar", v=17, at=0), 10, "REFUSE", "CAP_INVALID")))
DATA = bytes(range(256)) * 4
H = b64u(hashlib.sha256(DATA).digest())
vec("LC-file-ok", "lp02.linecaps", prov_session(rec(f(**{"t": "file-start", "cap": "photo", "id": "file0001", "name": "a.png", "type": "image/png", "size": len(DATA), "chunks": 1, "sha256": H}), 10, "ACCEPT"),
    rec(f(t="file-chunk", cap="photo", id="file0001", n=0, data=base64.b64encode(DATA).decode()), 20, "ACCEPT"), step("lc.settle", {}, "ACCEPT", result={"files": 1, "violations": 0})))
vec("LC-file-hash", "lp02.linecaps", prov_session(rec(f(**{"t": "file-start", "cap": "photo", "id": "file0001", "name": "a.png", "type": "image/png", "size": len(DATA), "chunks": 1, "sha256": "A" * 43}), 10, "ACCEPT"),
    rec(f(t="file-chunk", cap="photo", id="file0001", n=0, data=base64.b64encode(DATA).decode()), 20, "REFUSE", "CAP_HASH"), step("lc.settle", {}, "ACCEPT", result={"files": 0, "violations": 1, "last": "CAP_HASH"})))
vec("LC-file-type", "lp02.linecaps", prov_session(rec(f(**{"t": "file-start", "cap": "photo", "id": "file0001", "name": "a.exe", "type": "application/x-msdownload", "size": 10, "chunks": 1, "sha256": H}), 10, "REFUSE", "CAP_INVALID")))
vec("LC-chunk-order", "lp02.linecaps", prov_session(rec(f(**{"t": "file-start", "cap": "photo", "id": "file0002", "name": "b.png", "type": "image/png", "size": 30000, "chunks": 3, "sha256": H}), 10, "ACCEPT"),
    rec(f(t="file-chunk", cap="photo", id="file0002", n=1, data=base64.b64encode(b"x" * 12288).decode()), 20, "REFUSE", "CAP_FRAMING")))
vec("LC-chunk-not-base64", "lp02.linecaps", prov_session(rec(f(**{"t": "file-start", "cap": "photo", "id": "file0006", "name": "f.png", "type": "image/png", "size": 1, "chunks": 1, "sha256": H}), 10, "ACCEPT"),
    rec(f(t="file-chunk", cap="photo", id="file0006", n=0, data="YQ"), 20, "REFUSE", "CAP_FRAMING")), note="unpadded base64: lenient decoders differ, so the spec refuses it")
mp = copy.deepcopy(MAN); mp["caps"][3]["commands"][0]["params"] = "none"
vec("LC-manifest-params-type", "lp02.linecaps", [step("lc.manifest", {"manifest": mp}, "REFUSE", "MANIFEST_INVALID")])
vec("W-sub-no-url-left", "lp02.wake", [step("wake.subscribe", {"wake_id": WID, "body": {"max_per_day": 3}}, "REFUSE", "WAKE_INVALID")], {"thing": thing(left=True), "local": False}, note="members are checked before the departure")
# SPEC 7.1 rule 0 (block 36): the client endpoint's decision to send `hello` — only to a provider whose own signed,
# current federation document lists LP 0.2 and a common lp02.linecaps version. None = the runtime has no
# /t/<id>/modules route (an LP 0.1 runtime): never a frame to it.
def hello(id_, document, outcome, code=None, note="", pub=None):
    vec(id_, "lp02.linecaps", [step("lc.hello_allowed", {"document": document, "provider_pub": pub or PROV_B.pub}, outcome, code)], note=note)


hello("LC-hello-ok", doc(PROV_B, B), "ACCEPT")
hello("LC-hello-no-route", None, "REFUSE", "MODULE_UNSUPPORTED", "an LP 0.1 runtime: no document, no frame")
hello("LC-hello-lp01", doc(PROV_B, B, lp=["0.1"], modules={}), "REFUSE", "MODULE_UNSUPPORTED", "a provider that speaks LP 0.1 only")
hello("LC-hello-no-module", doc(PROV_B, B, modules={k: v for k, v in ALL_MODULES.items() if k != "lp02.linecaps"}), "REFUSE", "MODULE_UNSUPPORTED")
hello("LC-hello-v2-only", doc(PROV_B, B, modules={**ALL_MODULES, "lp02.linecaps": [2]}), "REFUSE", "MODULE_UNSUPPORTED", "no common version: never approximated")
hello("LC-hello-other-provider", doc(OTHER, B), "REFUSE", "FED_DOC_INVALID", "a valid document of another provider key")
tam_h = dict(doc(PROV_B, B, modules={k: v for k, v in ALL_MODULES.items() if k != "lp02.linecaps"}))
tam_h["modules"] = copy.deepcopy(ALL_MODULES)
hello("LC-hello-tampered", tam_h, "REFUSE", "FED_DOC_INVALID", "a module added after signing")
hello("LC-hello-expired", doc(PROV_B, B, issued=NOW - 3700, expires=NOW - 100), "REFUSE", "FED_DOC_STALE")
hello("LC-hello-typ", sign({k: v for k, v in doc(PROV_B, B).items() if k != "signature"}, "lp02.referral", PROV_B), "REFUSE", "FED_DOC_INVALID")
hello("LC-hello-doc-v2", doc(PROV_B, B, v="lp02.federation/2"), "REFUSE", "MODULE_VERSION_UNSUPPORTED")
hello("LC-hello-unknown-member", doc(PROV_B, B, note="x"), "REFUSE", "FED_DOC_INVALID")
hello("LC-hello-member-order", doc(PROV_B, B, implementation={"version": "1", "name": "vector"}), "ACCEPT", note="JSON member order carries no meaning")
vec("F-member-order", "lp02.federation", [step("fed.negotiate", {"local": LOCAL, "remote": doc(PROV_B, B, implementation={"version": "1", "name": "vector"})}, "ACCEPT")],
    note="JSON member order carries no meaning (found in block 36)")

big = 8388608
vec("LC-budget", "lp02.linecaps", prov_session(rec(f(**{"t": "file-start", "cap": "photo", "id": "file0003", "name": "c.png", "type": "image/png", "size": big, "chunks": 683, "sha256": H}), 10, "ACCEPT"),
    rec(f(**{"t": "file-start", "cap": "photo", "id": "file0004", "name": "d.png", "type": "image/png", "size": big, "chunks": 683, "sha256": H}), 20, "ACCEPT"),
    rec(f(**{"t": "file-start", "cap": "photo", "id": "file0005", "name": "e.png", "type": "image/png", "size": 1, "chunks": 1, "sha256": H}), 30, "REFUSE", "CAP_BUDGET")), note="16 MiB held per endpoint")
vec("LC-violation-limit", "lp02.linecaps", prov_session(*[rec(f(t="struct", cap="meter", values={"kwh": -1}), 10 + i, "REFUSE", "CAP_INVALID", {"violations": i + 1, "limit": i == 4}) for i in range(5)]))


# ---------------------------------------------------------------- lp02.result (block 43): a RESULT without a Line
RES_V = "lp02.result/1"
RT = rid("thing of the async result")
RQ = rid("request done?")
CLIENT_NEW = Key("client new device")


def question(**over):
    q = {"request_id": RQ, "thing_id": RT, "template": "visit-done", "label": "Is the repair done?",
         "options": [{"code": "fixed", "label": "Yes, it works"}, {"code": "not-fixed", "label": "No, book again"}, {"code": "later", "label": "Ask me later"}],
         "conclusion": {"fixed": "repair-done", "not-fixed": "repair-failed"},
         "deadline": iso(NOW + 3600), "created_at": iso(NOW - 600)}
    q.update(over)
    return q


def q_hash(q):
    return b64u(hashlib.sha256(jcs(q)).digest())


def c_body(q):
    return jcs({"v": RES_V, "question": q_hash(q)}).decode()


def answer(q, option="fixed", key=CLIENT, created=NOW - 60, aud=A, body_q=None, uri_option=None, uri_request=None):
    uri = f"{aud}/t/{q['thing_id']}/requests/{uri_request or q['request_id']}/conclude/{uri_option or option}"
    h = http_sign(key, "POST", uri, created, c_body(body_q or q))
    return {"option": option, "created": created, "kid": key.kid, "signature_input": h["signature-input"], "signature": h["signature"]}


def aresult(q=None, ans=None, outcome=None, key=PROV_A, typ="lp02.result", epoch=1, aud=A, result_id=None, sign_it=True, **over):
    q = q or question()
    ans = ans or answer(q)
    body = {"v": RES_V, "result_id": result_id or rid("async result"), "thing_id": q["thing_id"], "aud": aud,
            "outcome": outcome if outcome is not None else q["conclusion"].get(ans["option"], "repair-done"), "epoch": epoch,
            "issued_at": iso(NOW), "basis": {"kind": "request_answer", "question": q, "answer": ans}}
    body.update(over)
    return sign(body, typ, key) if sign_it else body


RTHING = {"thing_id": RT, "aud": A, "provider_pub": PROV_A.pub, "closed_at": None}
RBIND = [{"epoch": 1, "client_pub": CLIENT.pub, "bound_at": iso(NOW - 3000), "revoked_at": None}]


def ar(id_, result, outcome, code=None, res=None, thing=None, bindings=None, accepted=None, note=""):
    vec(id_, "lp02.result", [step("ares.verify", {"result": result}, outcome, code, res)],
        {"thing": thing or RTHING, "bindings": bindings or RBIND, "accepted": accepted or []}, note)


ok_r = aresult()
ar("AR-valid", ok_r, "ACCEPT", res={"outcome": "repair-done", "option": "fixed"}, note="the client's signed concluding choice is the Result's evidence")
ar("AR-idempotent", ok_r, "ACCEPT", accepted=[ok_r["result_id"]], note="the same Result verified again")
ar("AR-duplicate", aresult(result_id=rid("second result")), "REFUSE", "RESULT_EXISTS", accepted=[ok_r["result_id"]], note="one async Result per Thing")
# the provider changes what was agreed
q0 = question()
ar("AR-changed-answer", aresult(ans=dict(answer(q0), option="not-fixed")), "REFUSE", "RESULT_BASIS_INVALID", note="the client signed 'fixed', the provider claims 'not-fixed'")
ar("AR-changed-outcome", aresult(outcome="repair-failed"), "REFUSE", "RESULT_OUTCOME_MISMATCH", note="the provider substitutes another outcome")
tam = dict(ok_r)
tam["outcome"] = "repair-failed"
ar("AR-changed-outcome-unsigned", tam, "REFUSE", "SIGNATURE_INVALID", note="changed after the provider signed")
q_meaning = question(conclusion={"fixed": "warranty-waived", "not-fixed": "repair-failed"})
ar("AR-changed-meaning", aresult(q=q_meaning, ans=answer(q_meaning, body_q=q0)), "REFUSE", "RESULT_BASIS_INVALID", note="the question's meaning was changed after the client signed it")
ar("AR-wrong-request", aresult(q=question(request_id=rid("other request")), ans=answer(question(request_id=rid("other request")), uri_request=RQ)), "REFUSE", "RESULT_BASIS_INVALID", note="the answer was to another request")
ar("AR-unknown-option", aresult(ans=dict(answer(q0), option="maybe"), outcome="repair-done"), "REFUSE", "OPTION_UNKNOWN")
ar("AR-not-agreed", aresult(ans=answer(q0, option="later"), outcome="repair-done"), "REFUSE", "RESULT_NOT_AGREED", note="a non-concluding answer is not an agreement; CLOSED may exist without a Result")
# time
ar("AR-stale", aresult(ans=answer(q0, created=NOW + 3600 + 301)), "REFUSE", "RESULT_STALE", note="answered after the deadline (beyond the clock skew)")
ar("AR-before-question", aresult(ans=answer(q0, created=NOW - 600 - 301)), "REFUSE", "RESULT_STALE", note="signed before the question existed (beyond the clock skew)")
ar("AR-skew-tolerated", aresult(ans=answer(q0, created=NOW - 600 - 120)), "ACCEPT", res={"outcome": "repair-done"}, note="a client clock 2 minutes behind: as accepted as its signature")
ar("AR-after-closure", ok_r, "REFUSE", "THING_CLOSED", thing={**RTHING, "closed_at": iso(NOW - 120)}, note="the customer answered after the provider closed")
# authority
ar("AR-revoked-key", ok_r, "REFUSE", "KEY_REVOKED", bindings=[{"epoch": 1, "client_pub": CLIENT.pub, "bound_at": iso(NOW - 3000), "revoked_at": iso(NOW - 120)}])
ar("AR-stale-epoch", ok_r, "REFUSE", "RESULT_EPOCH_STALE", bindings=[{**RBIND[0], "revoked_at": iso(NOW - 120)}, {"epoch": 2, "client_pub": CLIENT_NEW.pub, "bound_at": iso(NOW - 120), "revoked_at": None}],
   note="the old key answered after the relationship moved to a new device")
ar("AR-rebind-later", ok_r, "ACCEPT", res={"outcome": "repair-done"}, bindings=[{**RBIND[0], "revoked_at": iso(NOW + 600)}, {"epoch": 2, "client_pub": CLIENT_NEW.pub, "bound_at": iso(NOW + 600), "revoked_at": None}],
   note="an agreement made before a later device move stays valid")
ar("AR-wrong-key", aresult(ans=answer(q0, key=OTHER)), "REFUSE", "KEY_MISMATCH")
inv = answer(q0, key=PROV_A)
ar("AR-invented-consent", aresult(ans={**inv, "kid": CLIENT.kid, "signature_input": inv["signature_input"].replace(PROV_A.kid, CLIENT.kid)}), "REFUSE", "RESULT_BASIS_INVALID",
   note="the provider signs the 'customer's' answer itself")
# scope
ar("AR-different-thing", ok_r, "REFUSE", "RESULT_SCOPE", thing={**RTHING, "thing_id": rid("another thing")})
ar("AR-different-tenant", aresult(aud=B, ans=answer(q0, aud=B)), "REFUSE", "RESULT_SCOPE", note="valid at another deployment (aud)")
ar("AR-different-provider", aresult(key=PROV_B), "REFUSE", "SIGNATURE_INVALID")
ar("AR-typ", aresult(typ="lp02.wake"), "REFUSE", "SIGNATURE_INVALID")
# shape
ar("AR-unknown-member", aresult(extra="x"), "REFUSE", "RESULT_INVALID")
fb = aresult(sign_it=False)
fb["basis"]["answer"] = {**fb["basis"]["answer"], "note": "ok"}
ar("AR-forbidden-member", sign(fb, "lp02.result", PROV_A), "REFUSE", "RESULT_INVALID", note="no words travel as evidence")
ar("AR-line-basis", aresult(basis={"kind": "line", "question": q0, "answer": answer(q0)}), "REFUSE", "RESULT_INVALID", note="the line basis is LP 0.1's Result, not this object")
ar("AR-v2", aresult(v="lp02.result/2"), "REFUSE", "MODULE_VERSION_UNSUPPORTED")
ar("AR-epoch-negative", aresult(epoch=-1), "REFUSE", "RESULT_INVALID")
ar("AR-question-one-option", aresult(q=question(options=[{"code": "fixed", "label": "Yes"}], conclusion={"fixed": "repair-done"})), "REFUSE", "RESULT_INVALID")
ar("AR-label-astral-ok", aresult(q=question(label="\U0001F527" * 30)), "ACCEPT", note="30 wrenches = 60 UTF-16 code units: the limit")
ar("AR-label-astral-long", aresult(q=question(label="\U0001F527" * 31)), "REFUSE", "RESULT_INVALID", note="31 = 62 code units (block 58: B counted 31)")
ar("AR-conclusion-unknown-option", aresult(q=question(conclusion={"fixed": "repair-done", "maybe": "x"})), "REFUSE", "RESULT_INVALID")

# making: both implementations sign the identical bytes (Ed25519 is deterministic)
MK = {"provider": "provider A", "aud": A, "question": q0, "answer": answer(q0), "epoch": 1, "issued_at": NOW, "result_id": rid("async result")}
vec("AR-make", "lp02.result", [step("ares.make", MK, "ACCEPT", None, {"signature": ok_r["signature"], "outcome": "repair-done"})], note="the same Result, byte for byte")
vec("AR-make-not-agreed", "lp02.result", [step("ares.make", {**MK, "answer": answer(q0, option="later")}, "REFUSE", "RESULT_NOT_AGREED")])
vec("AR-body", "lp02.result", [step("ares.body", {"question": q0}, "ACCEPT", None, {"body": c_body(q0)})], note="the exact bytes the client signs")

# ---------------------------------------------------------------- lp02.delegation (block 44): attenuated delegation
DLG_V = "lp02.delegation/1"
DT = rid("thing of the delegation")
AG_A, AG_B, AG_C = Key("agent A"), Key("agent B"), Key("agent C")


def dhash(d):
    return b64u(hashlib.sha256(jcs(d)).digest())


def deleg(signer, subject, parent=None, label="d", **over):
    body = {"v": DLG_V, "delegation_id": rid("delegation " + label), "thing_id": DT, "aud": A, "epoch": 1,
            "parent": None if parent is None else {"delegation_id": parent["delegation_id"], "hash": dhash(parent)},
            "issuer_kid": signer.kid, "subject_pub": subject.pub, "actions": ["answer", "line", "read", "subscribe"],
            "channels": ["data", "video", "voice"], "purpose": "repair", "not_before": iso(NOW - 3600), "exp": iso(NOW + 3600),
            "max_uses": 100, "depth": 3}
    body.update(over)
    return sign(body, "lp02.delegation", signer)


ROOT = deleg(PROV_A, CLIENT, label="root")
D1 = deleg(CLIENT, AG_A, ROOT, "1", actions=["answer", "read"], channels=["data"], purpose="repair.booking", max_uses=10, depth=2)
D2 = deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=[], purpose="repair.booking", max_uses=5, depth=1)
D3 = deleg(AG_B, AG_C, D2, "3", actions=["read"], channels=[], purpose="repair.booking", max_uses=2, depth=0)
DTHING = {"thing_id": DT, "aud": A, "provider_pub": PROV_A.pub, "epoch": 1}


def dv(id_, chain, outcome, code=None, res=None, action="read", channels=None, revoked=None, uses=None, thing=None, now=NOW, note=""):
    req = {"action": action, **({"channels": channels} if channels is not None else {})}
    vec(id_, "lp02.delegation", [step("dlg.verify", {"chain": chain, "request": req}, outcome, code, res)],
        {"now": now, "thing": thing or DTHING, "revoked": revoked or {"ids": [], "kids": []}, "uses": uses or {}}, note)


dv("AD-root", [ROOT], "ACCEPT", res={"leaf_kid": CLIENT.kid, "length": 1}, note="the bound client's own authority")
dv("AD-chain", [ROOT, D1, D2, D3], "ACCEPT", res={"leaf_kid": AG_C.kid, "length": 4}, note="root -> A -> B -> C")
dv("AD-C-not-wider", [ROOT, D1, D2, D3], "REFUSE", "DELEGATION_DENIED", action="answer", note="A may answer; C, below it, may not")
dv("AD-A-answers", [ROOT, D1], "ACCEPT", res={"leaf_kid": AG_A.kid, "length": 2}, action="answer")
# every widening dimension (each child properly signed by its parent's holder)
dv("AD-wider-channel", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=["data", "voice"], purpose="repair.booking", max_uses=5, depth=1)], "REFUSE", "DELEGATION_WIDENS")
dv("AD-longer-expiry", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=[], purpose="repair.booking", max_uses=5, depth=1, exp=iso(NOW + 7200))], "REFUSE", "DELEGATION_WIDENS")
dv("AD-earlier-start", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=[], purpose="repair.booking", max_uses=5, depth=1, not_before=iso(NOW - 7200))], "REFUSE", "DELEGATION_WIDENS")
dv("AD-more-uses", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=[], purpose="repair.booking", max_uses=11, depth=1)], "REFUSE", "DELEGATION_WIDENS")
dv("AD-other-purpose", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=[], purpose="repair.billing", max_uses=5, depth=1)], "REFUSE", "DELEGATION_WIDENS")
dv("AD-purpose-prefix-trick", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=[], purpose="repair.bookingx", max_uses=5, depth=1)], "REFUSE", "DELEGATION_WIDENS", note="a narrower purpose is a dotted sub-code, not a string prefix")
dv("AD-narrower-purpose", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=[], purpose="repair.booking.slot", max_uses=5, depth=1)], "ACCEPT", res={"leaf_kid": AG_B.kid, "length": 3})
dv("AD-unauthorized-action", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["line", "read"], channels=[], purpose="repair.booking", max_uses=5, depth=1)], "REFUSE", "DELEGATION_WIDENS")
dv("AD-reset-depth", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=[], purpose="repair.booking", max_uses=5, depth=2)], "REFUSE", "DELEGATION_WIDENS", note="depth must fall")
dv("AD-depth-zero-delegates", [ROOT, D1, D2, D3, deleg(AG_C, OTHER, D3, "4", actions=["read"], channels=[], purpose="repair.booking", max_uses=1, depth=0)], "REFUSE", "DELEGATION_WIDENS", note="C was given no right to delegate")
dv("AD-new-thing", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=[], purpose="repair.booking", max_uses=5, depth=1, thing_id=rid("another thing"))], "REFUSE", "DELEGATION_SCOPE")
dv("AD-other-aud", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=[], purpose="repair.booking", max_uses=5, depth=1, aud=B)], "REFUSE", "DELEGATION_SCOPE")
dv("AD-other-epoch-child", [ROOT, D1, deleg(AG_A, AG_B, D1, "2", actions=["read"], channels=[], purpose="repair.booking", max_uses=5, depth=1, epoch=2)], "REFUSE", "DELEGATION_WIDENS")
# chain structure
dv("AD-omit-parent", [ROOT, D2], "REFUSE", "DELEGATION_PARENT", note="B's delegation without A's")
D1X = deleg(CLIENT, AG_A, ROOT, "1", actions=["answer", "line", "read"], channels=["data"], purpose="repair.booking", max_uses=10, depth=2)
dv("AD-substitute-parent", [ROOT, D1X, D2], "REFUSE", "DELEGATION_PARENT", note="a wider parent with the same id: the hash names the real one")
dv("AD-no-root", [D1, D2, D3], "REFUSE", "DELEGATION_PARENT")
dv("AD-second-root", [ROOT, deleg(PROV_A, AG_A, label="root2")], "REFUSE", "DELEGATION_PARENT")
dv("AD-cycle", [ROOT, D1, D2, D1], "REFUSE", "DELEGATION_CYCLE")
deep = [deleg(PROV_A, CLIENT, label="deep0", depth=7)]
keys = [CLIENT] + [Key(f"deep {i}") for i in range(1, 10)]
for i in range(1, 9):
    deep.append(deleg(keys[i - 1], keys[i], deep[-1], f"deep{i}", depth=max(0, 7 - i)))
dv("AD-too-deep", deep, "REFUSE", "DELEGATION_TOO_DEEP", note="9 elements: refused before any signature is checked")
dv("AD-deepest-allowed", deep[:8], "ACCEPT", res={"leaf_kid": keys[7].kid, "length": 8})
dv("AD-forged-child", [ROOT, D1, D2, deleg(AG_C, AG_C, D2, "3", actions=["read"], channels=[], purpose="repair.booking", max_uses=2, depth=0)], "REFUSE", "SIGNATURE_INVALID", note="C signs its own delegation")
dv("AD-forged-root", [deleg(OTHER, CLIENT, label="root")], "REFUSE", "SIGNATURE_INVALID")
dv("AD-root-typ", [sign({k: v for k, v in ROOT.items() if k != "signature"}, "lp02.result", PROV_A)], "REFUSE", "SIGNATURE_INVALID")
# revocation, time, epoch, uses
dv("AD-revoked-parent", [ROOT, D1, D2, D3], "REFUSE", "DELEGATION_REVOKED", revoked={"ids": [D1["delegation_id"]], "kids": []}, note="no orphan authority")
dv("AD-revoked-child-only", [ROOT, D1, D2], "ACCEPT", res={"leaf_kid": AG_B.kid, "length": 3}, revoked={"ids": [D3["delegation_id"]], "kids": []}, note="revoking a child leaves its parent")
dv("AD-compromised-ancestor", [ROOT, D1, D2, D3], "REFUSE", "DELEGATION_REVOKED", revoked={"ids": [], "kids": [AG_A.kid]})
dv("AD-root-epoch-stale", [ROOT, D1], "REFUSE", "DELEGATION_EPOCH_STALE", thing={**DTHING, "epoch": 2}, note="the relationship moved to a new device")
D1E = deleg(CLIENT, AG_A, ROOT, "1e", actions=["answer", "read"], channels=["data"], purpose="repair.booking", max_uses=10, depth=2, exp=iso(NOW + 60))
D2E = deleg(AG_A, AG_B, D1E, "2e", actions=["read"], channels=[], purpose="repair.booking", max_uses=5, depth=1, exp=iso(NOW + 60))
dv("AD-parent-expired", [ROOT, D1E, D2E], "REFUSE", "DELEGATION_EXPIRED", now=NOW + 120)
dv("AD-not-yet", [ROOT, D1], "REFUSE", "DELEGATION_EXPIRED", now=NOW - 7200)
dv("AD-leaf-exhausted", [ROOT, D1, D2, D3], "REFUSE", "DELEGATION_EXHAUSTED", uses={D3["delegation_id"]: 2})
dv("AD-ancestor-exhausted", [ROOT, D1, D2, D3], "REFUSE", "DELEGATION_EXHAUSTED", uses={D1["delegation_id"]: 10}, note="a parent's allowance bounds all descendants together")
LINE_D = deleg(CLIENT, AG_A, ROOT, "line", actions=["line"], channels=["voice"], purpose="repair", max_uses=3, depth=0)
dv("AD-line-voice", [ROOT, LINE_D], "ACCEPT", res={"leaf_kid": AG_A.kid, "length": 2}, action="line", channels=["voice"])
dv("AD-line-video", [ROOT, LINE_D], "REFUSE", "DELEGATION_DENIED", action="line", channels=["voice", "video"])
# shape
dv("AD-unknown-member", [deleg(PROV_A, CLIENT, label="root", extra=1)], "REFUSE", "DELEGATION_INVALID")
dv("AD-forbidden-member", [deleg(PROV_A, CLIENT, label="root", note="x")], "REFUSE", "DELEGATION_INVALID")
dv("AD-unsorted-actions", [deleg(PROV_A, CLIENT, label="root", actions=["read", "answer"])], "REFUSE", "DELEGATION_INVALID")
dv("AD-unknown-action", [deleg(PROV_A, CLIENT, label="root", actions=["admin"])], "REFUSE", "DELEGATION_INVALID")
dv("AD-conclude-not-delegable", [deleg(PROV_A, CLIENT, label="root", actions=["conclude", "read"])], "REFUSE", "DELEGATION_INVALID", note="an agreement stays the person's own signature")
dv("AD-v2", [deleg(PROV_A, CLIENT, label="root", v="lp02.delegation/2")], "REFUSE", "MODULE_VERSION_UNSUPPORTED")
dv("AD-depth-8", [deleg(PROV_A, CLIENT, label="root", depth=8)], "REFUSE", "DELEGATION_INVALID")
dv("AD-empty", [], "REFUSE", "DELEGATION_INVALID")
vec("AD-make", "lp02.delegation", [step("dlg.make", {"signer": "agent A", "fields": {k: v for k, v in D2.items() if k not in ("v", "issuer_kid", "signature")}},
    "ACCEPT", None, {"signature": D2["signature"], "hash": dhash(D2)})], note="A and B sign and hash identical bytes")

# ---------------------------------------------------------------- lp02.recovery (block 45): moving to a new device
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF

RCV_V = "lp02.recovery/1"
RTH = rid("thing of the recovery")
# a vector never carries seed bytes (a secret-shaped field): the seed is named by a label, as test keys are
SEED = hashlib.sha256(b"LP02 TEST SEED recovery").digest()


class SeedKey(Key):
    def __init__(self, seed):
        ed = _HKDF(algorithm=_hashes.SHA256(), length=32, salt=b"lyne-recovery/1", info=b"lp02.recovery key").derive(seed)
        self.sk = Ed25519PrivateKey.from_private_bytes(ed)
        raw = self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pub = b64u(raw)
        self.kid = b64u(hashlib.sha256(jcs({"crv": "Ed25519", "kty": "OKP", "x": self.pub})).digest())


RKEY = SeedKey(SEED)
STOLEN = SeedKey(hashlib.sha256(b"someone else's seed").digest())


def rgrant(key=PROV_A, typ="lp02.recovery", **over):
    g = {"v": RCV_V, "recovery_id": rid("recovery 1"), "thing_id": RTH, "aud": A, "epoch": 1, "recovery_pub": RKEY.pub, "purpose": "rebind",
         "issued_at": iso(NOW - 86400), "exp": iso(NOW + 300 * 86400), "hold_seconds": 0}
    g.update(over)
    return sign(g, typ, key)


RG = rgrant()
RTHG = {"thing_id": RTH, "aud": A, "provider_pub": PROV_A.pub, "epoch": 1, "closed": False, "left": False}


def mbody(recovery_id=None):
    return jcs({"v": RCV_V, "recovery_id": recovery_id or RG["recovery_id"]}).decode()


def mreq(key=RKEY, body=None, created=NOW, aud=A, thing_id=RTH, sign_body=True):
    b = body if body is not None else mbody()
    uri = f"{aud}/t/{thing_id}/recover"
    h = http_sign(key, "POST", uri, created, b if sign_body else None)
    return {"method": "POST", "target_uri": f"{A}/t/{RTH}/recover", "headers": h, "body": b}


def rv(id_, request, outcome, code=None, res=None, record="default", thing=None, now=NOW, note=""):
    rec = {"grant": RG, "used_at": None, "revoked_at": None, "pending_until": None} if record == "default" else record
    vec(id_, "lp02.recovery", [step("rcv.move", request, outcome, code, res)], {"now": now, "thing": thing or RTHG, "record": rec}, note)


vec("RV-key", "lp02.recovery", [step("rcv.key", {"seed_label": "recovery"}, "ACCEPT", None, {"pub": RKEY.pub})], note="the same recovery key from the same offline seed (HKDF), in every implementation")
vec("RV-grant", "lp02.recovery", [step("rcv.grant", {"grant": RG}, "ACCEPT", None, {"recovery_id": RG["recovery_id"]})], {"thing": RTHG})
vec("RV-grant-forged", "lp02.recovery", [step("rcv.grant", {"grant": rgrant(key=OTHER)}, "REFUSE", "SIGNATURE_INVALID")], {"thing": RTHG}, note="a provider key the Thing does not have (e.g. rotated away)")
vec("RV-grant-other-thing", "lp02.recovery", [step("rcv.grant", {"grant": rgrant(thing_id=rid("other"))}, "REFUSE", "RECOVERY_UNKNOWN")], {"thing": RTHG})
vec("RV-grant-purpose", "lp02.recovery", [step("rcv.grant", {"grant": rgrant(purpose="line")}, "REFUSE", "RECOVERY_INVALID")], {"thing": RTHG}, note="a recovery grant has one power only")
vec("RV-grant-too-long", "lp02.recovery", [step("rcv.grant", {"grant": rgrant(exp=iso(NOW + 500 * 86400))}, "REFUSE", "RECOVERY_INVALID")], {"thing": RTHG})
vec("RV-grant-hold", "lp02.recovery", [step("rcv.grant", {"grant": rgrant(hold_seconds=604801)}, "REFUSE", "RECOVERY_INVALID")], {"thing": RTHG})
vec("RV-grant-v2", "lp02.recovery", [step("rcv.grant", {"grant": rgrant(v="lp02.recovery/2")}, "REFUSE", "MODULE_VERSION_UNSUPPORTED")], {"thing": RTHG})
vec("RV-grant-typ", "lp02.recovery", [step("rcv.grant", {"grant": rgrant(typ="lp02.delegation")}, "REFUSE", "SIGNATURE_INVALID")], {"thing": RTHG})

rv("RV-move", mreq(), "ACCEPT", res={"action": "move"}, note="a lost device: the relationship moves")
rv("RV-stolen-key", mreq(key=STOLEN), "REFUSE", "SIGNATURE_INVALID", note="a key the grant does not name")
rv("RV-unsigned-body", mreq(sign_body=False), "REFUSE", "SIGNATURE_INVALID", note="the body must be covered by content-digest")
rv("RV-other-body", mreq(body=jcs({"recovery_id": RG["recovery_id"], "v": RCV_V, "x": 1}).decode()), "REFUSE", "RECOVERY_INVALID")
rv("RV-not-canonical", mreq(body='{"v": "lp02.recovery/1", "recovery_id": "%s"}' % RG["recovery_id"]), "REFUSE", "RECOVERY_INVALID", note="exactly the JCS bytes")
rv("RV-unknown", mreq(body=mbody(rid("unknown recovery"))), "REFUSE", "RECOVERY_UNKNOWN", note="another Thing's or tenant's recovery: unknown here")
rv("RV-none", mreq(), "REFUSE", "RECOVERY_UNKNOWN", record=None)
rv("RV-revoked", mreq(), "REFUSE", "RECOVERY_REVOKED", record={"grant": RG, "used_at": None, "revoked_at": iso(NOW - 10), "pending_until": None})
rv("RV-replayed-used", mreq(), "REFUSE", "RECOVERY_USED", record={"grant": RG, "used_at": iso(NOW - 10), "revoked_at": None, "pending_until": None}, note="single use")
rv("RV-expired", mreq(created=NOW), "REFUSE", "RECOVERY_EXPIRED", now=NOW, record={"grant": rgrant(exp=iso(NOW - 1)), "used_at": None, "revoked_at": None, "pending_until": None})
rv("RV-old-artifact", mreq(), "REFUSE", "RECOVERY_EPOCH_STALE", thing={**RTHG, "epoch": 2}, note="a move already happened: older artifacts are dead")
rv("RV-closed", mreq(), "REFUSE", "THING_CLOSED", thing={**RTHG, "closed": True})
rv("RV-left", mreq(), "REFUSE", "CLIENT_LEFT", thing={**RTHG, "left": True})
RGH = rgrant(hold_seconds=3600)
rv("RV-hold-start", mreq(), "ACCEPT", res={"action": "pending", "pending_until": NOW + 3600}, record={"grant": RGH, "used_at": None, "revoked_at": None, "pending_until": None}, note="a held move: the old device can stop it")
rv("RV-hold-early", mreq(), "REFUSE", "RECOVERY_PENDING", record={"grant": RGH, "used_at": None, "revoked_at": None, "pending_until": NOW + 1800})
rv("RV-hold-due", mreq(), "ACCEPT", res={"action": "complete"}, record={"grant": RGH, "used_at": None, "revoked_at": None, "pending_until": NOW - 1})
rv("RV-stale-created", mreq(created=NOW - 400), "REFUSE", "SIGNATURE_INVALID")

# ---- block 48: a DETERMINISTIC refusal order — every repetition of a recovery request gets the same answer, whatever
# the timing, the replay memory or a restart (the Recovery Grant's persistent state decides; SPEC §14.2)
RC = {"thing": RTHG, "record": {"grant": RG, "used_at": None, "revoked_at": None, "pending_until": None}}
MV = mreq()


def mv(req, outcome, code=None, res=None, at=None):
    return step("rcv.move", {**req, **({"now": at} if at is not None else {})}, outcome, code, res)


vec("RV-48-replay-now", "lp02.recovery", [mv(MV, "ACCEPT", res={"action": "move"}), mv(MV, "REFUSE", "RECOVERY_USED")], {"now": NOW, **RC},
    note="the exact same request again in the same second: USED (not a replay code)")
vec("RV-48-replay-next-second", "lp02.recovery", [mv(MV, "ACCEPT", res={"action": "move"}), mv(MV, "REFUSE", "RECOVERY_USED", at=NOW + 1)], {"now": NOW, **RC})
vec("RV-48-replay-after-restart", "lp02.recovery", [mv(MV, "ACCEPT", res={"action": "move"}), step("rcv.restart", {}, "ACCEPT"), mv(MV, "REFUSE", "RECOVERY_USED")], {"now": NOW, **RC},
    note="a restart loses every in-memory state; the answer does not change")
vec("RV-48-two-valid-requests", "lp02.recovery", [mv(mreq(created=NOW - 1), "ACCEPT", res={"action": "move"}), mv(mreq(created=NOW), "REFUSE", "RECOVERY_USED")], {"now": NOW, **RC},
    note="two different, validly signed requests with one capability: one moves")
vec("RV-48-race-100", "lp02.recovery", [mv(MV, "ACCEPT", res={"action": "move"})] + [mv(mreq(created=NOW - (k % 250)) if k % 2 else MV, "REFUSE", "RECOVERY_USED") for k in range(99)],
    {"now": NOW, **RC}, note="a winner and 99 losers, identical or distinct: every loser USED")
vec("RV-48-old-device", "lp02.recovery", [mv(MV, "ACCEPT", res={"action": "move"}), mv(mreq(key=OTHER), "REFUSE", "SIGNATURE_INVALID")], {"now": NOW, **RC},
    note="the old device's own key is not the recovery key: SIGNATURE_INVALID before and after")
vec("RV-48-lost-race-epoch", "lp02.recovery", [mv(MV, "REFUSE", "RECOVERY_USED")],
    {"now": NOW, "thing": {**RTHG, "epoch": 2}, "record": {"grant": RG, "used_at": iso(NOW - 1), "revoked_at": None, "pending_until": None}},
    note="a lost race sees the move's epoch + 1 too: USED (rule 5) wins over EPOCH_STALE (rule 7)")
vec("RV-48-revoked-and-used", "lp02.recovery", [mv(MV, "REFUSE", "RECOVERY_REVOKED")],
    {"now": NOW, "thing": RTHG, "record": {"grant": RG, "used_at": iso(NOW - 5), "revoked_at": iso(NOW - 9), "pending_until": None}})
vec("RV-48-used-and-expired", "lp02.recovery", [mv(MV, "REFUSE", "RECOVERY_USED")],
    {"now": NOW, "thing": RTHG, "record": {"grant": rgrant(exp=iso(NOW - 1)), "used_at": iso(NOW - 5), "revoked_at": None, "pending_until": None}})
vec("RV-48-bad-signature-on-used", "lp02.recovery", [mv(mreq(key=STOLEN), "REFUSE", "SIGNATURE_INVALID")],
    {"now": NOW, "thing": RTHG, "record": {"grant": RG, "used_at": iso(NOW - 5), "revoked_at": None, "pending_until": None}},
    note="state is told only to the recovery key's holder: the signature (rule 3) comes before the grant's state")
vec("RV-48-wrong-thing", "lp02.recovery", [mv(mreq(body=mbody(rid("unknown recovery"))), "REFUSE", "RECOVERY_UNKNOWN")], {"now": NOW, **RC})
vec("RV-48-short-hold", "lp02.recovery", [step("rcv.grant", {"grant": rgrant(hold_seconds=600)}, "REFUSE", "RECOVERY_INVALID")], {"thing": RTHG},
    note="a hold is 0 or at least 900 s")
RGH2 = rgrant(hold_seconds=900)
HC = {"now": NOW, "thing": RTHG, "record": {"grant": RGH2, "used_at": None, "revoked_at": None, "pending_until": None}}
START = mreq(created=NOW)
vec("RV-48-hold-replayed-start", "lp02.recovery", [mv(START, "ACCEPT", res={"action": "pending", "pending_until": NOW + 900}), mv(START, "REFUSE", "RECOVERY_PENDING", at=NOW + 10),
    step("rcv.restart", {}, "ACCEPT"), mv(START, "REFUSE", "SIGNATURE_INVALID", at=NOW + 901)], HC,
    note="the request that started a hold: PENDING while held; after the hold it is outside its own window — it can never complete the move")
vec("RV-48-hold-complete-once", "lp02.recovery", [mv(START, "ACCEPT", res={"action": "pending", "pending_until": NOW + 900}), mv(mreq(created=NOW + 901), "ACCEPT", res={"action": "complete"}, at=NOW + 901),
    mv(mreq(created=NOW + 902), "REFUSE", "RECOVERY_USED", at=NOW + 902)], HC)
vec("RV-48-hold-early-new-request", "lp02.recovery", [mv(mreq(created=NOW + 100), "REFUSE", "RECOVERY_PENDING", at=NOW + 100)],
    {"now": NOW + 100, "thing": RTHG, "record": {"grant": RGH2, "used_at": None, "revoked_at": None, "pending_until": NOW + 900}})

# ---- block 49: LYNE RESULT PROOF (lyne-result-proof/1, SPEC §15) — an evidence envelope around existing signed objects
PF_CLOSED = iso(NOW)


def sign01(obj, key, drop=("signature",), member="signature"):
    """An LP 0.1 detached JWS (header JCS({alg, kid}), no typ) over the object without its signature members."""
    body = {k: v for k, v in obj.items() if k not in drop}
    header = b64u(jcs({"alg": "EdDSA", "kid": key.kid}))
    out = dict(obj)
    out[member] = header + ".." + b64u(key.sk.sign((header + "." + b64u(jcs(body))).encode()))
    return out


def pf_thing(key=PROV_A, **over):
    t = {"lp_version": "0.1", "thing_id": RT, "type": "repair.plumbing", "title": "Kitchen tap", "provider_pub": key.pub, "created_at": iso(NOW - 4000),
         "closed_at": PF_CLOSED, "version": 2}
    t.update(over)
    return sign01(t, key)


def pf_anchor(key=PROV_A, **over):
    a = {"lp_version": "0.1", "thing_id": RT, "version": 5, "prev_state_hash": rid("prev state") + "AAAAAAAAAAAAAAAAAAAAA", "status": "CLOSED", "waiting_on": None,
         "next_action": None, "deadline": None, "actor": "provider", "result_id": None, "timestamp": PF_CLOSED}
    a.update(over)
    return sign01(a, key)


PF_GID = rid("grant of the proof")


def pf_grant(key=PROV_A, **over):
    g = {"lp_version": "0.1", "grant_id": PF_GID, "thing_id": RT, "aud": A, "issuer": key.pub, "purpose": "visit", "channels": ["data"], "line_max_seconds": 600,
         "issued_at": iso(NOW - 3100), "redeem_by": iso(NOW - 2900), "exp": iso(NOW - 100), "max_uses": 1, "epoch": 1, "secret_commitment": rid("commitment") + "AAAAAAAAAAAAAAAAAAAAA"}
    g.update(over)
    return sign01(g, key)


def pf_receipt(key=PROV_A, client=CLIENT, **over):
    r = {"lp_version": "0.1", "grant_id": PF_GID, "thing_id": RT, "client_kid": client.kid, "bound_at": iso(NOW - 3000), "uses_remaining": 1}
    r.update(over)
    return sign01(r, key)


def proof(basis="request_answer", thing=None, anchor=None, result=None, client_pub=None, grant=None, receipt=None, **over):
    out = {"kind": "lyne-result-proof/1", "basis": basis, "thing": thing or pf_thing(), "anchor": anchor or pf_anchor(), "result": result or aresult(),
           "agreement": {"client_thing_pub": client_pub or CLIENT.pub, "grant": grant or pf_grant(), "receipt": receipt or pf_receipt()}}
    out.update(over)
    return out


def pf(id_, prf, outcome, code=None, res=None, note=""):
    vec(id_, "lyne-result-proof", [step("proof.verify", {"proof": prf}, outcome, code, res)], {}, note)


OK_RES = {"outcome": "repair-done", "basis": "request_answer", "thing_id": RT, "client_kid": CLIENT.kid, "provider_kid": PROV_A.kid, "closed_at": PF_CLOSED}
pf("PF-valid-request-answer", proof(), "ACCEPT", res=OK_RES, note="offline: the Thing, its closing State, the async Result, the authority it was agreed under")
# LP 0.1 Line-basis Result
LRID = rid("line result")
NEXT_CLOSED = {"status": "CLOSED", "waiting_on": None, "next_action": None, "deadline": None}


def lresult(key=PROV_A, client=CLIENT, **over):
    r = {"lp_version": "0.1", "result_id": LRID, "thing_id": RT, "grant_id": PF_GID, "line_seq": 1, "outcome": "agreed", "summary": "Visit Tuesday 10:00",
         "next_state": NEXT_CLOSED, "timestamp": iso(NOW - 5)}
    r.update(over)
    r = sign01(r, key, ("provider_sig", "client_thing_sig"), "provider_sig")
    return sign01(r, client, ("provider_sig", "client_thing_sig"), "client_thing_sig")


LINE_ANCHOR = pf_anchor(result_id=LRID, actor="provider")
pf("PF-valid-non-ascii", proof(thing=pf_thing(title="Köök — kraan ülevaatus")), "ACCEPT", res={"outcome": "repair-done"}, note="RFC 8785: raw UTF-8, never escaped (block 52 found a driver reading its pipe as cp1252)")
pf("PF-valid-line", proof("line", anchor=LINE_ANCHOR, result=lresult()), "ACCEPT",
   res={"outcome": "agreed", "basis": "line", "thing_id": RT, "client_kid": CLIENT.kid, "provider_kid": PROV_A.kid})
# the Result was agreed by a key that was bound EARLIER (before a device move): the proof carries THAT binding
pf("PF-valid-earlier-key", proof("line", anchor=LINE_ANCHOR, result=lresult(client=CLIENT_NEW), client_pub=CLIENT_NEW.pub, receipt=pf_receipt(client=CLIENT_NEW)),
   "ACCEPT", res={"client_kid": CLIENT_NEW.kid}, note="the key that agreed, as the provider bound it")


def tampered(f):
    prf = proof()
    f(prf)
    return prf


def resigned_result(**over):
    return aresult(**over)


q1 = question()
# --- the directive's list: outcome, question, choice, customer key, provider key, epoch, Thing id, Result id, State anchor,
# signature, version, basis kind — each once unsigned (a forger) and, where it means something, re-signed by the provider
pf("PF-outcome", tampered(lambda x: x["result"].__setitem__("outcome", "repair-failed")), "REFUSE", "SIGNATURE_INVALID")
pf("PF-outcome-resigned", proof(result=aresult(outcome="repair-failed")), "REFUSE", "RESULT_OUTCOME_MISMATCH", note="a provider cannot change what was agreed")
pf("PF-question", tampered(lambda x: x["result"]["basis"]["question"].__setitem__("label", "Is it paid?")), "REFUSE", "SIGNATURE_INVALID")
pf("PF-question-resigned", proof(result=aresult(q=question(label="Is it paid?"), ans=answer(q1))), "REFUSE", "RESULT_BASIS_INVALID", note="the customer signed another question")
pf("PF-choice-resigned", proof(result=aresult(ans=dict(answer(q1), option="not-fixed"), outcome="repair-failed")), "REFUSE", "RESULT_BASIS_INVALID", note="the customer chose 'fixed'")
pf("PF-customer-key", tampered(lambda x: x["agreement"].__setitem__("client_thing_pub", OTHER.pub)), "REFUSE", "PROOF_AUTHORITY")
pf("PF-customer-key-colluding", proof(client_pub=OTHER.pub, receipt=pf_receipt(client=OTHER)), "REFUSE", "KEY_MISMATCH", note="a Receipt for another key: that key did not answer")
pf("PF-provider-key", tampered(lambda x: x["thing"].__setitem__("provider_pub", OTHER.pub)), "REFUSE", "PROOF_SIGNATURE")
pf("PF-epoch-resigned", proof(result=aresult(epoch=2)), "REFUSE", "PROOF_AUTHORITY", note="agreed under another authority epoch than the bound key's")
pf("PF-thing-id", tampered(lambda x: x["thing"].__setitem__("thing_id", rid("another thing"))), "REFUSE", "PROOF_SIGNATURE")
pf("PF-other-thing", proof(thing=pf_thing(thing_id=rid("another thing"))), "REFUSE", "PROOF_SIGNATURE", note="the closing State is another Thing's")
pf("PF-result-id", tampered(lambda x: x["result"].__setitem__("result_id", rid("another result"))), "REFUSE", "SIGNATURE_INVALID")
pf("PF-anchor", tampered(lambda x: x["anchor"].__setitem__("timestamp", iso(NOW + 900))), "REFUSE", "PROOF_SIGNATURE")
pf("PF-anchor-resigned", proof(anchor=pf_anchor(timestamp=iso(NOW + 900))), "REFUSE", "PROOF_ANCHOR", note="the closing State is not the Thing's closing")
pf("PF-anchor-late", proof(thing=pf_thing(closed_at=iso(NOW + 900)), anchor=pf_anchor(timestamp=iso(NOW + 900))), "REFUSE", "PROOF_ANCHOR", note="closed by something else, later")
pf("PF-signature", tampered(lambda x: x["thing"].__setitem__("signature", x["thing"]["signature"][:-2] + ("AA" if x["thing"]["signature"][-2:] != "AA" else "BB"))), "REFUSE", "PROOF_SIGNATURE")
pf("PF-version-result", proof(result=aresult(v="lp02.result/2")), "REFUSE", "MODULE_VERSION_UNSUPPORTED")
pf("PF-version-kind", proof(kind="lyne-result-proof/2"), "REFUSE", "PROOF_INVALID")
pf("PF-basis-kind", proof(basis="line"), "REFUSE", "PROOF_SCOPE", note="an async Result offered as a Line Result")
pf("PF-basis-kind-resigned", proof(result=aresult(basis={"kind": "line", "question": q1, "answer": answer(q1)})), "REFUSE", "RESULT_INVALID")
# --- closure, authority, shape
pf("PF-not-closed", proof(thing=pf_thing(closed_at=None)), "REFUSE", "PROOF_NOT_CLOSED", note="only a CLOSED Thing has a final Result proof")
pf("PF-bound-after", proof(receipt=pf_receipt(bound_at=iso(NOW + 400))), "REFUSE", "PROOF_AUTHORITY", note="answered before the key was bound (beyond the skew)")
pf("PF-grant-other-provider", proof(grant=pf_grant(key=OTHER)), "REFUSE", "PROOF_AUTHORITY")
pf("PF-extra-member", proof(history=[]), "REFUSE", "PROOF_INVALID", note="no history, no audit, nothing else")
pf("PF-missing-member", {k: v for k, v in proof().items() if k != "anchor"}, "REFUSE", "PROOF_INVALID")
# --- Line basis tampers
pf("PF-line-outcome", proof("line", anchor=LINE_ANCHOR, result=dict(lresult(), outcome="declined")), "REFUSE", "PROOF_SIGNATURE")
pf("PF-line-client-other", proof("line", anchor=LINE_ANCHOR, result=lresult(client=OTHER)), "REFUSE", "PROOF_SIGNATURE")
pf("PF-line-anchor-other-result", proof("line", anchor=pf_anchor(result_id=rid("other result")), result=lresult()), "REFUSE", "PROOF_ANCHOR")
pf("PF-line-next-state", proof("line", anchor=LINE_ANCHOR, result=lresult(next_state={"status": "WAITING", "waiting_on": "provider", "next_action": "x", "deadline": None})),
   "REFUSE", "PROOF_ANCHOR")
pf("PF-line-other-grant", proof("line", anchor=LINE_ANCHOR, result=lresult(grant_id=rid("another grant"))), "REFUSE", "PROOF_SCOPE")

# ---- block 55: lp02.agreement/1 (SPEC §17) — a Result several actors agree to, under a policy fixed in advance
AGR_V = "lp02.agreement/1"
AGQ = rid("agreement question")
LANDLORD, TECH, TECH2 = Key("landlord"), Key("technician"), Key("technician two")
POL_ALL = {"requirements": [{"roles": ["customer"], "min": 1}, {"roles": ["landlord"], "min": 1}, {"roles": ["technician"], "min": 1}]}


def agq(**over):
    q = {"request_id": AGQ, "thing_id": RT, "template": "repair-ok", "label": "Is the repair accepted?",
         "options": [{"code": "accept", "label": "Yes, accept"}, {"code": "reject", "label": "No, redo"}, {"code": "later", "label": "Ask me later"}],
         "conclusion": {"accept": "repair-accepted", "reject": "repair-rejected"}, "policy": POL_ALL,
         "deadline": iso(NOW + 3600), "created_at": iso(NOW - 600)}
    q.update(over)
    return q


def ag_body(q, role):
    return jcs({"v": AGR_V, "question": q_hash(q), "role": role}).decode()


def asig(q, role, key, option="accept", created=NOW - 60, aud=A, body_role=None, body_q=None, pub=None):
    uri = f"{aud}/t/{q['thing_id']}/agreements/{q['request_id']}/sign/{option}"
    h = http_sign(key, "POST", uri, created, ag_body(body_q or q, body_role or role))
    return {"basis": "answer", "role": role, "pub": pub or key.pub, "created": created, "signature_input": h["signature-input"], "signature": h["signature"]}


def kid(pub):
    return b64u(hashlib.sha256(jcs({"crv": "Ed25519", "kty": "OKP", "x": pub})).digest())


def std_signers(q, option="accept"):
    return [asig(q, "customer", CLIENT, option), asig(q, "landlord", LANDLORD, option), asig(q, "technician", TECH, option)]


def agres(q=None, option="accept", signers=None, key=PROV_A, typ="lp02.agreement", epoch=1, aud=A, result_id=None, outcome=None, sign_it=True, sort=True, **over):
    q = q or agq()
    sg = signers if signers is not None else std_signers(q, option)
    if sort:
        sg = sorted(sg, key=lambda x: x["role"] + kid(x["pub"]))
    body = {"v": AGR_V, "result_id": result_id or rid("agreement result"), "thing_id": q["thing_id"], "aud": aud,
            "outcome": outcome if outcome is not None else q["conclusion"].get(option, "repair-accepted"), "option": option, "epoch": epoch,
            "issued_at": iso(NOW), "question": q, "signers": sg}
    body.update(over)
    return sign(body, typ, key) if sign_it else body


AGTHING = {"thing_id": RT, "aud": A, "provider_pub": PROV_A.pub, "closed_at": None}
AGCUST = {"epoch": 1, "client_pub": CLIENT.pub, "bound_at": iso(NOW - 3000)}


def agv(id_, result, outcome, code=None, res=None, thing=None, customer="default", accepted=None, note=""):
    vec(id_, "lp02.agreement", [step("agr.verify", {"result": result}, outcome, code, res)],
        {"thing": thing or AGTHING, "customer": AGCUST if customer == "default" else customer, "accepted": accepted or []}, note)


g0 = agq()
ok_g = agres()
agv("AG-valid-all", ok_g, "ACCEPT", res={"outcome": "repair-accepted", "option": "accept", "roles": ["customer", "landlord", "technician"]},
    note="landlord, technician and customer each signed the exact question for their role; the provider issued one Result")
agv("AG-idempotent", ok_g, "ACCEPT", accepted=[ok_g["result_id"]])
agv("AG-duplicate", agres(result_id=rid("second agreement")), "REFUSE", "RESULT_EXISTS", accepted=[ok_g["result_id"]], note="one Result per Thing")
# 55C policies: ALL / ANY / M-of-N, deterministic
g_any = agq(policy={"requirements": [{"roles": ["landlord", "technician"], "min": 1}]})
agv("AG-any-of", agres(q=g_any, signers=[asig(g_any, "technician", TECH)]), "ACCEPT", res={"roles": ["technician"]}, customer=None, note="ANY of the roles")
g_mn = agq(policy={"requirements": [{"roles": ["technician"], "min": 2}]})
agv("AG-m-of-n", agres(q=g_mn, signers=[asig(g_mn, "technician", TECH), asig(g_mn, "technician", TECH2)]), "ACCEPT", customer=None, note="2 of N technicians")
agv("AG-m-of-n-short", agres(q=g_mn, signers=[asig(g_mn, "technician", TECH)]), "REFUSE", "POLICY_NOT_MET", customer=None)
agv("AG-same-key-twice", agres(q=g_mn, signers=[asig(g_mn, "technician", TECH), asig(g_mn, "technician", TECH, created=NOW - 50)]), "REFUSE", "AGREEMENT_INVALID",
    customer=None, note="one key counts once: the same technician twice is not two")
agv("AG-one-key-two-roles", agres(signers=[asig(g0, "customer", CLIENT), asig(g0, "landlord", TECH), asig(g0, "technician", TECH)]), "REFUSE", "AGREEMENT_INVALID",
    note="one key holding two roles still counts once")
g_prov = agq(policy={"requirements": [{"roles": ["provider", "technician"], "min": 2}]})
agv("AG-provider-counts-once", agres(q=g_prov, signers=[asig(g_prov, "technician", TECH)]), "ACCEPT", customer=None, note="the provider counts, once, by its own signature")
g_prov2 = agq(policy={"requirements": [{"roles": ["provider"], "min": 2}]})
agv("AG-provider-not-twice", agres(q=g_prov2, signers=[asig(g_prov2, "technician", TECH)]), "REFUSE", "POLICY_NOT_MET", customer=None)
agv("AG-missing-role", agres(signers=[asig(g0, "customer", CLIENT), asig(g0, "technician", TECH)]), "REFUSE", "POLICY_NOT_MET", note="the landlord did not sign")
agv("AG-unsorted", agres(sort=False, signers=list(reversed(sorted(std_signers(g0), key=lambda x: x["role"] + kid(x["pub"]))))), "REFUSE", "AGREEMENT_INVALID",
    note="signers in canonical order (role, then kid)")
agv("AG-signer-provider-role", agres(signers=std_signers(g0) + [asig(g0, "provider", OTHER)]), "REFUSE", "AGREEMENT_INVALID", note="the provider signs the Result, not as a signer")
# 55E tamper: role, threshold, signer, answer, outcome, Thing, epoch
agv("AG-role-swapped", agres(signers=[asig(g0, "customer", CLIENT), asig(g0, "landlord", TECH, body_role="technician"), asig(g0, "technician", TECH2)]),
    "REFUSE", "RESULT_BASIS_INVALID", note="a technician's signature presented as the landlord's")
g_low = agq(policy={"requirements": [{"roles": ["customer"], "min": 1}, {"roles": ["landlord", "technician"], "min": 1}]})
agv("AG-threshold-lowered", agres(q=g_low, signers=[asig(g_low, "customer", CLIENT, body_q=g0), asig(g_low, "technician", TECH, body_q=g0)]), "REFUSE", "RESULT_BASIS_INVALID",
    note="the provider lowers the policy after the actors signed")
agv("AG-option-changed", agres(option="reject", signers=std_signers(g0, "accept")), "REFUSE", "RESULT_BASIS_INVALID", note="they signed 'accept', the provider claims 'reject'")
agv("AG-outcome-changed", agres(outcome="repair-rejected"), "REFUSE", "RESULT_OUTCOME_MISMATCH")
tg = dict(ok_g)
tg["outcome"] = "repair-rejected"
agv("AG-unsigned-tamper", tg, "REFUSE", "SIGNATURE_INVALID", note="changed after the provider signed")
agv("AG-not-agreed", agres(option="later"), "REFUSE", "RESULT_NOT_AGREED")
agv("AG-unknown-option", agres(option="maybe", outcome="repair-accepted"), "REFUSE", "OPTION_UNKNOWN")
agv("AG-stale", agres(signers=[asig(g0, "customer", CLIENT), asig(g0, "landlord", LANDLORD, created=NOW + 3600 + 301), asig(g0, "technician", TECH)]), "REFUSE", "RESULT_STALE",
    note="the landlord signed after the deadline")
agv("AG-customer-other-key", agres(signers=[asig(g0, "customer", OTHER), asig(g0, "landlord", LANDLORD), asig(g0, "technician", TECH)]), "REFUSE", "KEY_MISMATCH",
    note="the customer role is the bound key's, nobody else's")
agv("AG-epoch", agres(epoch=2), "REFUSE", "KEY_MISMATCH", note="signed under another authority epoch")
agv("AG-customer-unbound", ok_g, "REFUSE", "KEY_MISMATCH", customer=None, note="a customer signer needs the binding it signed under")
inv = asig(g0, "landlord", PROV_A, pub=LANDLORD.pub)
agv("AG-invented-signature", agres(signers=[asig(g0, "customer", CLIENT), {**inv, "signature_input": inv["signature_input"].replace(PROV_A.kid, LANDLORD.kid)}, asig(g0, "technician", TECH)]),
    "REFUSE", "RESULT_BASIS_INVALID", note="the provider signs the landlord's part itself")
agv("AG-other-thing", ok_g, "REFUSE", "RESULT_SCOPE", thing={**AGTHING, "thing_id": rid("another thing")})
agv("AG-other-aud", ok_g, "REFUSE", "RESULT_SCOPE", thing={**AGTHING, "aud": B})
agv("AG-after-closure", ok_g, "REFUSE", "THING_CLOSED", thing={**AGTHING, "closed_at": iso(NOW - 120)}, note="a late signer after CLOSED")
agv("AG-other-provider", agres(key=PROV_B), "REFUSE", "SIGNATURE_INVALID")
agv("AG-typ", agres(typ="lp02.result"), "REFUSE", "SIGNATURE_INVALID")
agv("AG-v2", agres(v="lp02.agreement/2"), "REFUSE", "MODULE_VERSION_UNSUPPORTED")
agv("AG-extra-member", agres(history=[]), "REFUSE", "AGREEMENT_INVALID")
agv("AG-signer-extra-member", agres(signers=[{**asig(g0, "customer", CLIENT), "name": "Mari"}, asig(g0, "landlord", LANDLORD), asig(g0, "technician", TECH)]), "REFUSE", "AGREEMENT_INVALID",
    note="no names travel as evidence")
g_uns = agq(policy={"requirements": [{"roles": ["technician", "landlord"], "min": 1}]})
agv("AG-policy-unsorted", agres(q=g_uns, signers=[asig(g_uns, "technician", TECH)]), "REFUSE", "AGREEMENT_INVALID", customer=None)
g_nopol = {k: v for k, v in g0.items() if k != "policy"}
agv("AG-no-policy", agres(q=g_nopol, signers=[asig(g_nopol, "technician", TECH)]), "REFUSE", "AGREEMENT_INVALID", customer=None)
g_astral = agq(label="\U0001F527" * 31)
agv("AG-label-astral-long", agres(q=g_astral, signers=std_signers(g_astral)), "REFUSE", "AGREEMENT_INVALID", note="labels count UTF-16 code units (block 58)")
agv("AG-no-signers", agres(signers=[]), "REFUSE", "AGREEMENT_INVALID")
# 55D the Line basis: an LP 0.1 Result stands for the customer
LSUM = "Is the repair accepted?: Yes, accept"
agv("AG-line", agres(signers=[{"basis": "line", "role": "customer", "pub": CLIENT.pub, "result": lresult(summary=LSUM)}, asig(g0, "landlord", LANDLORD), asig(g0, "technician", TECH)]),
    "ACCEPT", res={"outcome": "repair-accepted"}, note="the customer agreed on a Line; the others signed async")
agv("AG-line-declined", agres(signers=[{"basis": "line", "role": "customer", "pub": CLIENT.pub, "result": lresult(summary=LSUM, outcome="declined")}, asig(g0, "landlord", LANDLORD),
    asig(g0, "technician", TECH)]), "REFUSE", "RESULT_BASIS_INVALID")
agv("AG-line-other-summary", agres(signers=[{"basis": "line", "role": "customer", "pub": CLIENT.pub, "result": lresult(summary="Is the repair accepted?: No, redo")},
    asig(g0, "landlord", LANDLORD), asig(g0, "technician", TECH)]), "REFUSE", "RESULT_BASIS_INVALID", note="the customer agreed to another option on the Line")
agv("AG-line-not-customer", agres(signers=[asig(g0, "customer", CLIENT), {"basis": "line", "role": "landlord", "pub": LANDLORD.pub, "result": lresult(client=LANDLORD, summary=LSUM)},
    asig(g0, "technician", TECH)]), "REFUSE", "RESULT_BASIS_INVALID", note="a Line Result stands only for the customer")
agv("AG-line-same-key", agres(signers=[asig(g0, "customer", CLIENT), {"basis": "line", "role": "landlord", "pub": CLIENT.pub, "result": lresult(summary=LSUM)},
    asig(g0, "technician", TECH)]), "REFUSE", "AGREEMENT_INVALID", note="the customer's key cannot also be the landlord")
# red team 55: typed members — a pattern is tested only on a string (['x'] is not 'x')
agv("AG-outcome-array", agres(outcome=["repair-accepted"]), "REFUSE", "AGREEMENT_INVALID")
agv("AG-option-array", agres(option=["accept"], outcome="repair-accepted", signers=std_signers(g0)), "REFUSE", "AGREEMENT_INVALID")
agv("AG-role-array", agres(signers=[{**asig(g0, "customer", CLIENT), "role": ["customer"]}, asig(g0, "landlord", LANDLORD), asig(g0, "technician", TECH)], sort=False), "REFUSE", "AGREEMENT_INVALID")
g_arr = agq(template=["repair-ok"])
agv("AG-template-array", agres(q=g_arr, signers=std_signers(g_arr)), "REFUSE", "AGREEMENT_INVALID")
# making and the signed bytes
MKG = {"provider": "provider A", "aud": A, "question": g0, "option": "accept", "signers": std_signers(g0), "epoch": 1, "issued_at": NOW, "result_id": rid("agreement result")}
vec("AG-make", "lp02.agreement", [step("agr.make", MKG, "ACCEPT", None, {"signature": ok_g["signature"], "outcome": "repair-accepted"})], note="the same Result, byte for byte")
vec("AG-make-not-agreed", "lp02.agreement", [step("agr.make", {**MKG, "option": "later"}, "REFUSE", "RESULT_NOT_AGREED")])
vec("AG-body", "lp02.agreement", [step("agr.body", {"question": g0, "role": "landlord"}, "ACCEPT", None, {"body": ag_body(g0, "landlord")})], note="the exact bytes an actor signs")
# the portable proof (basis "agreement")
pf("PF-agreement", proof("agreement", result=ok_g), "ACCEPT", res={"outcome": "repair-accepted", "basis": "agreement", "client_kid": CLIENT.kid, "roles": ["customer", "landlord", "technician"]})
g_nc = agq(policy={"requirements": [{"roles": ["landlord"], "min": 1}, {"roles": ["technician"], "min": 1}]})
nc = agres(q=g_nc, signers=[asig(g_nc, "landlord", LANDLORD), asig(g_nc, "technician", TECH)])
pf("PF-agreement-no-customer", proof("agreement", result=nc, agreement=None), "ACCEPT", res={"basis": "agreement", "client_kid": None}, note="no customer signer: no customer authority")
pf("PF-agreement-customer-hidden", proof("agreement", result=ok_g, agreement=None), "REFUSE", "KEY_MISMATCH", note="a customer signer needs its authority in the proof")
pf("PF-agreement-role", proof("agreement", result={**ok_g, "signers": [{**ok_g["signers"][0], "role": "tenant"}] + ok_g["signers"][1:]}), "REFUSE", "SIGNATURE_INVALID")
pf("PF-agreement-epoch", proof("agreement", result=agres(epoch=2)), "REFUSE", "PROOF_AUTHORITY")
pf("PF-agreement-threshold", proof("agreement", result=agres(q=g_low, signers=[asig(g_low, "customer", CLIENT, body_q=g0), asig(g_low, "technician", TECH, body_q=g0)])),
   "REFUSE", "RESULT_BASIS_INVALID")
pf("PF-agreement-as-request-answer", proof(result=ok_g), "REFUSE", "PROOF_INVALID", note="an agreement offered on the request-answer basis")
pf("PF-agreement-v2", proof("agreement", result=agres(v="lp02.agreement/2")), "REFUSE", "MODULE_VERSION_UNSUPPORTED")

# ---- block 50: lp02.nonce/1 (SPEC §16) — CREATED = freshness, NONCE = uniqueness, never rate or authority
NC_URI = f"{A}/t/{RT}"
NC_BIND = {"client_kid": CLIENT.kid, "client_thing_pub": CLIENT.pub}


def nonce_of(label):
    return b64u(hashlib.sha256(("LP02 NONCE " + label).encode()).digest()[:16])


def nreq(label="n", method="GET", uri=NC_URI, body="", key=CLIENT, created=NOW, kid=None, nonce=None, order="std", sign_params=None, digest=None):
    n = nonce if nonce is not None else nonce_of(label)
    with_digest = digest if digest is not None else (method == "POST" and body not in ("", "{}"))
    comps = '"@method" "@target-uri" "content-digest"' if with_digest else '"@method" "@target-uri"'
    k = kid or key.kid
    params = (f'({comps});created={created};nonce="{n}";keyid="{k}";alg="ed25519"' if order == "std"
              else f'({comps});created={created};keyid="{k}";nonce="{n}";alg="ed25519"')
    d = digest_of(body) if with_digest else None
    signed = sign_params or params
    lines = [f'"@method": {method}', f'"@target-uri": {uri}'] + ([f'"content-digest": {d}'] if d else []) + [f'"@signature-params": {signed}']
    h = {"signature-input": "sig1=" + params, "signature": "sig1=:" + __import__("base64").b64encode(key.sk.sign("\n".join(lines).encode())).decode() + ":"}
    if d:
        h["content-digest"] = d
    return {"method": method, "target_uri": uri, "headers": h, "body": body}


def nv(id_, steps, required=True, note=""):
    vec(id_, "lp02.nonce", steps, {"now": NOW, "binding": NC_BIND, "required": required}, note)


def ns(req, outcome, code=None, at=None):
    return step("nonce.verify", {**req, **({"now": at} if at is not None else {})}, outcome, code, {"kid": CLIENT.kid} if outcome == "ACCEPT" else None)


POSTB = '{"answer":"yes"}'
nv("NC-valid-get", [ns(nreq("g1"), "ACCEPT")])
nv("NC-valid-post", [ns(nreq("p1", "POST", body=POSTB), "ACCEPT")])
nv("NC-same-second", [ns(nreq(f"s{k}"), "ACCEPT") for k in range(50)] + [ns(nreq(f"m{k}", "POST", body=POSTB), "ACCEPT") for k in range(50)],
   note="100 requests from one key in ONE second, same target and body: no false replay")
nv("NC-replay-exact", [ns(nreq("r1", "POST", body=POSTB), "ACCEPT"), ns(nreq("r1", "POST", body=POSTB), "REFUSE", "NONCE_REPLAYED")])
nv("NC-replay-get", [ns(nreq("r2"), "ACCEPT"), ns(nreq("r2"), "REFUSE", "NONCE_REPLAYED")])
nv("NC-dup-nonce-other-body", [ns(nreq("d1", "POST", body=POSTB), "ACCEPT"), ns(nreq("d1", "POST", body='{"answer":"no"}'), "REFUSE", "NONCE_REPLAYED")],
   note="a nonce is single-use for its key, whatever is signed with it")
nv("NC-dup-nonce-other-target", [ns(nreq("d2"), "ACCEPT"), ns(nreq("d2", uri=f"{A}/t/{RT}/requests"), "REFUSE", "NONCE_REPLAYED")])
nv("NC-restart-post", [ns(nreq("x1", "POST", body=POSTB), "ACCEPT"), step("nonce.restart", {}, "ACCEPT"), ns(nreq("x1", "POST", body=POSTB), "REFUSE", "NONCE_REPLAYED")],
   note="a state-changing request's nonce survives a restart (persistent fingerprint, bounded TTL)")
nv("NC-restart-get", [ns(nreq("x2"), "ACCEPT"), step("nonce.restart", {}, "ACCEPT"), ns(nreq("x2"), "ACCEPT")],
   note="a SAFE READ's nonce lives in memory only: after a restart the same read is answered again (harmless, specified)")
nv("NC-expired-created", [ns(nreq("e1", created=NOW - 400), "REFUSE", "SIGNATURE_INVALID")], note="a fresh nonce does not make an old request fresh")
nv("NC-future-created", [ns(nreq("e2", created=NOW + 400), "REFUSE", "SIGNATURE_INVALID")])
nv("NC-wrong-key", [ns(nreq("k1", key=OTHER), "REFUSE", "KEY_MISMATCH")])
nv("NC-wrong-key-claims-kid", [ns(nreq("k2", key=OTHER, kid=CLIENT.kid), "REFUSE", "SIGNATURE_INVALID")])
nv("NC-malformed-short", [ns(nreq(nonce="A" * 21), "REFUSE", "NONCE_INVALID")])
nv("NC-malformed-noncanonical", [ns(nreq(nonce="A" * 21 + "B"), "REFUSE", "NONCE_INVALID")], note="16 bytes have ONE base64url spelling")
nv("NC-malformed-padding", [ns(nreq(nonce="A" * 20 + "=="), "REFUSE", "NONCE_INVALID")])
nv("NC-malformed-empty", [ns(nreq(nonce=""), "REFUSE", "NONCE_INVALID")])
nv("NC-malformed-long", [ns(nreq(nonce="A" * 43), "REFUSE", "NONCE_INVALID")])
lp01 = hreq("GET", NC_URI, "", CLIENT, NOW)
nv("NC-omitted-required", [ns(lp01, "REFUSE", "NONCE_REQUIRED")], note="negotiated: never silently downgraded to LP 0.1")
nv("NC-omitted-not-required", [ns(lp01, "IGNORE")], required=False, note="not negotiated: LP 0.1 §6.5 applies, unchanged")
nv("NC-param-order", [ns(nreq("o1", order="swapped"), "REFUSE", "SIGNATURE_INVALID")], note="one canonical parameter order")
nv("NC-nonce-not-signed", [ns(nreq("u1", sign_params=f'("@method" "@target-uri");created={NOW};keyid="{CLIENT.kid}";alg="ed25519"'), "REFUSE", "SIGNATURE_INVALID")],
   note="the nonce is inside @signature-params")
nv("NC-body-unsigned", [ns(nreq("b1", "POST", body=POSTB, digest=False), "REFUSE", "DIGEST_MISMATCH")])

# ---- block 56: trust without global identity (SPEC §18) — VERIFIED apart from CLAIMED; introductions by context
INTRO_V = "lp02.introduction/1"
IT = rid("thing of the introduction")
TPID = rid("target point")
ITHING = {"thing_id": IT, "aud": A, "provider_pub": PROV_A.pub, "client_pub": CLIENT.pub}
TARGET = {"aud": B, "point_id": TPID, "provider_pub": PROV_B.pub}
PV = {"v": "lp02.admission/1", "aud": B, "provider_pub": PROV_B.pub, "point_id": TPID, "label": "Bike repair", "service": "repair.bike",
      "purposes": [{"code": "visit", "label": "A visit"}], "admission": {"mode": "public", "humans": "allow", "agents": "deny"}, "channels": ["data"],
      "valid_until": iso(NOW + 86400), "open": f"{B}/o/{TPID}"}


def intro(key=PROV_A, typ="lp02.introduction", by="provider", **over):
    x = {"v": INTRO_V, "intro_id": rid("introduction"), "thing_id": IT, "aud": A, "by": by, "target": dict(TARGET), "purpose": "visit",
         "issued_at": iso(NOW - 60), "exp": iso(NOW + 86400)}
    x.update(over)
    return sign(x, typ, key)


def iv(id_, x, outcome, code=None, res=None, point=None, fetched_from=None, thing=None, note=""):
    inp = {"intro": x}
    if point is not None:
        inp["point"] = point
        inp["fetched_from"] = fetched_from
    vec(id_, "lp02.introduction", [step("intro.verify", inp, outcome, code, res)], {"thing": thing or ITHING}, note)


iv("IN-valid", intro(), "ACCEPT", res={"checked_target": False, "purpose": "visit", "introduced_by": {"thing_id": IT, "role": "provider", "kid": PROV_A.kid},
   "target": {"aud": B, "point_id": TPID, "provider_kid": PROV_B.kid}}, note="signed with the key of the person's OWN Thing with the introducer")
iv("IN-valid-target", intro(), "ACCEPT", point=PV, fetched_from=B, res={"checked_target": True, "claimed": {"label": "Bike repair", "service": "repair.bike", "purposes": ["A visit"]}},
   note="the page in front of the person is the one meant: origin, point and key; its words are claims")
iv("IN-by-client", intro(key=CLIENT, by="client"), "ACCEPT", res={"introduced_by": {"thing_id": IT, "role": "client", "kid": CLIENT.kid}}, note="the other direction: the client introduces")
iv("IN-role-swapped", intro(key=CLIENT, by="provider"), "REFUSE", "SIGNATURE_INVALID", note="signed by the client, claiming to be the provider")
iv("IN-stranger", intro(key=OTHER), "REFUSE", "SIGNATURE_INVALID", note="a key the person has no relationship with introduces no one")
iv("IN-other-thing", intro(thing_id=rid("another thing")), "REFUSE", "INTRO_SCOPE")
iv("IN-other-aud", intro(aud=B), "REFUSE", "INTRO_SCOPE")
iv("IN-expired", intro(issued_at=iso(NOW - 7200), exp=iso(NOW)), "REFUSE", "INTRO_EXPIRED")
iv("IN-future", intro(issued_at=iso(NOW + 301), exp=iso(NOW + 4000)), "REFUSE", "INTRO_EXPIRED")
iv("IN-too-long", intro(exp=iso(NOW - 60 + 7 * 86400 + 1)), "REFUSE", "INTRO_INVALID", note="an introduction lives at most 7 days — never an address")
iv("IN-tampered-target", {**intro(), "target": {**TARGET, "provider_pub": OTHER.pub}}, "REFUSE", "SIGNATURE_INVALID")
# 56D phishing / substitution: the target the device fetched is checked against the signed one
iv("IN-target-key-substituted", intro(), "REFUSE", "INTRO_TARGET_MISMATCH", point={**PV, "provider_pub": OTHER.pub}, fetched_from=B, note="the right address serving another key")
iv("IN-target-lookalike", intro(), "REFUSE", "INTRO_TARGET_MISMATCH", point={**PV, "aud": "https://b-example.com"}, fetched_from="https://b-example.com",
   note="a look-alike origin with the same label and purposes")
iv("IN-target-copied", intro(), "REFUSE", "INTRO_TARGET_MISMATCH", point=PV, fetched_from="https://evil.example", note="the genuine view, served from somewhere else")
iv("IN-target-other-point", intro(), "REFUSE", "INTRO_TARGET_MISMATCH", point={**PV, "point_id": rid("other point")}, fetched_from=B)
iv("IN-target-expired", intro(), "REFUSE", "OPEN_POINT_UNKNOWN", point={**PV, "valid_until": iso(NOW)}, fetched_from=B, note="an introduction does not keep a point open")
iv("IN-target-purpose", intro(purpose="quote"), "REFUSE", "OPEN_PURPOSE_UNKNOWN", point=PV, fetched_from=B)
# no identity, no text
iv("IN-name", intro(name="Margus"), "REFUSE", "INTRO_INVALID", note="no 'find Margus': an introduction names a point and a key, never a person")
iv("IN-note", intro(note="trust me"), "REFUSE", "INTRO_INVALID", note="no words travel")
iv("IN-target-label", intro(target={**TARGET, "label": "Bike repair"}), "REFUSE", "INTRO_INVALID")
iv("IN-target-http", intro(target={**TARGET, "aud": "http://b.example"}), "REFUSE", "INTRO_INVALID", note="a target origin is https (localhost only for tests)")
iv("IN-target-array", intro(target={**TARGET, "aud": [B]}), "REFUSE", "INTRO_INVALID")
# red team 56: an origin is ASCII lower-case (punycode shows as xn--), a time is a real time
iv("IN-target-homograph", intro(target={**TARGET, "aud": "https://bіke.example"}), "REFUSE", "INTRO_INVALID", note="a Cyrillic letter in the origin: refused, never displayed as the Latin look-alike")
iv("IN-target-upper", intro(target={**TARGET, "aud": "https://B.example"}), "REFUSE", "INTRO_INVALID")
iv("IN-bad-date", intro(exp="2026-13-45T00:00:00Z"), "REFUSE", "INTRO_INVALID", note="matches the pattern, is no time")
iv("IN-by-agent", intro(by="agent"), "REFUSE", "INTRO_INVALID", note="introducers are the two parties of the Thing")
iv("IN-typ", intro(typ="lp02.referral"), "REFUSE", "SIGNATURE_INVALID")
iv("IN-v2", intro(v="lp02.introduction/2"), "REFUSE", "MODULE_VERSION_UNSUPPORTED")
vec("IN-make", "lp02.introduction", [step("intro.make", {"signer": "provider A", "by": "provider", "thing_id": IT, "aud": A, "target": TARGET, "purpose": "visit",
    "issued_at": NOW - 60, "exp": NOW + 86400, "intro_id": rid("introduction")}, "ACCEPT", None, {"signature": intro()["signature"]})], note="the same introduction, byte for byte")
vec("IN-make-too-long", "lp02.introduction", [step("intro.make", {"signer": "provider A", "by": "provider", "thing_id": IT, "aud": A, "target": TARGET, "purpose": "visit",
    "issued_at": NOW, "exp": NOW + 8 * 86400, "intro_id": rid("introduction")}, "REFUSE", "INTRO_INVALID")])

# 56A trust view: what is VERIFIED (key, origin, signature, freshness, a pin) apart from what is CLAIMED
TDESC_POINTS = [{k: v for k, v in PV.items() if k not in ("v", "aud", "provider_pub")}]


def tv(id_, doc, fetched_from, outcome, code=None, res=None, pins=None, note=""):
    vec(id_, "lp02.trust", [step("trust.view", {"doc": doc, "fetched_from": fetched_from, "pins": pins or []}, outcome, code, res)], {}, note)


DB = descriptor(key=PROV_B, aud=B, tenant="Bike repair Ltd", points=TDESC_POINTS)
tv("TV-new", DB, B, "ACCEPT", res={"verified": {"origin": B, "provider_kid": PROV_B.kid, "signed": True, "fresh_until": iso(NOW + 3000), "known": "new", "same_key_at": []},
   "claimed": {"tenant": "Bike repair Ltd", "points": ["Bike repair"]}}, note="the company name is the publisher's claim; the key and the origin are verified")
tv("TV-pinned", DB, B, "ACCEPT", pins=[{"origin": B, "provider_pub": PROV_B.pub}], res={"verified": {"origin": B, "provider_kid": PROV_B.kid, "signed": True,
   "fresh_until": iso(NOW + 3000), "known": "pinned", "same_key_at": []}}, note="the same key as the person's earlier relationship with this origin")
tv("TV-key-substituted", descriptor(key=OTHER, aud=B, tenant="Bike repair Ltd", points=TDESC_POINTS), B, "REFUSE", "KEY_MISMATCH",
   pins=[{"origin": B, "provider_pub": PROV_B.pub}], note="a known origin presenting another key: refused, never silently 'updated'")
tv("TV-copied", DB, "https://b-example.com", "REFUSE", "TRUST_ORIGIN_MISMATCH", note="the genuine signed descriptor, re-served from a look-alike origin")
tv("TV-clone-new-key", descriptor(key=OTHER, aud="https://b-example.com", tenant="Bike repair Ltd", points=TDESC_POINTS), "https://b-example.com", "ACCEPT",
   pins=[{"origin": B, "provider_pub": PROV_B.pub}], res={"verified": {"origin": "https://b-example.com", "provider_kid": OTHER.kid, "signed": True, "fresh_until": iso(NOW + 3000),
   "known": "new", "same_key_at": []}, "claimed": {"tenant": "Bike repair Ltd", "points": ["Bike repair"]}},
   note="the same CLAIMS at a look-alike origin: verified shows a NEW key at another origin — the claims prove nothing")
tv("TV-same-key-elsewhere", DB, B, "ACCEPT", pins=[{"origin": "https://bikes.example", "provider_pub": PROV_B.pub}],
   res={"verified": {"origin": B, "provider_kid": PROV_B.kid, "signed": True, "fresh_until": iso(NOW + 3000), "known": "new", "same_key_at": ["https://bikes.example"]}})
tv("TV-point-view", PV, B, "ACCEPT", res={"verified": {"origin": B, "provider_kid": PROV_B.kid, "signed": False, "fresh_until": iso(NOW + 86400), "known": "new", "same_key_at": []},
   "claimed": {"label": "Bike repair", "service": "repair.bike", "purposes": ["A visit"]}}, note="an unsigned point view: only TLS vouches for origin and key")
tv("TV-tampered", {**DB, "tenant": "Bank"}, B, "REFUSE", "SIGNATURE_INVALID")
tv("TV-typ", descriptor(key=PROV_B, typ="lp02.open", aud=B), B, "REFUSE", "SIGNATURE_INVALID")
tv("TV-stale", descriptor(key=PROV_B, aud=B, valid_until=iso(NOW)), B, "REFUSE", "FED_DOC_STALE")
tv("TV-http", {**PV, "aud": "http://b.example"}, "http://b.example", "REFUSE", "TRUST_INVALID")
tv("TV-homograph", {**PV, "aud": "https://bіke.example"}, "https://bіke.example", "REFUSE", "TRUST_INVALID")
tv("TV-bad-date", {**PV, "valid_until": "2026-02-30T00:00:00Z"}, B, "REFUSE", "FED_DOC_STALE", note="matches the pattern, is no time: never fresh")
tv("TV-no-key", {k: v for k, v in PV.items() if k != "provider_pub"}, B, "REFUSE", "TRUST_INVALID")

OUT.write_text(json.dumps({"kind": "lyne-lp02-vectors/1", "status": "PRIVATE - EXPERIMENTAL - UNPUBLISHED - NOT LP 0.1", "now": NOW, "count": len(V), "vectors": V}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
print(f"{len(V)} vectors -> {OUT}")
