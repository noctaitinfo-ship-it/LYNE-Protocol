#!/usr/bin/env python3
"""Generates the conformance vectors of the EXPERIMENTAL module lp02.channel/2 (SPEC.md) — deterministic, byte-stable.

EXPERIMENTAL · PRIVATE · NOT LP 0.1. /2 differs from /1 in one place: an actor names adapter BINDINGS, the runtime MINTS
the Endpoint references (SPEC §1). In conformance mode the n-th minted reference of an instance is
b64u(SHA-256("LP02 TEST MINT " + mint_seed + " " + n))[:22]; this generator tracks n per vector (class Minter).
Test keys: seed = SHA-256("LP02 TEST KEY " + label), as every LP 0.2 vector set. No vector carries a private key.
Importable (the red team builds its scenarios with these helpers).

Usage: python generate.py   (writes channel2-vectors.json beside this file)
"""

import base64
import datetime
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
NOW = 1790000000
V = "lp02.channel/2"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jcs(v) -> bytes:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(obj):
    return b64u(hashlib.sha256(jcs(obj)).digest())


class Key:
    def __init__(self, label):
        self.label = label
        self.sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("LP02 TEST KEY " + label).encode()).digest())
        self.pub = b64u(self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.kid = b64u(hashlib.sha256(jcs({"crv": "Ed25519", "kty": "OKP", "x": self.pub})).digest())


def sign(key, obj, typ, kid=None):
    header = b64u(jcs({"alg": "EdDSA", "kid": kid or key.kid, "typ": typ}))
    payload = b64u(jcs({k: v for k, v in obj.items() if k != "signature"}))
    return header + ".." + b64u(key.sk.sign((header + "." + payload).encode("ascii")))


def ident(label):
    return b64u(hashlib.sha256(("lp02.channel vector id " + label).encode()).digest()[:16])


def binding(label):
    """An adapter-issued opaque binding handle (the actor's registration with its own adapter)."""
    return b64u(hashlib.sha256(("lp02.channel/2 binding " + label).encode()).digest())[:24]


def minted(seed, n):
    return b64u(hashlib.sha256(f"LP02 TEST MINT {seed} {n}".encode()).digest())[:22]


class Minter:
    """Mirrors an instance's conformance-mode minting: refs in accept order."""
    def __init__(self, seed):
        self.seed, self.n = seed, 0

    def take(self, k):
        out = [minted(self.seed, self.n + i) for i in range(k)]
        self.n += k
        return out


K = {n: Key("channel " + n) for n in ("alice", "bob", "provider", "mallory", "oldphone", "agent1")}
ROLE = {"alice": "customer", "bob": "technician", "provider": "provider", "oldphone": "customer", "mallory": "customer", "agent1": "agent"}
THING = ident("thing")
BINDINGS = {
    "alice": [binding("alice email"), binding("alice voice"), binding("alice agent")],
    "bob": [binding("bob email"), binding("bob voice"), binding("bob agent"), binding("bob api"), binding("bob holo")],
    "provider": [binding("provider api")],
    "agent1": [binding("agent1 api")],
    "oldphone": [binding("oldphone email")],
}
BA_MAIL, BA_VOICE, BA_AGENT = BINDINGS["alice"]
BB_MAIL, BB_VOICE, BB_AGENT, BB_API, BB_HOLO = BINDINGS["bob"]


def party(n):
    return {"role": ROLE[n], "kid": K[n].kid}


def context(status="OPEN", negotiated=True, thing=THING, seed="thing-1"):
    parties = [{"role": ROLE[n], "kid": K[n].kid, "pub": K[n].pub, "revoked": n == "oldphone"} for n in ("alice", "bob", "provider", "oldphone", "agent1")]
    return {"now": NOW, "negotiated": negotiated, "mint_seed": seed, "bindings": {K[n].kid: list(b) for n, b in BINDINGS.items()},
            "thing": {"thing_id": thing, "status": status, "parties": parties}}


def offer(actor, routes, issued=NOW - 100, ttl=86400, *, thing=THING, signer=None, kid=None, typ="lp02.endpoint-offer", extra_route=None, as_actor=None, v=V):
    rs = []
    for r in routes:
        ch, b = r[0], r[1]
        exp = r[2] if len(r) > 2 else issued + ttl
        rr = {"channel": ch, "binding": b, "expires_at": iso(exp)}
        if extra_route:
            rr.update(extra_route)
        rs.append(rr)
    o = {"v": v, "thing_id": thing, "actor": as_actor or party(actor), "routes": rs, "issued_at": iso(issued), "expires_at": iso(issued + ttl)}
    o["signature"] = sign(signer or K[actor], o, typ, kid)
    return o


def request(frm, to, label, payload, created=NOW - 10, life=510, *, thing=THING, signer=None, kid=None, typ="lp02.delivery", extra=None, as_from=None, as_to=None, v=V):
    r = {"v": v, "thing_id": thing, "delivery_id": ident(label), "from": as_from or party(frm), "to": as_to or party(to),
         "payload_digest": digest(payload), "created": iso(created), "exp": iso(created + life)}
    if extra:
        r.update(extra)
    r["signature"] = sign(signer or K[frm], r, typ, kid)
    return r


def receipt(by, req, *, payload_digest=None, signer=None, as_by=None, received=NOW):
    r = {"v": V, "thing_id": req["thing_id"], "delivery_id": req["delivery_id"], "by": as_by or party(by),
         "payload_digest": payload_digest or req["payload_digest"], "received_at": iso(received)}
    r["signature"] = sign(signer or K[by], r, "lp02.delivery-receipt")
    return r


def text(t):
    return {"type": "text", "text": t}


def step(op, inp, outcome="ACCEPT", code=None, result=None):
    e = {"outcome": outcome}
    if code:
        e["code"] = code
    if result is not None:
        e["result"] = result
    return {"op": op, "input": inp, "expect": e}


class Gens:
    def __init__(self):
        self.g = {}

    def next(self, kid):
        self.g[kid] = self.g.get(kid, 0) + 1
        return self.g[kid]


def s_offer(o, m=None, outcome="ACCEPT", code=None, gens=None):
    """ACCEPT consumes len(routes) minted references from the vector's Minter; returns (step, refs)."""
    if outcome != "ACCEPT":
        return step("ch2.offer", o, outcome, code), []
    refs = m.take(len(o["routes"]))
    g = gens.next(o["actor"]["kid"]) if gens else 1
    res = {"actor": o["actor"]["kid"], "generation": g, "routes": [{"channel": r["channel"], "endpoint_ref": e} for r, e in zip(o["routes"], refs)]}
    return step("ch2.offer", o, "ACCEPT", None, res), refs


def s_send(req, payload=None, outcome="ACCEPT", code=None, routes=None):
    inp = {"request": req, **({"payload": payload} if payload is not None else {})}
    res = {"delivery_id": req["delivery_id"], **({"routes": routes} if routes is not None else {})} if outcome == "ACCEPT" else None
    return step("ch2.send", inp, outcome, code, res)


def attempt(req, n, channel, endpoint, status, relay=None, outcome="ACCEPT", code=None, at=NOW, v=V):
    route = {"channel": channel, "endpoint_ref": endpoint, **({"relay": relay} if relay else {})}
    a = {"v": v, "delivery_id": req["delivery_id"] if isinstance(req, dict) else req, "attempt": n, "route": route, "status": status, "at": iso(at)}
    return step("ch2.attempt", a, outcome, code, {"attempt": n, "status": status} if outcome == "ACCEPT" else None)


def s_receipt(rc, outcome="ACCEPT", code=None):
    return step("ch2.receipt", rc, outcome, code, {"delivery_id": rc["delivery_id"], "status": "DELIVERED"} if outcome == "ACCEPT" else None)


def s_resolve(requester, target, delivery=None, outcome="ACCEPT", code=None, routes=None):
    inp = {"requester": party(requester), "target": party(target), **({"delivery_id": delivery["delivery_id"] if isinstance(delivery, dict) else delivery} if delivery else {})}
    res = {"routes": sorted(({"channel": c, "endpoint_ref": e} for c, e in routes), key=lambda r: (r["channel"], r["endpoint_ref"]))} if outcome == "ACCEPT" else None
    return step("ch2.resolve", inp, outcome, code, res)


def tick(t):
    return step("ch2.tick", {"now": t}, result={})


def record(offers, active, digests=None, thing=THING):
    return step("ch2.record", {}, result={"thing_id": thing, "offers": [{"actor": K[a].kid, "channels": sorted(ch)} for a, ch in sorted(offers, key=lambda x: K[x[0]].kid)],
                                           "active_deliveries": active, "retained_digests": active if digests is None else digests, "content_retained": False})


VECTORS = []


def vec(vid, steps, note, ctx=None):
    VECTORS.append({"id": vid, "module": "lp02.channel", "note": note, "context": ctx or context(), "steps": steps})


class Scenario:
    """One vector's minter + generation counter, so ACCEPT results carry the exact minted references."""
    def __init__(self, seed="thing-1"):
        self.m, self.g, self.seed = Minter(seed), Gens(), seed

    def offer(self, o, outcome="ACCEPT", code=None):
        return s_offer(o, self.m, outcome, code, self.g)


P1, P2, P3 = text("Meeting tomorrow?"), text("Yes, 14:00."), text("Send me the address.")
R1 = request("alice", "bob", "d1", P1)
R2 = request("bob", "alice", "d2", P2)
R3 = request("alice", "bob", "d3", P3)
PURGE = NOW - 10 + 510 + 300 + 1
OA = offer("alice", [("email", BA_MAIL), ("voice", BA_VOICE), ("agent", BA_AGENT)])
OB = offer("bob", [("email", BB_MAIL), ("voice", BB_VOICE), ("agent", BB_AGENT)])


def both(sc):
    sa, ra = sc.offer(OA)
    sb, rb = sc.offer(OB)
    return [sa, sb], dict(zip(("email", "voice", "agent"), ra)), dict(zip(("email", "voice", "agent"), rb))


# ---- the OWNER's cross-channel case, with minted references
sc = Scenario()
st, A, B = both(sc)
vec("C2-one-thing-three-channels", st + [
    s_send(R1, P1, routes=3), attempt(R1, 1, "email", B["email"], "SENT", relay="mail-adapter"), s_receipt(receipt("bob", R1)),
    s_send(R2, P2, routes=3), attempt(R2, 1, "voice", A["voice"], "SENT", relay="tel-adapter"), s_receipt(receipt("alice", R2)),
    s_send(R3, P3, routes=3), attempt(R3, 1, "agent", B["agent"], "SENT"), s_receipt(receipt("bob", R3)),
    record([("alice", ["agent", "email", "voice"]), ("bob", ["agent", "email", "voice"])], 3),
    tick(PURGE), record([("alice", ["agent", "email", "voice"]), ("bob", ["agent", "email", "voice"])], 0),
], "three exchanges over minted references; after retention only the current offers (channel classes) remain")

# ---- offers: bindings in, minted references out
sc = Scenario()
s1, r1 = sc.offer(offer("alice", [("email", BA_MAIL)], issued=NOW - 200))
s2, r2 = sc.offer(offer("alice", [("email", BA_MAIL)], issued=NOW - 100))
assert r1 != r2
vec("C2-offer-mints-and-rotates", [s1, s2, s_resolve("alice", "alice", routes=[("email", r2[0])]), record([("alice", ["email"])], 0)],
    "the same binding offered again gets a NEW reference (generation 2): rotation is structural; the old reference is gone")
sc = Scenario()
s1, r1 = sc.offer(offer("bob", [("email", BB_MAIL)], issued=NOW - 200))
s2, r2 = sc.offer(offer("bob", [("agent", BB_AGENT)], issued=NOW - 100))
vec("C2-withdrawn-ref-not-offered", [s1, s_send(R1, P1), attempt(R1, 1, "email", r1[0], "FAILED"), s2,
                                      attempt(R1, 2, "email", r1[0], "SENT", outcome="REFUSE", code="ROUTE_NOT_OFFERED"), attempt(R1, 2, "agent", r2[0], "SENT"),
                                      s_receipt(receipt("bob", R1))],
    "a replaced (withdrawn) reference: ROUTE_NOT_OFFERED, like any other")
sc = Scenario()
vec("C2-offer-stale-ratchet", [sc.offer(offer("alice", [("agent", BA_AGENT)], issued=NOW - 100))[0],
                               sc.offer(offer("alice", [("email", BA_MAIL)], issued=NOW - 200), "REFUSE", "OFFER_STALE")[0]], "an older offer cannot come back")
vec("C2-offer-expired", [s_offer(offer("alice", [("email", BA_MAIL)], issued=NOW - 1000, ttl=500), outcome="REFUSE", code="OFFER_STALE")[0]], "an expired offer")
vec("C2-offer-address-email", [s_offer(offer("alice", [("email", "alice@example.com")]), outcome="REFUSE", code="ENDPOINT_EXPOSED")[0]], "an e-mail address as binding")
vec("C2-offer-address-phone", [s_offer(offer("alice", [("sms", "+372555012345678")]), outcome="REFUSE", code="ENDPOINT_EXPOSED")[0]], "a phone number as binding")
vec("C2-offer-address-url", [s_offer(offer("alice", [("api", "https://alice.example/hook")]), outcome="REFUSE", code="ENDPOINT_EXPOSED")[0]], "a URL as binding")
vec("C2-offer-short-binding", [s_offer(offer("alice", [("email", "abc123")]), outcome="REFUSE", code="OFFER_INVALID")[0]], "a binding too short to be opaque")
vec("C2-offer-endpoint-supplied", [s_offer(offer("alice", [("email", BA_MAIL)], extra_route={"endpoint_ref": minted("thing-1", 0)}), outcome="REFUSE", code="OFFER_INVALID")[0]],
    "an actor never supplies an Endpoint reference")
vec("C2-offer-forbidden-name", [s_offer(offer("alice", [("email", BA_MAIL)], extra_route={"note": "call after 5"}), outcome="REFUSE", code="OFFER_INVALID")[0]],
    "a person's words inside an offer (§2.1.6)")
vec("C2-offer-too-long", [s_offer(offer("alice", [("email", BA_MAIL)], ttl=30 * 86400 + 1), outcome="REFUSE", code="OFFER_INVALID")[0]], "longer than 30 days")
vec("C2-offer-duplicate-binding", [s_offer(offer("alice", [("email", BA_MAIL), ("agent", BA_MAIL)]), outcome="REFUSE", code="OFFER_INVALID")[0]], "one binding for two routes")
vec("C2-offer-v1-object", [s_offer(offer("alice", [("email", BA_MAIL)], v="lp02.channel/1"), outcome="REFUSE", code="MODULE_VERSION_UNSUPPORTED")[0]],
    "a /1 offer is never read as /2 (no silent substitution)")
vec("C2-offer-other-thing", [s_offer(offer("alice", [("email", BA_MAIL)], thing=ident("other thing")), outcome="REFUSE", code="CHANNEL_THING_MISMATCH")[0]], "another Thing")
vec("C2-offer-thing-closed", [s_offer(OA, outcome="REFUSE", code="THING_CLOSED")[0]], "a CLOSED Thing", ctx=context("CLOSED"))
vec("C2-offer-actor-unknown", [s_offer(offer("mallory", [("email", binding("mallory email"))]), outcome="REFUSE", code="ACTOR_UNKNOWN")[0]], "not a party")
vec("C2-offer-actor-revoked", [s_offer(offer("oldphone", [("email", BINDINGS["oldphone"][0])]), outcome="REFUSE", code="KEY_REVOKED")[0]], "the old device after a move")
vec("C2-offer-sig-forged", [s_offer(offer("alice", [("email", BA_MAIL)], signer=K["mallory"], kid=K["alice"].kid), outcome="REFUSE", code="SIGNATURE_INVALID")[0]], "forged")
vec("C2-offer-sig-wrong-typ", [s_offer(offer("alice", [("email", BA_MAIL)], typ="lp02.delivery"), outcome="REFUSE", code="SIGNATURE_INVALID")[0]], "another domain")
vec("C2-binding-unknown", [s_offer(offer("alice", [("email", binding("never issued"))]), outcome="REFUSE", code="BINDING_UNKNOWN")[0]], "a binding the adapter never issued")
vec("C2-binding-of-another-actor", [s_offer(offer("alice", [("email", BB_MAIL)]), outcome="REFUSE", code="BINDING_UNKNOWN")[0]],
    "another actor's binding: refused exactly like a random one")
sc = Scenario()
s1, r1 = sc.offer(OB)
vec("C2-ref-as-binding", [s1, sc.offer(offer("alice", [("email", r1[0])]), "REFUSE", "BINDING_UNKNOWN")[0]],
    "a minted reference presented as a binding: BINDING_UNKNOWN, like any string")
sc = Scenario()
s1, r1 = sc.offer(offer("bob", [("holo-link", BB_HOLO), ("agent", BB_AGENT)]))
vec("C2-offer-future-channel", [s1, s_send(R1, P1, routes=2), attempt(R1, 1, "holo-link", r1[0], "SENT", outcome="REFUSE", code="CHANNEL_UNSUPPORTED"),
                                attempt(R1, 1, "agent", r1[1], "SENT"), record([("bob", ["agent", "holo-link"])], 1)],
    "a future channel class is kept but not routable here")
sc = Scenario()
s1, _ = sc.offer(OB)
s2, _ = sc.offer(offer("bob", [], issued=NOW - 50))
vec("C2-offer-withdraw", [s1, s2, s_send(R1, P1, "REFUSE", "NO_ROUTE"), record([("bob", [])], 0)], "[] withdraws every route")
vec("C2-lp01-peer", [s_offer(OA, outcome="REFUSE", code="MODULE_NOT_NEGOTIATED")[0], s_send(R1, P1, "REFUSE", "MODULE_NOT_NEGOTIATED")],
    "an LP 0.1 peer never negotiated the module", ctx=context(negotiated=False))

# ---- deliveries (as /1, with minted references)
sc = Scenario()
s1, rb = sc.offer(OB)
B = dict(zip(("email", "voice", "agent"), rb))
vec("C2-route-change-during-delivery", [s1, s_send(R1, P1), attempt(R1, 1, "email", B["email"], "FAILED"), attempt(R1, 2, "agent", B["agent"], "SENT"),
                                        s_receipt(receipt("bob", R1)), record([("bob", ["agent", "email", "voice"])], 1)], "one delivery over two routes")
vec("C2-duplicate-request", [s1, s_send(R1, P1), s_send(R1, P1, "IGNORE"), attempt(R1, 1, "email", B["email"], "SENT"),
                             s_receipt(receipt("bob", R1)), s_receipt(receipt("bob", R1), "IGNORE")], "idempotent")
vec("C2-replay-other-payload", [s1, s_send(R1, P1), s_send(request("alice", "bob", "d1", text("Meeting today?")), text("Meeting today?"), "REFUSE", "DELIVERY_REPLAY")], "replay")
vec("C2-replay-after-expiry", [s1, s_send(R1, P1), tick(PURGE), s_send(R1, P1, "REFUSE", "DELIVERY_EXPIRED"), record([("bob", ["agent", "email", "voice"])], 0)], "dead after exp")
vec("C2-request-v1", [s1, s_send(request("alice", "bob", "v1", P1, v="lp02.channel/1"), P1, "REFUSE", "MODULE_VERSION_UNSUPPORTED")], "a /1 delivery request")
vec("C2-route-in-request", [s1, s_send(request("alice", "bob", "x3", P1, extra={"channel": "email"}), P1, "REFUSE", "DELIVERY_INVALID")], "no channel in a request")
vec("C2-history-in-request", [s1, s_send(request("alice", "bob", "x4", P1, extra={"prev": digest({"x": 1})}), P1, "REFUSE", "DELIVERY_INVALID")], "no history")
vec("C2-recipient-self", [s1, s_send(request("bob", "bob", "x7", P1), P1, "REFUSE", "RECIPIENT_INVALID")], "to the sender")
vec("C2-sender-revoked", [s1, s_send(request("oldphone", "bob", "x9", P1), P1, "REFUSE", "KEY_REVOKED")], "revoked sender")
vec("C2-payload-mismatch", [s1, s_send(R1, text("Meeting today?"), "REFUSE", "PAYLOAD_DIGEST_MISMATCH")], "payload not the signed one")
vec("C2-no-route", [s_send(R1, P1, "REFUSE", "NO_ROUTE"), record([], 0)], "no transport")
vec("C2-relay-claims-delivered", [s1, s_send(R1, P1), attempt(R1, 1, "email", B["email"], "DELIVERED", outcome="REFUSE", code="RECEIPT_REQUIRED")], "only the receipt delivers")
vec("C2-receipt-forged", [s1, s_send(R1, P1), s_receipt(receipt("bob", R1, signer=K["mallory"]), "REFUSE", "SIGNATURE_INVALID")], "forged receipt")
vec("C2-attempt-unknown", [attempt(ident("nothing"), 1, "email", B["email"], "SENT", outcome="REFUSE", code="DELIVERY_UNKNOWN")], "no such delivery")
vec("C2-receipt-wrong-party", [s1, s_send(R1, P1), s_receipt(receipt("provider", R1), "REFUSE", "RECEIPT_INVALID")], "a receipt by someone other than the recipient")
vec("C2-attempt-exposed", [s1, s_send(R1, P1), attempt(R1, 1, "email", "bob@example.com", "SENT", outcome="REFUSE", code="ENDPOINT_EXPOSED")], "an address in an attempt")
vec("C2-attempt-after-delivered", [s1, s_send(R1, P1), attempt(R1, 1, "email", B["email"], "SENT"), s_receipt(receipt("bob", R1)),
                                   attempt(R1, 2, "agent", B["agent"], "SENT", outcome="REFUSE", code="ATTEMPT_ORDER")], "nothing after DELIVERED")

# ---- R-1: no answer reveals whether a reference is live anywhere else
FOREIGN_THING = Scenario("thing-A")       # a reference legitimately learned in Thing A
_, ra = s_offer(OB, FOREIGN_THING.m, gens=Gens())
OTHER_TENANT = minted("tenant-2 thing-9", 0)
RANDOM = b64u(hashlib.sha256(b"random reference").digest())[:22]
sc = Scenario("thing-B")
s1, rb = sc.offer(OB)
probes = {"learned in Thing A (bob present here)": ra[0], "minted by another tenant": OTHER_TENANT, "random": RANDOM}
steps = [s1, s_send(R1, P1)]
for label, refv in probes.items():
    steps.append(attempt(R1, 1, "email", refv, "SENT", outcome="REFUSE", code="ROUTE_NOT_OFFERED"))
steps.append(attempt(R1, 1, "email", rb[0], "SENT"))
vec("C2-R1-foreign-ref-attempt", steps,
    "a reference learned in Thing A, one of another tenant and a random string: the SAME ROUTE_NOT_OFFERED, nothing else; the real route works", ctx=context(seed="thing-B"))
sc = Scenario("thing-B")
s1, rb = sc.offer(offer("bob", [("email", BB_MAIL, NOW + 100)]))
s2, ra2 = sc.offer(offer("alice", [("email", BA_MAIL)]))
vec("C2-R1-expired-and-other-actor", [s1, s2, s_send(R1, P1), tick(NOW + 101),
                                      attempt(R1, 1, "email", rb[0], "SENT", outcome="REFUSE", code="ROUTE_NOT_OFFERED"),
                                      attempt(R1, 1, "email", ra2[0], "SENT", outcome="REFUSE", code="ROUTE_NOT_OFFERED")],
    "an expired reference and another actor's live reference: the same refusal", ctx=context(seed="thing-B"))
sc = Scenario("thing-B")
vec("C2-R1-actor-absent", [sc.offer(OA)[0], s_send(R1, P1, "REFUSE", "NO_ROUTE"),
                           sc.offer(offer("alice", [("email", ra[0])], issued=NOW - 50), "REFUSE", "BINDING_UNKNOWN")[0]],
    "Bob has no offer here: a learned reference opens nothing, and presented as a binding it is BINDING_UNKNOWN like any string", ctx=context(seed="thing-B"))
sc = Scenario("thing-B")
s1, _ = sc.offer(offer("alice", [("email", BA_MAIL)], issued=NOW - 200))
probe_bindings = [ra[0], OTHER_TENANT, RANDOM, binding("never issued"), BB_MAIL]
vec("C2-R1-binding-probes", [s1] + [sc.offer(offer("alice", [("email", b)], issued=NOW - 100), "REFUSE", "BINDING_UNKNOWN")[0] for b in probe_bindings],
    "references and foreign bindings presented as bindings: always BINDING_UNKNOWN, never a different answer", ctx=context(seed="thing-B"))
# same real adapter target -> two Things -> two unrelated references
sx, sy = Scenario("thing-X"), Scenario("thing-Y")
ox, rx = sx.offer(offer("alice", [("email", BA_MAIL)]))
oy, ry = sy.offer(offer("alice", [("email", BA_MAIL)], thing=ident("thing Y")))
assert rx[0] != ry[0]
vec("C2-same-binding-thing-X", [ox, s_resolve("alice", "alice", routes=[("email", rx[0])])], "Alice's one e-mail binding in Thing X", ctx=context(seed="thing-X"))
ctx_y = context(seed="thing-Y", thing=ident("thing Y"))
vec("C2-same-binding-thing-Y", [oy, s_resolve("alice", "alice", routes=[("email", ry[0])]), record([("alice", ["email"])], 0, thing=ident("thing Y"))],
    "the SAME binding in Thing Y: an unrelated reference; the record names no binding", ctx=ctx_y)

# ---- visibility (as /1)
sc = Scenario()
s1, rb = sc.offer(OB)
BOB = list(zip(("email", "voice", "agent"), rb))
vec("C2-resolve-enumerate-refused", [s1, s_resolve("alice", "bob", outcome="REFUSE", code="OFFER_NOT_VISIBLE")], "no enumeration")
vec("C2-resolve-authorized", [s1, s_send(R1, P1), s_resolve("alice", "bob", R1, routes=BOB)], "the sender of an open delivery")
vec("C2-resolve-after-close", [s1, s_send(R1, P1), tick(NOW + 501), s_resolve("alice", "bob", R1, outcome="REFUSE", code="OFFER_NOT_VISIBLE")], "authority ends")
vec("C2-resolve-probe-indistinguishable", [s_resolve("alice", "provider", outcome="REFUSE", code="OFFER_NOT_VISIBLE")], "no offer: the same refusal")

# ---- abuse control
sc = Scenario()
s1, _ = sc.offer(OB)
burst = [s1] + [s_send(request("alice", "bob", f"burst {n}", text(f"ping {n}"))) for n in range(100)]
burst += [s_send(request("alice", "bob", "burst 100", text("ping 100")), outcome="REFUSE", code="RATE_LIMITED")]
vec("C2-rate-limit", burst, "100 deliveries per sender per 60 s")

# ---- cross-implementation signatures
vec("C2-sign-cross", [step("ch2.sign", {"signer": "channel alice", "typ": "lp02.endpoint-offer", "object": {k: v for k, v in OA.items() if k != "signature"}},
                           result={"signature": OA["signature"]}),
                      step("ch2.sign", {"signer": "channel alice", "typ": "lp02.delivery", "object": {k: v for k, v in R1.items() if k != "signature"}},
                           result={"signature": R1["signature"]})], "what one makes, the others verify")

if __name__ == "__main__":
    out = {"kind": "lp02-channel-vectors/2", "status": "EXPERIMENTAL · PRIVATE · NOT LP 0.1", "now": NOW, "count": len(VECTORS), "vectors": VECTORS}
    (HERE / "channel2-vectors.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"channel/2 vectors: {len(VECTORS)} vectors, {sum(len(v['steps']) for v in VECTORS)} steps")
