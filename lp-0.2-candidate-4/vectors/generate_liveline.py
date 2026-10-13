#!/usr/bin/env python3
"""Generates the conformance vectors of lp02.liveline/1 (SPEC.md) — deterministic, byte-stable.

PRIVATE · EXPERIMENTAL · NOT LP 0.1. Every expectation is written by hand from SPEC §4–§6 (no implementation computes
it). Ops: ll.make, ll.local, ll.frame, ll.session (SPEC §10).

Usage: python generate.py   (writes liveline-vectors.json beside this file)
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NOW = 1790000000
M = "lp02.liveline"
V = "lp02.liveline/1"


def d(id_, negotiated=True, ordered=True, protocol="", mr=None, mpl=None):
    return {"id": id_, "negotiated": negotiated, "ordered": ordered, "protocol": protocol, "maxRetransmits": mr, "maxPacketLifeTime": mpl}


C0, D1 = d(0), d(1)


def frame(control=C0, data=D1, **over):
    f = {"lyne": V, "t": "profile", "channels": {"lyne-control": control, "lyne-data": data}}
    f.update(over)
    return f


def txt(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


ACC = {"outcome": "ACCEPT", "result": {}}


def ref(code):
    return {"outcome": "REFUSE", "code": code}


vectors = []


def vec(id_, note, steps, grant_data=None):
    vectors.append({"id": id_, "module": M, "note": note, "context": {"now": NOW, "negotiated": True}, "steps": steps})


def step(op, inp, expect):
    return {"op": op, "input": inp, "expect": expect}


# ---- ll.make (SPEC §4)
vec("LL-make-control-and-data", "the frame of a compliant endpoint whose Grant includes data",
    [step("ll.make", {"grant_data": True}, {"outcome": "ACCEPT", "result": {"frame": frame()}})])
vec("LL-make-control-only", "control only: lyne-data is null",
    [step("ll.make", {"grant_data": False}, {"outcome": "ACCEPT", "result": {"frame": frame(data=None)}})])

# ---- ll.local (SPEC §3 rule 2 = §5 rules 5–9 on own descriptors)
LOCAL = [
    ("LL-local-ok-data", "both channels exactly as the profile", True, C0, D1, ACC),
    ("LL-local-ok-control-only", "control only, no data in the Grant", False, C0, None, ACC),
    ("LL-local-negotiated-false", "a runtime that created control in band", False, d(0, negotiated=False), None, ref("LINE_PROFILE_MISMATCH")),
    ("LL-local-control-id-1", "control on stream 1", False, d(1), None, ref("LINE_PROFILE_MISMATCH")),
    ("LL-local-unordered", "control unordered", False, d(0, ordered=False), None, ref("LINE_PROFILE_MISMATCH")),
    ("LL-local-max-retransmits", "control partially reliable (maxRetransmits 0)", False, d(0, mr=0), None, ref("LINE_PROFILE_MISMATCH")),
    ("LL-local-max-packet-lifetime", "data partially reliable (maxPacketLifeTime 500)", True, C0, d(1, mpl=500), ref("LINE_PROFILE_MISMATCH")),
    ("LL-local-protocol", "a non-empty protocol", False, d(0, protocol="lyne"), None, ref("LINE_PROFILE_MISMATCH")),
    ("LL-local-data-missing", "the Grant includes data but no data channel was created", True, C0, None, ref("LINE_PROFILE_MISMATCH")),
    ("LL-local-data-without-grant", "a data channel created without data in the Grant", False, C0, D1, ref("CHANNEL_NOT_GRANTED")),
    ("LL-local-no-control", "no control channel", False, None, None, ref("LINE_PROFILE_MISMATCH")),
]
for id_, note, gd, c, dd, exp in LOCAL:
    vec(id_, note, [step("ll.local", {"grant_data": gd, "channels": {"lyne-control": c, "lyne-data": dd}}, exp)])

# ---- ll.frame (SPEC §5)
FRAMES = [
    # accepted
    ("LL-frame-ok-data", "a compliant frame, data granted", True, txt(frame()), ACC),
    ("LL-frame-ok-control-only", "a compliant frame, control only", False, txt(frame(data=None)), ACC),
    ("LL-frame-member-order", "member order is free (JSON objects)", True, '{"channels":{"lyne-data":{"maxPacketLifeTime":null,"maxRetransmits":null,"protocol":"","ordered":true,"negotiated":true,"id":1},"lyne-control":{"id":0,"negotiated":true,"ordered":true,"protocol":"","maxRetransmits":null,"maxPacketLifeTime":null}},"t":"profile","lyne":"lp02.liveline/1"}', ACC),
    # rule 1
    ("LL-frame-too-large", "more than 1024 bytes", False, txt(frame(data=None)) + " " * 1100, ref("LINE_PROFILE_INVALID")),
    ("LL-frame-not-json", "not JSON", False, "{lyne: profile", ref("LINE_PROFILE_INVALID")),
    ("LL-frame-array", "JSON but not an object", False, "[1,2]", ref("LINE_PROFILE_INVALID")),
    ("LL-frame-duplicate-member", "a duplicate member (strict JSON)", False, '{"lyne":"lp02.liveline/1","lyne":"lp02.liveline/1","t":"profile","channels":{"lyne-control":' + txt(C0) + ',"lyne-data":null}}', ref("LINE_PROFILE_INVALID")),
    # rule 2
    ("LL-frame-lp01-object-first", "an LP 0.1 object where the frame must be", False, '{"kind":"bye","reason":"DONE"}', ref("LINE_PROFILE_INVALID")),
    ("LL-frame-lyne-number", "lyne is not a string", False, txt({**frame(data=None), "lyne": 1}), ref("LINE_PROFILE_INVALID")),
    ("LL-frame-version-2", "a future version of this module", False, txt(frame(data=None, lyne="lp02.liveline/2")), ref("MODULE_VERSION_UNSUPPORTED")),
    ("LL-frame-other-module", "a frame of another module on control", False, txt(frame(data=None, lyne="lp02.linecaps/1")), ref("LINE_PROFILE_INVALID")),
    ("LL-frame-version-0", "version 0 is not a version", False, txt(frame(data=None, lyne="lp02.liveline/0")), ref("LINE_PROFILE_INVALID")),
    # rule 3
    ("LL-frame-t-hello", "t is not profile", False, txt(frame(data=None, t="hello")), ref("LINE_PROFILE_INVALID")),
    ("LL-frame-extra-member", "an extra top-level member", False, txt({**frame(data=None), "x": 1}), ref("LINE_PROFILE_INVALID")),
    # rule 4
    ("LL-frame-channels-missing-data-key", "channels without the lyne-data member", False, txt({"lyne": V, "t": "profile", "channels": {"lyne-control": C0}}), ref("LINE_PROFILE_INVALID")),
    ("LL-frame-channels-extra", "channels with a third channel", False, txt({"lyne": V, "t": "profile", "channels": {"lyne-control": C0, "lyne-data": None, "rogue": C0}}), ref("LINE_PROFILE_INVALID")),
    # rule 5
    ("LL-frame-descriptor-extra", "a descriptor with an extra member", False, txt(frame(control={**C0, "label": "lyne-control"}, data=None)), ref("LINE_PROFILE_INVALID")),
    ("LL-frame-descriptor-string-id", "id as a string", False, txt(frame(control={**C0, "id": "0"}, data=None)), ref("LINE_PROFILE_INVALID")),
    ("LL-frame-descriptor-id-range", "id 65535 is out of range", False, txt(frame(control={**C0, "id": 65535}, data=None)), ref("LINE_PROFILE_INVALID")),
    ("LL-frame-descriptor-negative-retransmits", "maxRetransmits -1", False, txt(frame(control={**C0, "maxRetransmits": -1}, data=None)), ref("LINE_PROFILE_INVALID")),
    ("LL-frame-descriptor-bool-ordered-number", "ordered as 1", False, txt(frame(control={**C0, "ordered": 1}, data=None)), ref("LINE_PROFILE_INVALID")),
    ("LL-frame-descriptor-id-fraction", "id written as 0.0 (an integer has no fraction)", False, txt(frame(data=None)).replace('"id":0', '"id":0.0'), ref("LINE_PROFILE_INVALID")),
    ("LL-frame-descriptor-exponent", "maxRetransmits written as 1e0", False, txt(frame(control={**C0, "maxRetransmits": "@"}, data=None)).replace('"@"', "1e0"), ref("LINE_PROFILE_INVALID")),
    ("LL-frame-descriptor-negative-zero", "id written as -0 is the integer 0", False, txt(frame(data=None)).replace('"id":0', '"id":-0'), ACC),
    ("LL-frame-descriptor-long-protocol", "a protocol of 256 characters", False, txt(frame(control={**C0, "protocol": "p" * 256}, data=None)), ref("LINE_PROFILE_INVALID")),
    # rule 6
    ("LL-frame-no-control", "lyne-control null: no control channel", False, txt(frame(control=None, data=None)), ref("LINE_PROFILE_MISMATCH")),
    # rule 7
    ("LL-frame-data-without-grant", "a data channel the Grant does not include", False, txt(frame()), ref("CHANNEL_NOT_GRANTED")),
    ("LL-frame-data-without-grant-and-bad-control", "rule 7 before rule 8", False, txt(frame(control=d(0, ordered=False))), ref("CHANNEL_NOT_GRANTED")),
    # rule 8
    ("LL-frame-negotiated-false", "the peer created control in band", False, txt(frame(control=d(0, negotiated=False), data=None)), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-control-id-1", "control on stream 1", False, txt(frame(control=d(1), data=None)), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-control-id-7", "control on another stream", False, txt(frame(control=d(7), data=None)), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-control-unordered", "control unordered", False, txt(frame(control=d(0, ordered=False), data=None)), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-control-max-retransmits", "control with maxRetransmits 3", False, txt(frame(control=d(0, mr=3), data=None)), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-control-max-retransmits-0", "control with maxRetransmits 0 (unreliable)", False, txt(frame(control=d(0, mr=0), data=None)), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-control-max-packet-lifetime", "control with maxPacketLifeTime 1000", False, txt(frame(control=d(0, mpl=1000), data=None)), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-control-protocol", "control with a non-empty protocol", False, txt(frame(control=d(0, protocol="lyne-control"), data=None)), ref("LINE_PROFILE_MISMATCH")),
    # rule 9
    ("LL-frame-data-missing", "data granted but no data channel", True, txt(frame(data=None)), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-data-id-0", "data on stream 0", True, txt(frame(data=d(0))), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-swapped-ids", "control on 1 and data on 0", True, txt(frame(control=d(1), data=d(0))), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-duplicate-stream-id", "both channels on stream 0", True, txt(frame(control=d(0), data=d(0))), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-data-unordered", "data unordered", True, txt(frame(data=d(1, ordered=False))), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-data-max-retransmits", "data with maxRetransmits 5", True, txt(frame(data=d(1, mr=5))), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-data-max-packet-lifetime", "data with maxPacketLifeTime 250", True, txt(frame(data=d(1, mpl=250))), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-data-protocol", "data with a protocol", True, txt(frame(data=d(1, protocol="x"))), ref("LINE_PROFILE_MISMATCH")),
    ("LL-frame-data-negotiated-false", "data created in band", True, txt(frame(data=d(1, negotiated=False))), ref("LINE_PROFILE_MISMATCH")),
]
for id_, note, gd, text, exp in FRAMES:
    vec(id_, note, [step("ll.frame", {"grant_data": gd, "text": text}, exp)])


# ---- ll.session (SPEC §6)
def ev(e, **kw):
    return {"e": e, **kw}


OKC, OKD = txt(frame(data=None)), txt(frame())
LP01 = '{"kind":"result_proposal"}'


def sess(id_, note, gd, events, exp):
    vec(id_, note, [step("ll.session", {"grant_data": gd, "events": events}, exp)])


def state(s, held=0):
    return {"outcome": "ACCEPT", "result": {"state": s, "held_data": held}}


sess("LL-session-verified", "control opens, the peer's frame verifies", False, [ev("ice_connected"), ev("control_open"), ev("message", channel="lyne-control", text=OKC)], state("verified"))
sess("LL-session-verified-then-lp01", "after verification LP 0.1 objects flow", False, [ev("control_open"), ev("message", channel="lyne-control", text=OKC), ev("message", channel="lyne-control", text=LP01)], state("verified"))
sess("LL-session-waiting", "control open, no frame yet, inside the timeout", False, [ev("control_open"), ev("elapsed", ms=9999)], state("waiting"))
sess("LL-session-profile-timeout", "no frame within 10 s after control opened (peer's control on another stream, or none)", False, [ev("control_open"), ev("elapsed", ms=10000)], ref("LINE_PROFILE_MISMATCH"))
sess("LL-session-setup-timeout", "ICE connected, control never opens within 30 s (missing control channel)", False, [ev("ice_connected"), ev("elapsed", ms=29999), ev("elapsed", ms=1)], ref("LINE_PROFILE_MISMATCH"))
sess("LL-session-setup-ok-before-timeout", "control opens before the setup timeout", False, [ev("ice_connected"), ev("elapsed", ms=29000), ev("control_open"), ev("elapsed", ms=5000), ev("message", channel="lyne-control", text=OKC)], state("verified"))
sess("LL-session-lp01-first", "an LP 0.1 object before the frame", False, [ev("control_open"), ev("message", channel="lyne-control", text=LP01)], ref("LINE_PROFILE_INVALID"))
sess("LL-session-second-frame", "a second frame after verification", False, [ev("control_open"), ev("message", channel="lyne-control", text=OKC), ev("message", channel="lyne-control", text=OKC)], ref("LINE_PROFILE_INVALID"))
sess("LL-session-dcep-control", "the peer opened lyne-control in band (negotiated=false)", False, [ev("ice_connected"), ev("datachannel", label="lyne-control")], ref("LINE_PROFILE_MISMATCH"))
sess("LL-session-dcep-data", "the peer opened lyne-data in band", True, [ev("control_open"), ev("datachannel", label="lyne-data")], ref("LINE_PROFILE_MISMATCH"))
sess("LL-session-dcep-rogue", "an in-band channel with another label", False, [ev("control_open"), ev("message", channel="lyne-control", text=OKC), ev("datachannel", label="rogue")], ref("CHANNEL_NOT_GRANTED"))
sess("LL-session-bad-frame", "the frame fails §5", True, [ev("control_open"), ev("message", channel="lyne-control", text=txt(frame(data=d(1, mr=2))))], ref("LINE_PROFILE_MISMATCH"))
sess("LL-session-data-without-authority", "the peer's frame shows data, the Grant has none", False, [ev("control_open"), ev("message", channel="lyne-control", text=OKD)], ref("CHANNEL_NOT_GRANTED"))
sess("LL-session-data-held", "data before verification is held, then delivered", True, [ev("control_open"), ev("message", channel="lyne-data", text="a"), ev("message", channel="lyne-data", text="b")], state("waiting", 2))
sess("LL-session-data-delivered", "held data is delivered on verification", True, [ev("control_open"), ev("message", channel="lyne-data", text="a"), ev("message", channel="lyne-control", text=OKD), ev("message", channel="lyne-data", text="b")], state("verified"))
sess("LL-session-held-overflow", "a 65th held data message", True, [ev("control_open")] + [ev("message", channel="lyne-data", text=str(i)) for i in range(65)], ref("LINE_PROFILE_INVALID"))
sess("LL-session-held-64", "64 held data messages are allowed", True, [ev("control_open")] + [ev("message", channel="lyne-data", text=str(i)) for i in range(64)], state("waiting", 64))
sess("LL-session-after-failure", "events after a failure are not processed", False, [ev("control_open"), ev("datachannel", label="lyne-control"), ev("message", channel="lyne-control", text=OKC)], ref("LINE_PROFILE_MISMATCH"))
sess("LL-session-fresh-line", "a new line_seq is a new session: verification starts again (no state carried)", False, [ev("control_open"), ev("elapsed", ms=3000)], state("waiting"))

out = {"kind": "lp02-liveline-vectors/1", "status": "EXPERIMENTAL · PRIVATE · NOT LP 0.1", "now": NOW, "count": len(vectors), "vectors": vectors}
(HERE / "liveline-vectors.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
print(f"liveline vectors: {len(vectors)} vectors, {sum(len(v['steps']) for v in vectors)} steps")
