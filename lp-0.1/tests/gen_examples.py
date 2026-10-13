#!/usr/bin/env python3
"""Deterministic generator for the LP 0.1 example fixtures (valid / invalid / tampered).

All keys, secrets and identifiers are derived from public labels: they are TEST VECTORS, not
secrets. Ed25519 signatures are deterministic, so regenerating yields identical files.

Usage: python 03_Protokoll/tests/gen_examples.py --write
run_tests.py compares the files in 03_Protokoll/examples/ with build_fixtures().
"""

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lp_testlib as lp  # noqa: E402

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _mutated(base: dict, change) -> dict:
    obj = copy.deepcopy(base)
    change(obj)
    return obj


def build_fixtures() -> dict:
    provider = lp.example_private_key("provider key")
    client = lp.example_private_key("client thing key")
    provider_pub = lp.public_b64u(provider)
    client_pub = lp.public_b64u(client)
    grant_secret = lp.tv("grant secret")
    line_salt = lp.tv("line salt", 16)
    thing_id = lp.b64u(lp.tv("thing id", 16))
    grant_id = lp.b64u(lp.tv("grant id", 16))
    result_id = lp.b64u(lp.tv("result id", 16))
    challenge = lp.b64u(lp.tv("challenge", 16))

    thing = {
        "lp_version": "0.1",
        "thing_id": thing_id,
        "type": "repair.plumbing",
        "title": "Kitchen tap replacement - order 1042",
        "provider_pub": provider_pub,
        "created_at": "2026-09-28T09:00:00Z",
        "closed_at": None,
        "version": 1,
    }
    thing["signature"] = lp.sign(provider, thing, "thing")

    state1 = {
        "lp_version": "0.1",
        "thing_id": thing_id,
        "version": 1,
        "prev_state_hash": None,
        "status": "WAITING",
        "waiting_on": "client",
        "next_action": "Choose a visit time",
        "deadline": "2026-09-29T18:00:00Z",
        "actor": "provider",
        "result_id": None,
        "timestamp": "2026-09-28T09:00:00Z",
    }
    state1["signature"] = lp.sign(provider, state1, "state")

    grant = {
        "lp_version": "0.1",
        "grant_id": grant_id,
        "thing_id": thing_id,
        "issuer": provider_pub,
        "subject": "client",
        "aud": "https://provider.example",
        "purpose": "schedule-visit",
        "channels": ["voice", "video"],
        "issued_at": "2026-09-28T09:05:00Z",
        "redeem_by": "2026-09-28T09:20:00Z",
        "not_before": "2026-09-28T09:05:00Z",
        "exp": "2026-09-28T21:05:00Z",
        "line_max_seconds": 900,
        "max_uses": 1,
        "epoch": 0,
        "secret_commitment": lp.secret_commitment(grant_secret),
    }
    grant["signature"] = lp.sign(provider, grant, "grant")

    redemption = {
        "lp_version": "0.1",
        "grant_id": grant_id,
        "thing_id": thing_id,
        "client_thing_pub": client_pub,
        "challenge": challenge,
        "secret_proof": lp.secret_proof(grant_secret, grant_id, challenge, client_pub),
    }
    redemption["signature"] = lp.sign(client, redemption, "redemption")

    receipt = {
        "lp_version": "0.1",
        "grant_id": grant_id,
        "thing_id": thing_id,
        "client_kid": lp.key_id(client_pub),
        "bound_at": "2026-09-28T09:07:42Z",
        "uses_remaining": 1,
    }
    receipt["signature"] = lp.sign(provider, receipt, "redemption_receipt")

    result = {
        "lp_version": "0.1",
        "result_id": result_id,
        "thing_id": thing_id,
        "grant_id": grant_id,
        "line_seq": 1,
        "outcome": "agreed",
        "summary": "Visit agreed for Tue 29 Sep, 14:00-16:00. Replace the tap cartridge; "
                   "full tap replacement only if the cartridge fix fails.",
        "next_state": {
            "status": "WAITING",
            "waiting_on": "provider",
            "next_action": "Visit on 29 Sep, 14:00-16:00",
            "deadline": "2026-09-29T16:00:00Z",
        },
        "timestamp": "2026-09-28T10:12:00Z",
    }
    result["provider_sig"] = lp.sign(provider, result, "result")
    result["client_thing_sig"] = lp.sign(client, result, "result")

    state2 = {
        "lp_version": "0.1",
        "thing_id": thing_id,
        "version": 2,
        "prev_state_hash": lp.state_hash(state1),
        "status": "WAITING",
        "waiting_on": "provider",
        "next_action": "Visit on 29 Sep, 14:00-16:00",
        "deadline": "2026-09-29T16:00:00Z",
        "actor": "provider",
        "result_id": result_id,
        "timestamp": "2026-09-28T10:12:30Z",
    }
    state2["signature"] = lp.sign(provider, state2, "state")

    bucket = lp.unix("2026-09-28T10:00:00Z") // lp.RDV_BUCKET
    vectors = {
        "note": "TEST VECTORS derived from public labels. NOT SECRETS. MUST NOT be used outside tests.",
        "label_prefix": lp.TV_PREFIX,
        "labels": {
            "provider_key_seed": "provider key",
            "client_thing_key_seed": "client thing key",
            "grant_secret": "grant secret",
            "line_salt": "line salt",
        },
        "provider_kid": lp.key_id(provider_pub),
        "client_kid": lp.key_id(client_pub),
        "secret_commitment": grant["secret_commitment"],
        "delivery_link": f"https://provider.example/l/{grant_id}#{lp.b64u(grant_secret)}",
        "rendezvous": [
            {
                "direction": d,
                "bucket_start": lp.iso(b * lp.RDV_BUCKET),
                "bucket": b,
                "epoch": 0,
                "line_seq": 1,
                "addr": lp.rdv_addr(grant_secret, line_salt, d, thing_id, 0, 1, b),
            }
            for d in lp.DIRECTIONS
            for b in (bucket, bucket + 1)
        ],
        "k_signal_sha256": {
            d: lp.sha256_b64u(lp.signal_key(grant_secret, line_salt, d, thing_id, 0, 1))
            for d in lp.DIRECTIONS
        },
    }

    offer = {
        "lp_version": "0.1",
        "thing_id": thing_id,
        "line_seq": 1,
        "seq": 1,
        "from": "provider",
        "kind": "offer",
        "body": "v=0 (TEST VECTOR placeholder for an SDP offer)",
        "sent_at": "2026-09-28T10:00:05Z",
    }
    offer["signature"] = lp.sign(provider, offer, "signal")
    answer = {
        "lp_version": "0.1",
        "thing_id": thing_id,
        "line_seq": 1,
        "seq": 1,
        "from": "client",
        "kind": "answer",
        "body": "v=0 (TEST VECTOR placeholder for an SDP answer)",
        "sent_at": "2026-09-28T10:00:09Z",
    }
    answer["signature"] = lp.sign(client, answer, "signal")
    messages = {"p2c": offer, "c2p": answer}
    nonce_labels = {d: f"signal nonce {d} 1" for d in lp.DIRECTIONS}
    signal = {
        "note": "TEST VECTORS derived from public labels. NOT SECRETS. MUST NOT be used outside tests.",
        "label_prefix": lp.TV_PREFIX,
        "nonce_labels": nonce_labels,
        "bucket": bucket,
        "messages": messages,
        "envelopes": {
            d: lp.seal_envelope(lp.signal_key(grant_secret, line_salt, d, thing_id, 0, 1),
                                lp.rdv_addr(grant_secret, line_salt, d, thing_id, 0, 1, bucket),
                                lp.jcs(messages[d]), lp.tv(nonce_labels[d], lp.NONCE_BYTES))
            for d in lp.DIRECTIONS
        },
    }

    long_window = dict(grant, redeem_by="2026-09-28T09:25:00Z")
    long_window.pop("signature")
    long_window["signature"] = lp.sign(provider, long_window, "grant")

    fixtures = {
        "valid/thing.json": thing,
        "valid/state.1.json": state1,
        "valid/grant.json": grant,
        "valid/redemption.json": redemption,
        "valid/redemption_receipt.json": receipt,
        "valid/result.json": result,
        "valid/state.2.json": state2,
        "valid/vectors.json": vectors,
        "valid/signal.json": signal,
    }

    fixtures["invalid/thing.missing-provider_pub.json"] = _mutated(thing, lambda o: o.pop("provider_pub"))
    fixtures["invalid/thing.extra-field.json"] = _mutated(
        thing, lambda o: o.__setitem__("client_phone", "+000 0000 0000"))
    fixtures["invalid/state.ui-label-status.json"] = _mutated(state1, lambda o: o.update(status="LYNE"))
    fixtures["invalid/state.waiting-without-waiting_on.json"] = _mutated(
        state1, lambda o: o.update(waiting_on=None))
    fixtures["invalid/state.v1-with-prev-hash.json"] = _mutated(
        state1, lambda o: o.update(prev_state_hash=lp.state_hash(state1)))
    fixtures["invalid/state.closed-with-deadline.json"] = _mutated(
        state2, lambda o: o.update(status="CLOSED", waiting_on=None, next_action=None))
    fixtures["invalid/grant.channel-sms.json"] = _mutated(grant, lambda o: o.update(channels=["voice", "sms"]))
    fixtures["invalid/grant.max_uses-zero.json"] = _mutated(grant, lambda o: o.update(max_uses=0))
    fixtures["invalid/grant.raw-secret-field.json"] = _mutated(grant, lambda o: o.__setitem__("secret", "x"))
    fixtures["invalid/result.missing-client-sig.json"] = _mutated(result, lambda o: o.pop("client_thing_sig"))
    fixtures["invalid/result.summary-too-long.json"] = _mutated(result, lambda o: o.update(summary="x" * 281))

    fixtures["tampered/result.summary-altered.json"] = _mutated(
        result, lambda o: o.update(summary="Visit agreed for Tue 29 Sep, 14:00-16:00. "
                                           "Full tap replacement at the client's cost."))
    fixtures["tampered/grant.channels-widened.json"] = _mutated(
        grant, lambda o: o.update(channels=["voice", "video", "data"]))

    fixtures["semantic-invalid/grant.redeem-window-too-long.json"] = long_window
    return fixtures


def render(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def main():
    if "--write" not in sys.argv:
        print(__doc__)
        return 2
    for rel, obj in build_fixtures().items():
        path = EXAMPLES / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(obj), encoding="utf-8", newline="\n")
        print("wrote", path.relative_to(EXAMPLES.parent))
    return 0


if __name__ == "__main__":
    sys.exit(main())
