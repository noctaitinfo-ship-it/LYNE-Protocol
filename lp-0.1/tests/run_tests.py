#!/usr/bin/env python3
"""Gate 1 test suite for the LYNE Protocol LP 0.1 (draft 3).

Checks: the four JSON Schemas (with the official `jsonschema` validator, Draft 2020-12), the example
fixtures (valid / invalid / tampered / semantic-invalid), Ed25519 signatures and HKDF/HMAC
derivations, AES-256-GCM signaling envelopes with directional keys and nonce rules, lifecycle
consistency, fixture reproducibility, the Gate 1 contract of draft 3 (crypto profile, error code,
memory-only capability secrets, Appendix B), the structure of PROTOCOL.md, Threat_model.md and
CHANGELOG.md, the A2R/PAP full-read record, the secret scanner and the CI configuration.

Setup:  python -m pip install -r requirements-dev.txt
Usage:  python 03_Protokoll/tests/run_tests.py        Exit code: 0 = PASS, 1 = FAIL
"""

import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROTO = HERE.parent
ROOT = PROTO.parent
sys.path.insert(0, str(HERE))

try:
    from cryptography.exceptions import InvalidTag
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError
    import lp_testlib as lp
    import gen_examples
except ImportError as exc:
    print(f"[FAIL] missing dependency ({exc}); run: python -m pip install -r requirements-dev.txt")
    sys.exit(1)

SCHEMA_NAMES = ("thing", "state", "grant", "result")
FIXTURE_SETS = ("valid", "invalid", "tampered", "semantic-invalid")

INVALID_EXPECTATIONS = {
    "thing.missing-provider_pub.json": ("required", "provider_pub"),
    "thing.extra-field.json": ("additionalProperties", "client_phone"),
    "state.ui-label-status.json": ("enum", "status"),
    "state.waiting-without-waiting_on.json": ("enum", "waiting_on"),
    "state.v1-with-prev-hash.json": ("const", "prev_state_hash"),
    "state.closed-with-deadline.json": ("const", "deadline"),
    "grant.channel-sms.json": ("enum", "channels"),
    "grant.max_uses-zero.json": ("minimum", "max_uses"),
    "grant.raw-secret-field.json": ("additionalProperties", "secret"),
    "result.missing-client-sig.json": ("required", "client_thing_sig"),
    "result.summary-too-long.json": ("maxLength", "summary"),
}
SEMANTIC_EXPECTATIONS = {
    "grant.redeem-window-too-long.json": "REDEEM_WINDOW_MAX",
}

PROTOCOL_SECTIONS = [
    "Motivation", "Terminology", "Thing", "State", "Grant", "Redemption and Thing-bound Identity",
    "Rendezvous", "Live Line", "Result", "Revocation and Expiry", "Security / Threat Model",
    "Non-goals", "Prior Art", "Endpoint Neutrality", "Protocol Lifecycle",
]
MANDATORY_THREATS = [
    "Grant theft", "First-redemption race", "Replay", "Copied QR/link", "MITM", "Clock skew",
    "Device loss", "Provider compromise", "Malicious provider", "Malicious client",
    "Agent overreach", "Rendezvous enumeration", "Metadata correlation", "TURN leakage", "DoS",
    "Cross-tenant access", "Result repudiation", "Key substitution",
]
ADDITIONAL_THREATS = ["Content retention by a participant or endpoint",
                      "Canonicalization and signature confusion", "Fragment leakage", "Signaling nonce reuse"]
THREAT_LABELS = ("- **Threat:**", "- **Impact:**", "- **Mitigation:**", "- **Residual risk:**")
PERSISTENCE_TERM = re.compile(r"^(persistent( \(.+\))?|retained until .+|transient( \(.+\))?|not held)$")

ERROR_CODE = "GRANT_REDEMPTION_EXPIRED"
# Superseded names, assembled at run time so that this file does not contain them either.
OLD_ERROR_CODE = "_".join(("REDEEM", "WINDOW", "CLOSED"))
OLD_KEY_NAME = re.compile(r"\bK_" + "sig" + r"\b")
OLD_KEY_LABEL = "LYNE/0.1/" + "sig|"
OLD_KEY_FUNCTION = "signaling" + "_key"

CRYPTO_PROFILE = ("Ed25519 / EdDSA", "SHA-256", "HMAC-SHA256", "HKDF-SHA256", "AES-256-GCM", "JCS",
                  "Detached JWS", "HTTP Message Signatures", "WebRTC", "ICE", "STUN", "TURN", "DTLS-SRTP",
                  "SCTP/DTLS data channels")
MASTER_PROFILE = ("Ed25519/EdDSA", "SHA-256", "HMAC-SHA256", "HKDF-SHA256", "AES-256-GCM", "JCS",
                  "detached JWS", "HTTP Message Signatures", "WebRTC", "ICE", "STUN", "TURN", "DTLS-SRTP",
                  "SCTP/DTLS")
FORBIDDEN_STORAGE = ("`localStorage`", "`sessionStorage`", "IndexedDB", "the Cache API", "service-worker caches",
                     "cookies", "logs", "analytics", "crash telemetry", "the URL query or path")
APPENDIX_B_EXPECTED = {
    "B.1": "HUMAN GATE — the only Gate 1 HUMAN GATE after technical PASS",
    "B.2": "RESOLVED IN 1B/004R",
    "B.3": "RESOLVED",
    "B.4": "NON-GOAL v0.1 — a compromise freezes/revokes the affected Thing relationship; a new Provider key "
           "requires a newly established trusted relationship / new Thing; no transparent rotation",
    "B.5": "NON-GOAL v0.1",
    "B.6": "HUMAN GATE BEFORE PUBLIC/COMMERCIAL RELEASE — not a private R&D / Gate 1 blocker; do not claim FTO",
    "B.7": "RESOLVED FOR LP 0.1 PRIVATE LOCK",
    "B.8": "DEFERRED ETAPP 2",
    "B.9": "DEFERRED ETAPP 2",
    "B.10": "NON-GOAL v0.1",
    "B.11": "HUMAN GATE BEFORE PUBLIC/COMMERCIAL CLAIMS — not a Gate 1 blocker",
    "B.12": "RESOLVED", "B.13": "RESOLVED", "B.14": "RESOLVED", "B.15": "RESOLVED", "B.16": "RESOLVED",
}
PRIVATE_LOCK_LINE = ("PRIVATE LP 0.1 LOCK: done on 2026-09-27 — B.1 decided by the owner rule; draft 3 is the private locked baseline "
                     "for P0.")
# SHA-256 of the normative text (sections 1-15, Appendix A, Appendix C) of the private LP 0.1 lock (382d3ef).
LOCKED_NORMATIVE_SHA256 = "b591c2f4a73d8beb42800d5c068602740fffdfaeac94ffad8e64e384776dd61a"
PUBLIC_RELEASE_LINE = "PUBLIC/COMMERCIAL RELEASE: still blocked by B.6, B.11, Q-PUBLIC and later release gates."
OTSUSED_ROW = ("- 2026-09-27 · LP 0.1 Gate 1 technical closure: canonical crypto profile locked; redemption error "
               "code normalized; directional AES-GCM nonce/replay rules tested; browser capability secrets are "
               "memory-only; Appendix B reclassified so patent/eIDAS gates block public/commercial release, not "
               "private R&D; remote CI includes secret scan. · C")
FULL_READ = ROOT / "02_Uuring" / "Prior_art" / "FULL_READ_2026-09-27.md"
SECRET_SCAN = ROOT / "scripts" / "secret-scan.py"


class Report:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            print(f"[PASS] {name}")
        else:
            self.failed += 1
            print(f"[FAIL] {name}" + (f" -- {detail}" if detail else ""))
        return ok


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def schema_for(file_name):
    prefix = file_name.split(".", 1)[0]
    return prefix if prefix in SCHEMA_NAMES else None


def schema_errors(instance, schema):
    """(path, keyword, message) for every error reported by the official Draft 2020-12 validator."""
    return [("$." + ".".join(str(p) for p in e.absolute_path), e.validator, e.message)
            for e in Draft202012Validator(schema).iter_errors(instance)]


def flat(text):
    return re.sub(r"\s+", " ", text)


def sections(markdown):
    parts = re.split(r"^## (\d+)\. (.+)$", markdown, flags=re.M)
    return [(int(parts[i]), parts[i + 1].strip(), parts[i + 2]) for i in range(1, len(parts) - 2, 3)]


def markdown_table(text, first_header):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("|") and cells and cells[0] == first_header:
            rows = []
            for row in lines[i + 2:]:
                if not row.startswith("|"):
                    break
                rows.append([c.strip() for c in row.strip().strip("|").split("|")])
            return rows
    return []


def numbered_rule(section_text, number):
    """Text of rule `number` in a numbered list, up to the next rule or heading."""
    match = re.search(rf"^{number}\. (.*?)(?=^\d+\. |^#|\Z)", section_text, flags=re.M | re.S)
    return flat(match.group(1)) if match else ""


def repo_text_files():
    """Tracked files plus untracked files that git does not ignore; binary files are skipped."""
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                         capture_output=True, check=True).stdout
    for name in sorted({n for n in out.decode("utf-8").split("\0") if n}):
        path = ROOT / name
        if path.is_file():
            data = path.read_bytes()
            if b"\0" not in data[:8192]:
                yield name, data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------- schemas and fixtures

def check_schemas(report):
    schemas = {}
    for name in SCHEMA_NAMES:
        path = PROTO / "Schemas" / f"{name}.schema.json"
        try:
            schema = load(path)
        except (OSError, ValueError) as exc:
            report.check(f"schema parses: {path.name}", False, str(exc))
            continue
        report.check(f"schema parses: {path.name}", True)
        try:
            Draft202012Validator.check_schema(schema)
            report.check(f"schema is valid against the Draft 2020-12 metaschema (jsonschema): {path.name}", True)
        except SchemaError as exc:
            report.check(f"schema is valid against the Draft 2020-12 metaschema (jsonschema): {path.name}",
                         False, exc.message)
        meta_ok = (schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
                   and isinstance(schema.get("$id"), str) and schema["$id"].endswith(f"/{name}.schema.json")
                   and isinstance(schema.get("title"), str) and schema.get("type") == "object"
                   and isinstance(schema.get("required"), list) and schema["required"]
                   and schema.get("additionalProperties") is False)
        report.check(f"schema meta ($schema 2020-12, $id, title, type, required, additionalProperties false): {path.name}",
                     meta_ok)
        schemas[name] = schema
    report.check("State wire status enum is exactly OPEN, WAITING, CLOSED (no UI label, no phases)",
                 set(schemas.get("state", {}).get("properties", {}).get("status", {}).get("enum", []))
                 == {"OPEN", "WAITING", "CLOSED"})
    grant = schemas.get("grant", {})
    report.check("Grant object cannot carry a raw secret (additionalProperties false, no 'secret' member)",
                 "secret" not in grant.get("properties", {}) and grant.get("additionalProperties") is False)
    report.check("Grant schema requires redeem_by (bearer window)", "redeem_by" in grant.get("required", []))
    return schemas


def check_fixtures(report, schemas):
    examples = PROTO / "examples"
    for sub in FIXTURE_SETS:
        for path in sorted((examples / sub).glob("*.json")):
            name = schema_for(path.name)
            label = f"{sub}/{path.name}"
            if name is None:
                continue
            if name not in schemas:
                report.check(f"schema available for {label}", False)
                continue
            errors = schema_errors(load(path), schemas[name])
            if sub == "valid":
                report.check(f"valid accepted: {label}", not errors, "; ".join(map(str, errors)))
            elif sub in ("tampered", "semantic-invalid"):
                report.check(f"{sub} is schema-valid: {label}", not errors, "; ".join(map(str, errors)))
            else:
                expected = INVALID_EXPECTATIONS.get(path.name)
                if expected is None:
                    report.check(f"invalid has an expectation: {label}", False)
                    continue
                keyword, where = expected
                hit = any(k == keyword and where in f"{p} {m}" for p, k, m in errors)
                report.check(f"invalid rejected for the expected rule ({keyword} / {where}): {label}",
                             bool(errors) and hit, "; ".join(map(str, errors)) or "accepted")
    missing = set(INVALID_EXPECTATIONS) - {p.name for p in (examples / "invalid").glob("*.json")}
    report.check("every expected invalid fixture exists", not missing, ", ".join(sorted(missing)))
    for file_name, marker in SEMANTIC_EXPECTATIONS.items():
        path = examples / "semantic-invalid" / file_name
        if not path.is_file():
            report.check(f"semantic-invalid fixture exists: {file_name}", False)
            continue
        grant = load(path)
        ok_sig = lp.verify(grant["signature"], grant["issuer"], grant, "grant")[0]
        errors = lp.grant_time_errors(grant)
        report.check(f"semantic-invalid rejected by the time rules ({marker}) despite a valid signature: {file_name}",
                     ok_sig and any(marker in e for e in errors), "; ".join(errors) or "accepted")


def check_crypto_and_lifecycle(report):
    valid = PROTO / "examples" / "valid"
    thing = load(valid / "thing.json")
    state1 = load(valid / "state.1.json")
    state2 = load(valid / "state.2.json")
    grant = load(valid / "grant.json")
    redemption = load(valid / "redemption.json")
    receipt = load(valid / "redemption_receipt.json")
    result = load(valid / "result.json")
    vectors = load(valid / "vectors.json")
    provider_pub = thing["provider_pub"]
    client_pub = redemption["client_thing_pub"]

    def sig(label, jws, pub, obj, kind):
        ok, why = lp.verify(jws, pub, obj, kind)
        report.check(f"signature verifies: {label}", ok, why)

    sig("thing.signature (provider)", thing["signature"], provider_pub, thing, "thing")
    sig("state.1.signature (provider)", state1["signature"], provider_pub, state1, "state")
    sig("grant.signature (provider)", grant["signature"], grant["issuer"], grant, "grant")
    sig("redemption.signature (Thing-key)", redemption["signature"], client_pub, redemption, "redemption")
    sig("redemption_receipt.signature (provider)", receipt["signature"], provider_pub, receipt,
        "redemption_receipt")
    sig("result.provider_sig (provider)", result["provider_sig"], provider_pub, result, "result")
    sig("result.client_thing_sig (Thing-key)", result["client_thing_sig"], client_pub, result, "result")
    sig("state.2.signature (provider)", state2["signature"], provider_pub, state2, "state")

    tampered = PROTO / "examples" / "tampered"
    t_result = load(tampered / "result.summary-altered.json")
    report.check("tampered Result fails both signatures",
                 not lp.verify(t_result["provider_sig"], provider_pub, t_result, "result")[0]
                 and not lp.verify(t_result["client_thing_sig"], client_pub, t_result, "result")[0])
    t_grant = load(tampered / "grant.channels-widened.json")
    report.check("tampered Grant (channels widened after signing) fails its signature",
                 not lp.verify(t_grant["signature"], t_grant["issuer"], t_grant, "grant")[0])
    report.check("signature bound to the expected key: Result provider_sig rejected under the Thing-key",
                 not lp.verify(result["provider_sig"], client_pub, result, "result")[0])

    grant_secret = lp.tv(vectors["labels"]["grant_secret"])
    line_salt = lp.tv(vectors["labels"]["line_salt"], 16)
    thing_id = thing["thing_id"]
    report.check("same thing_id across Thing, States, Grant, Redemption, Receipt, Result",
                 len({thing_id, state1["thing_id"], state2["thing_id"], grant["thing_id"],
                      redemption["thing_id"], receipt["thing_id"], result["thing_id"]}) == 1)
    report.check("Grant issuer equals Thing provider_pub", grant["issuer"] == provider_pub)
    report.check("secret_commitment = SHA-256(S)", grant["secret_commitment"] == lp.secret_commitment(grant_secret)
                 and vectors["secret_commitment"] == grant["secret_commitment"])
    time_errors = lp.grant_time_errors(grant)
    report.check("Grant time rules hold (bearer window <= 15 min, redeem_by <= exp, lifetime, line_max_seconds)",
                 not time_errors, "; ".join(time_errors))
    bound = lp.unix(receipt["bound_at"])
    report.check("Redemption happened inside the bearer phase [issued_at, redeem_by)",
                 lp.unix(grant["issued_at"]) <= bound < lp.unix(grant["redeem_by"]))
    report.check("Redemption secret_proof = HMAC(HKDF(S), JCS{challenge, client_thing_pub, grant_id})",
                 redemption["secret_proof"] == lp.secret_proof(grant_secret, grant["grant_id"],
                                                                redemption["challenge"], client_pub))
    report.check("Redemption and Receipt reference the Grant; client_kid = kid(client_thing_pub)",
                 redemption["grant_id"] == receipt["grant_id"] == grant["grant_id"]
                 and receipt["client_kid"] == lp.key_id(client_pub) == vectors["client_kid"]
                 and receipt["uses_remaining"] == grant["max_uses"])
    report.check("State 1: version 1, no predecessor, provider actor, not anchored",
                 state1["version"] == 1 and state1["prev_state_hash"] is None
                 and state1["actor"] == "provider" and state1["result_id"] is None)
    report.check("State 2 extends State 1 (version + 1, prev_state_hash = SHA-256(JCS(State 1)))",
                 state2["version"] == 2 and state2["prev_state_hash"] == lp.state_hash(state1))
    report.check("Result references the Grant and a line_seq within max_uses",
                 result["grant_id"] == grant["grant_id"] and 1 <= result["line_seq"] <= grant["max_uses"])
    t_nb, t_exp = lp.unix(grant["not_before"]), lp.unix(grant["exp"])
    report.check("Result timestamp inside [not_before, exp + RESULT_WINDOW]",
                 t_nb <= lp.unix(result["timestamp"]) <= t_exp + lp.RESULT_WINDOW)
    anchored = {k: state2[k] for k in ("status", "waiting_on", "next_action", "deadline")}
    report.check("State 2 is anchored by the Result (result_id, fields = next_state, provider actor, not earlier)",
                 state2["result_id"] == result["result_id"] and anchored == result["next_state"]
                 and state2["actor"] == "provider"
                 and lp.unix(state2["timestamp"]) >= lp.unix(result["timestamp"]))
    link_ok = vectors["delivery_link"] == f"https://provider.example/l/{grant['grant_id']}#{lp.b64u(grant_secret)}"
    report.check("delivery link = https://<aud host>/l/<grant_id>#<b64u(S)>",
                 link_ok and grant["aud"] == "https://provider.example")

    rdv = vectors["rendezvous"]
    rdv_ok = all(v["addr"] == lp.rdv_addr(grant_secret, line_salt, v["direction"], thing_id, v["epoch"],
                                          v["line_seq"], v["bucket"])
                 and lp.unix(v["bucket_start"]) == v["bucket"] * lp.RDV_BUCKET for v in rdv)
    report.check("rendezvous addresses match HKDF(S, line_salt, dir|thing_id|epoch|line_seq|bucket)", rdv_ok)
    report.check("vectors cover both directions (p2c, c2p)", {v["direction"] for v in rdv} == set(lp.DIRECTIONS))
    report.check("all rendezvous addresses are distinct (per direction and per bucket)",
                 len({v["addr"] for v in rdv}) == len(rdv))
    wrong_salt = lp.rdv_addr(grant_secret, b"\x00" * 16, "p2c", thing_id, 0, 1, rdv[0]["bucket"])
    report.check("a party holding only the link (no line_salt) derives a different address",
                 wrong_salt not in {v["addr"] for v in rdv})


def _receive(receiver, addr, envelope):
    """'accepted' or the receiver's rejection reason."""
    try:
        receiver.receive(addr, envelope)
        return "accepted"
    except lp.EnvelopeRejected as exc:
        return str(exc)


def _decrypt_fails(key, envelope, addr):
    try:
        lp.open_envelope(key, envelope, addr)
        return False
    except InvalidTag:
        return True


def check_signaling(report):
    """AES-256-GCM envelopes with directional keys and nonce rules (PROTOCOL.md sections 7.2 and 7.3)."""
    valid = PROTO / "examples" / "valid"
    vectors = load(valid / "vectors.json")
    signal = load(valid / "signal.json")
    thing = load(valid / "thing.json")
    provider_pub = thing["provider_pub"]
    client_pub = load(valid / "redemption.json")["client_thing_pub"]
    grant_secret = lp.tv(vectors["labels"]["grant_secret"])
    line_salt = lp.tv(vectors["labels"]["line_salt"], 16)
    thing_id = thing["thing_id"]
    bucket = signal["bucket"]
    dirs = lp.DIRECTIONS
    keys = {d: lp.signal_key(grant_secret, line_salt, d, thing_id, 0, 1) for d in dirs}
    addrs = {d: lp.rdv_addr(grant_secret, line_salt, d, thing_id, 0, 1, bucket) for d in dirs}
    later = {d: lp.rdv_addr(grant_secret, line_salt, d, thing_id, 0, 1, bucket + 1) for d in dirs}
    envelopes, messages = signal["envelopes"], signal["messages"]

    report.check('K_signal vectors match HKDF(S, line_salt, "LYNE/0.1/signal|" dir|thing_id|epoch|line_seq)',
                 all(vectors["k_signal_sha256"][d] == lp.sha256_b64u(keys[d]) for d in dirs))
    report.check("direction separation: K_signal_p2c differs from K_signal_c2p; both are 256-bit AES keys",
                 keys["p2c"] != keys["c2p"] and all(len(k) == 32 for k in keys.values()))
    report.check("fixture envelopes sit at addr(dir, bucket) and carry 96-bit test-vector nonces",
                 all(envelopes[d]["addr"] == addrs[d]
                     and lp.b64u_decode(envelopes[d]["n"]) == lp.tv(signal["nonce_labels"][d], lp.NONCE_BYTES)
                     for d in dirs))

    # 1-2: encrypt/decrypt per direction (fixture and a fresh random nonce)
    for d in dirs:
        rx = lp.SignalReceiver(d, keys[d])
        try:
            fixture_ok = json.loads(rx.receive(addrs[d], envelopes[d])) == messages[d]
        except lp.EnvelopeRejected as exc:
            fixture_ok = False
            print(f"       {d}: {exc}")
        plaintext = lp.jcs(messages[d])
        fresh = lp.SignalSender(d, keys[d]).seal(addrs[d], plaintext)
        round_trip = (len(lp.b64u_decode(fresh["n"])) == lp.NONCE_BYTES
                      and lp.SignalReceiver(d, keys[d]).receive(addrs[d], fresh) == plaintext)
        report.check(f"AES-GCM {d}: encrypt/decrypt with K_signal_{d} passes (fixture and fresh random 96-bit nonce)",
                     fixture_ok and round_trip)
        role = lp.SENDER_ROLE[d]
        errors = lp.signal_message_errors(messages[d], d, provider_pub, client_pub, 0, lp.unix(messages[d]["sent_at"]))
        report.check(f"signal message {d}: from = {role}, signed by the {role} key, seq and sent_at accepted",
                     not errors, "; ".join(errors))
    report.check("a provider signal message arriving on the c2p direction is rejected (from must be client)",
                 bool(lp.signal_message_errors(messages["p2c"], "c2p", provider_pub, client_pub, 0,
                                               lp.unix(messages["p2c"]["sent_at"]))))

    # 3-4: wrong-direction keys
    report.check("wrong direction: c2p ciphertext does not decrypt with K_signal_p2c",
                 _decrypt_fails(keys["p2c"], envelopes["c2p"], addrs["c2p"]))
    report.check("wrong direction: p2c ciphertext does not decrypt with K_signal_c2p",
                 _decrypt_fails(keys["c2p"], envelopes["p2c"], addrs["p2c"]))
    reflected = dict(envelopes["p2c"], addr=addrs["c2p"])
    report.check("reflected envelope: a p2c envelope reposted at the c2p address is rejected by the c2p receiver",
                 _receive(lp.SignalReceiver("c2p", keys["c2p"]), addrs["c2p"], reflected) == "authentication failed")

    # 5: duplicate nonce under the same directional key
    rx = lp.SignalReceiver("p2c", keys["p2c"])
    first = _receive(rx, addrs["p2c"], envelopes["p2c"])
    again = _receive(rx, addrs["p2c"], envelopes["p2c"])
    reuse = lp.seal_envelope(keys["p2c"], addrs["p2c"], b"another plaintext", lp.b64u_decode(envelopes["p2c"]["n"]))
    reused = _receive(rx, addrs["p2c"], reuse)
    report.check("duplicate nonce under K_signal_p2c is rejected (replayed envelope and nonce-reusing envelope)",
                 first == "accepted" and again.startswith("duplicate nonce") and reused.startswith("duplicate nonce"),
                 f"{first} / {again} / {reused}")
    sender = lp.SignalSender("c2p", keys["c2p"])
    guard_nonce = lp.tv("sender nonce guard", lp.NONCE_BYTES)
    sender.seal(addrs["c2p"], b"first", guard_nonce)
    try:
        sender.seal(addrs["c2p"], b"second", guard_nonce)
        guarded = False
    except lp.NonceReuse:
        guarded = True
    report.check("a sender refuses to reuse a nonce under the same directional key", guarded)

    # 6: the same nonce under the opposite directional key
    shared = lp.tv("shared nonce across directions", lp.NONCE_BYTES)
    env_p = lp.SignalSender("p2c", keys["p2c"]).seal(addrs["p2c"], b"offer", shared)
    env_c = lp.SignalSender("c2p", keys["c2p"]).seal(addrs["c2p"], b"answer", shared)
    report.check("the same nonce under the opposite directional key is not a violation (separate nonce spaces)",
                 env_p["n"] == env_c["n"]
                 and _receive(lp.SignalReceiver("p2c", keys["p2c"]), addrs["p2c"], env_p) == "accepted"
                 and _receive(lp.SignalReceiver("c2p", keys["c2p"]), addrs["c2p"], env_c) == "accepted")

    # 7-8: tampering
    raw = bytearray(lp.b64u_decode(envelopes["c2p"]["c"]))
    raw[0] ^= 0x01
    modified = dict(envelopes["c2p"], c=lp.b64u(bytes(raw)))
    report.check("tamper: a modified ciphertext fails authentication",
                 _receive(lp.SignalReceiver("c2p", keys["c2p"]), addrs["c2p"], modified) == "authentication failed")
    moved = dict(envelopes["c2p"], addr=later["c2p"])
    report.check("tamper: a modified address (AAD) fails authentication",
                 _receive(lp.SignalReceiver("c2p", keys["c2p"]), later["c2p"], moved) == "authentication failed"
                 and _decrypt_fails(keys["c2p"], envelopes["c2p"], later["c2p"]))

    # replay-set bookkeeping
    rx = lp.SignalReceiver("c2p", keys["c2p"])
    forged_first = _receive(rx, addrs["c2p"], modified)
    genuine_after = _receive(rx, addrs["c2p"], envelopes["c2p"])
    report.check("a forged envelope does not poison the nonce-replay set (nonce recorded only after authentication)",
                 forged_first == "authentication failed" and genuine_after == "accepted")
    short = dict(envelopes["c2p"], n=lp.b64u(lp.b64u_decode(envelopes["c2p"]["n"])[:8]))
    report.check("an envelope whose nonce is not exactly 96 bits is rejected",
                 _receive(lp.SignalReceiver("c2p", keys["c2p"]), addrs["c2p"], short).startswith("nonce is not"))
    size_before = rx.replay_set_size
    rx.end_line()
    report.check("the nonce-replay set is transient: it is emptied when the Line ends",
                 size_before == 1 and rx.replay_set_size == 0)


def check_reproducible(report):
    examples = PROTO / "examples"
    expected = gen_examples.build_fixtures()
    mismatched = [rel for rel, obj in expected.items()
                  if not (examples / rel).is_file() or load(examples / rel) != obj]
    report.check("fixtures equal the deterministic generator output", not mismatched, ", ".join(mismatched))
    present = {str(p.relative_to(examples)).replace("\\", "/")
               for sub in FIXTURE_SETS for p in (examples / sub).glob("*")}
    stale = sorted(present - set(expected))
    report.check("no stray files in the fixture directories", not stale, ", ".join(stale))


# ---------------------------------------------------------------- documents

def check_protocol(report):
    text = (PROTO / "PROTOCOL.md").read_text(encoding="utf-8")
    found = sections(text)
    titles = [(n, t) for n, t, _ in found]
    report.check("PROTOCOL.md has sections 1-15 in order with the required titles",
                 titles == list(enumerate(PROTOCOL_SECTIONS, start=1)), str(titles))
    body = {t: s for _, t, s in found}
    marker = re.findall(r"\b(TODO|TBD|FIXME|XXX)\b", text)
    report.check("no TODO/TBD/FIXME/XXX markers", not marker, ", ".join(marker))
    for word in ("MUST", "MUST NOT", "SHOULD", "MAY"):
        report.check(f"normative keyword present: {word}", re.search(rf"\b{word}\b", text) is not None)
    core = ("Thing", "State", "Grant", "Redemption and Thing-bound Identity", "Rendezvous",
            "Live Line", "Result", "Revocation and Expiry", "Protocol Lifecycle")
    empty = [t for t in core if len(body.get(t, "").strip()) < 400]
    report.check("every core lifecycle section has normative content", not empty, ", ".join(empty))
    human_only = re.findall(r"(?i)\bMUST\s+be\s+(?:a\s+)?human\b|human-only|\bonly\s+(?:a\s+)?humans?\b", text)
    report.check("no human-only endpoint requirement", not human_only, ", ".join(human_only))
    neutrality = flat(body.get("Endpoint Neutrality", ""))
    report.check("Endpoint Neutrality states that no endpoint is required to be human",
                 "MUST NOT require that either endpoint is a human" in neutrality)
    report.check("Endpoint Neutrality keeps the Grant as authority boundary and excludes delegation",
                 all(s in neutrality for s in
                     ("authority boundary", "LP 0.1 defines no delegation", "not a claim of novelty")))
    novelty = re.compile(r"(?i)\b(novel|novelty|first to|invent\w*|unique to|uniquely)\b")
    negation = re.compile(r"(?i)\b(no|not|never|without)\b|MUST NOT|does not")
    claims = [ln.strip() for ln in text.splitlines() if novelty.search(ln) and not negation.search(ln)]
    report.check("no novelty claim without negation (heuristic)", not claims, " | ".join(claims))
    prior = body.get("Prior Art", "")
    cited = all(s in prior for s in (
        "draft-das-6g-query-scoped-communication-handles-06",
        "https://datatracker.ietf.org/doc/html/draft-das-6g-query-scoped-communication-handles-06",
        "draft-baur-pap-02", "https://datatracker.ietf.org/doc/html/draft-baur-pap-02",
        "Berty", "https://berty.tech/docs/protocol/", "SimpleX", "https://simplex.chat/docs/simplex.html"))
    report.check("Prior Art cites A2R, PAP, Berty and SimpleX with primary URLs", cited)
    report.check("State section declares LIVE and RESULT phases (not State values)",
                 "LIVE and RESULT are lifecycle phases, not State values" in flat(body.get("State", "")))

    report.check("header: LP 0.1 draft 3, PRIVATE LOCKED BASELINE FOR P0, lock date and scope",
                 "| Version | LP 0.1, draft 3" in text and "| Status | PRIVATE LOCKED BASELINE FOR P0 |" in text
                 and "| Lock date | 2026-09-27" in text
                 and all(s in text for s in ("Not a public standard", "not freedom-to-operate", "not trademark clearance",
                                             "Any later normative change requires a new LP version or draft")))
    head, _, rest = text.partition("## 1. Motivation")
    normative, _, appendices = rest.partition("## Appendix B.")
    normative_bytes = ("## 1. Motivation" + normative + "## Appendix C." + appendices.partition("## Appendix C.")[2]).encode("utf-8")
    report.check("locked normative text unchanged (sections 1-15, Appendices A and C match the private LP 0.1 lock)",
                 hashlib.sha256(normative_bytes).hexdigest() == LOCKED_NORMATIVE_SHA256, hashlib.sha256(normative_bytes).hexdigest())

    # cryptographic profile (§2.6)
    terminology = body.get("Terminology", "")
    profile_part = terminology.split("### 2.6 Cryptographic profile", 1)[1] if "### 2.6 Cryptographic profile" in terminology else ""
    profile = [r[0] for r in markdown_table(profile_part, "Primitive")]
    report.check("crypto profile (§2.6) lists exactly the canonical LP 0.1 core primitives, in order",
                 tuple(profile) == CRYPTO_PROFILE, str(profile))
    report.check("crypto profile: standard primitives only, no custom cryptography; WebAuthn and X25519 excluded",
                 all(s in flat(profile_part) for s in (
                     "LP 0.1 uses standard primitives only and defines no custom cryptography",
                     "WebAuthn is not an LP 0.1 wire primitive",
                     "X25519 is not used directly by LP 0.1 and is not a required core primitive"))
                 and not any("WebAuthn" in p or "X25519" in p for p in profile))

    # error code for a Redemption after redeem_by
    grant_text = flat(body.get("Grant", ""))
    codes = [r[0] for r in markdown_table(body.get("Protocol Lifecycle", ""), "Code")]
    report.check(f"bearer window: redeem_by <= issued_at + REDEEM_WINDOW_MAX (900 s) is normative; error {ERROR_CODE}",
                 "`redeem_by` ≤ `issued_at` + `REDEEM_WINDOW_MAX`" in grant_text
                 and "| `REDEEM_WINDOW_MAX` | 900 s" in text and f"`{ERROR_CODE}`" in codes
                 and text.count(f"`{ERROR_CODE}`") >= 5, f"{text.count(ERROR_CODE)} occurrences")

    # fragment secret and memory-only capability secrets (§5.4)
    section54 = body.get("Grant", "").split("### 5.4 Fragment secret cleanup", 1)
    section54 = section54[1] if len(section54) == 2 else ""
    rule3, rule4, rule5 = (numbered_rule(section54, n) for n in (3, 4, 5))
    report.check("fragment secret cleanup rules (§5.4): replaceState, no third-party code, delete S, PRK_line",
                 all(s in grant_text for s in ("### 5.4 Fragment secret cleanup", "history.replaceState",
                                                "MUST NOT load third-party scripts", "MUST delete S",
                                                "PRK_line = HKDF-Extract(salt = line_salt, IKM = S)")))
    missing_storage = [s for s in FORBIDDEN_STORAGE if s not in rule3]
    report.check("§5.4: S and line_salt are memory-only and MUST NOT be written to any forbidden storage",
                 "exist only in the memory of the running page and MUST NOT be persisted" in rule3
                 and "S and `line_salt` MUST NOT be written to" in rule3 and not missing_storage,
                 ", ".join(missing_storage))
    report.check("§5.4: page/tab/process loss loses the capability; no recovery or account; Provider issues a new Grant",
                 all(s in rule4 for s in ("If the page, tab or process that holds these secrets ends",
                                          "the capability they carry is lost",
                                          "LP 0.1 has no recovery, export, backup or account mechanism",
                                          "the Provider issues a new Grant")))
    report.check("§5.4: the non-extractable Thing-key is not a capability secret", "not a capability secret" in rule5)

    # directional signaling keys and AES-GCM nonce rules (§7.2, §7.3)
    rdv_text = flat(body.get("Rendezvous", ""))
    report.check("direction-separated signaling keys and addresses (p2c / c2p)",
                 all(s in rdv_text for s in ('"LYNE/0.1/rdv|" dir', '"LYNE/0.1/signal|" dir', "`p2c`", "`c2p`",
                                              "`K_signal_p2c` = `K_signal(p2c)`", "`K_signal_c2p` = `K_signal(c2p)`",
                                              "reflected envelope fails",
                                              "`p2c` requires `provider`, `c2p` requires `client`")))
    report.check("AES-GCM nonce rules (§7.3): 96 random bits, no reuse per key, separate spaces, transient replay set",
                 all(s in rdv_text for s in (
                     "`n` is exactly 96 random bits",
                     "A sender MUST NOT reuse a nonce under the same directional key",
                     "separate nonce spaces",
                     "the same nonce value under the opposite directional key is not a reuse",
                     "A receiver MUST keep, for the active Line (one `line_seq`), the set of nonces",
                     "MUST reject an envelope whose nonce is already in that set",
                     "The set is transient and held in memory only: it is deleted when the Line ends")))
    identity = flat(body.get("Redemption and Thing-bound Identity", ""))
    result_text = flat(body.get("Result", ""))
    report.check("Result exchange over HTTP: Client is always the requester; pending_result",
                 "Roles over HTTP are fixed" in identity and "`pending_result`" in identity
                 and "Over the Thing endpoint the HTTP roles are fixed" in result_text
                 and "offered as `pending_result` in GetThing responses" in result_text
                 and "The Client endpoint is always the HTTP requester" in text)

    # persistence wording
    report.check("persistence terms defined (§2.5: persistent, retained until, transient, not held)",
                 all(f"| {t} |" in text for t in ("persistent", "transient", "not held"))
                 and "| retained until *event* |" in text)
    legacy = [p for p in ("MUST NOT receive or store", "beyond operational necessity", "holds at least",
                          "is not persisted.") if p in text]
    report.check("legacy persistence phrases removed", not legacy, ", ".join(legacy))
    report.check("Live Line forbids content persistence by any party",
                 "MUST NOT be persisted by any party" in flat(body.get("Live Line", ""))
                 and "not held by the Rendezvous Service" in flat(body.get("Live Line", "")))
    report.check("Result is the only persistent artifact of a Line",
                 "only persistent artifact of a Live Line" in result_text)
    rows = markdown_table(body.get("Protocol Lifecycle", ""), "Data")
    table = {r[0]: r for r in rows}
    required_rows = ("Thing", "State chain", "Result (complete)", "Result proposal (incomplete)",
                     "Grant Secret S", "Signaling envelopes", "Live Line content (media, lyne-data)")
    report.check("persistence table has the required rows", all(r in table for r in required_rows),
                 ", ".join(r for r in required_rows if r not in table))
    off_vocab = [f"{r[0]}: {c}" for r in rows for c in r[1:5] if not PERSISTENCE_TERM.match(c)]
    report.check("persistence table uses only the §2.5 terms", not off_vocab, " | ".join(off_vocab))
    rdv_ok = all(r[3] == "not held" or (r[0] == "Signaling envelopes" and r[3].startswith("transient"))
                 for r in rows)
    turn_ok = all(r[4] == "not held" or (r[0].startswith("Live Line content") and r[4].startswith("transient"))
                  for r in rows)
    report.check("persistence: Rendezvous holds only transient envelopes; TURN only relays Line content",
                 rdv_ok and turn_ok)
    content = table.get("Live Line content (media, lyne-data)", [""] * 5)
    report.check("persistence: Live Line content is transient everywhere, never persistent or retained",
                 all(c.startswith(("transient", "not held")) for c in content[1:5]))
    result_row = table.get("Result (complete)", [""] * 5)
    secret_row = table.get("Grant Secret S", [""] * 5)
    report.check("persistence: complete Result persistent at Provider and Client; S retained only until Redemption",
                 result_row[1] == "persistent" and result_row[2] == "persistent"
                 and all("until Redemption completes or redeem_by" in c for c in secret_row[1:3]))
    salt_row = table.get("line_salt, PRK_line and derived keys", [""] * 5)
    nonce_row = table.get("Nonce-replay sets (signaling)", [""] * 5)
    report.check("persistence: S, line_salt, PRK_line and nonce-replay sets are transient, memory-only at the Client",
                 all(r[2].startswith("transient (memory only") for r in (secret_row, salt_row, nonce_row))
                 and all(r[1].startswith("transient") for r in (secret_row, salt_row, nonce_row)))

    # Appendix B classification (exact)
    appendix = text.split("## Appendix B.", 1)[1].split("## Appendix C.", 1)[0] if "## Appendix B." in text else ""
    b_rows = {r[0]: r for r in markdown_table(appendix, "#") if r and r[0].startswith("B.")}
    for item, expected in APPENDIX_B_EXPECTED.items():
        got = b_rows.get(item, ["", "", "(missing)"])[2]
        report.check(f"Appendix B {item} is classified exactly: {expected[:60]}", got == expected, got)
    report.check("Appendix B has no unexpected items", set(b_rows) == set(APPENDIX_B_EXPECTED),
                 ", ".join(sorted(set(b_rows) ^ set(APPENDIX_B_EXPECTED))))
    lock_blockers = sorted(k for k, r in b_rows.items() if r[2].startswith("HUMAN GATE") and "PUBLIC/COMMERCIAL" not in r[2])
    report.check("B.1 is the only private-lock HUMAN GATE; B.6 and B.11 block only public/commercial steps",
                 lock_blockers == ["B.1"], ", ".join(lock_blockers))
    closing = [ln.strip() for ln in appendix.strip().splitlines() if ln.strip()][-2:]
    report.check("Appendix B ends with the private-lock and public/commercial release statements",
                 closing == [PRIVATE_LOCK_LINE, PUBLIC_RELEASE_LINE], " | ".join(closing))
    report.check("B.7 points to the full-read record", "FULL_READ_2026-09-27.md" in " ".join(b_rows.get("B.7", [])))


def check_threat_model(report):
    text = (PROTO / "Threat_model.md").read_text(encoding="utf-8")
    blocks = re.split(r"^### ", text, flags=re.M)[1:]
    headings = {b.splitlines()[0].strip(): b for b in blocks}
    for name in MANDATORY_THREATS + ADDITIONAL_THREATS:
        kind = "mandatory" if name in MANDATORY_THREATS else "additional"
        match = [h for h in headings if re.fullmatch(rf"T\d\d {re.escape(name)}", h, flags=re.I)]
        if not match:
            report.check(f"threat model covers ({kind}): {name}", False, "heading missing")
            continue
        block = headings[match[0]]
        missing = [label for label in THREAT_LABELS if label not in block]
        report.check(f"threat model covers ({kind}): {name} (threat, impact, mitigation, residual risk)",
                     not missing, ", ".join(missing))


def check_changelog(report):
    text = (PROTO / "CHANGELOG.md").read_text(encoding="utf-8")
    report.check("CHANGELOG records LP 0.1 draft 3 (Gate 1 contract repair) above draft 2",
                 "## LP 0.1 draft 3" in text and "Gate 1 contract repair" in text
                 and text.find("## LP 0.1 draft 3") < text.find("## LP 0.1 draft 2"))


def check_gate1_contract(report):
    """Repository-wide rules of BLOCK 004R that are not local to PROTOCOL.md."""
    files = dict(repo_text_files())
    hits = sorted(name for name, body in files.items() if OLD_ERROR_CODE in body)
    report.check("the superseded redemption error code has 0 occurrences in the repository",
                 not hits, ", ".join(hits))
    hits = sorted(name for name, body in files.items()
                  if OLD_KEY_NAME.search(body) or OLD_KEY_LABEL in body or OLD_KEY_FUNCTION in body)
    report.check("the superseded signaling key name, HKDF label and helper have 0 occurrences", not hits,
                 ", ".join(hits))
    uses = {name for name, body in files.items() if ERROR_CODE in body}
    required = {"03_Protokoll/PROTOCOL.md", "03_Protokoll/Threat_model.md", "03_Protokoll/CHANGELOG.md",
                "03_Protokoll/tests/run_tests.py"}
    report.check(f"{ERROR_CODE} is used in the protocol, threat model, changelog and tests",
                 required <= uses, ", ".join(sorted(required - uses)))

    master = files.get("00_LYVE_MASTER_KAVA.md", "")
    not_built = master.split("## 13. NOT BUILT", 1)[1].split("\n## ", 1)[0] if "## 13. NOT BUILT" in master else ""
    crypto_line = next((ln for ln in not_built.splitlines() if "NO CUSTOM CRYPTOGRAPHY" in ln), "")
    report.check("master §13 states the canonical crypto profile (standard primitives only, no custom cryptography)",
                 "STANDARD PRIMITIVES ONLY, NO CUSTOM CRYPTOGRAPHY" in crypto_line
                 and all(p in crypto_line for p in MASTER_PROFILE)
                 and "WebAuthn" in crypto_line and "X25519" in crypto_line
                 and "ainult Ed25519/X25519/HKDF/DTLS-SRTP/WebAuthn" not in master)
    version = re.match(r"# LYNE — MASTER STRUKTUURKAVA v(\d+)\.(\d+)\.(\d+)\n", master)
    report.check("master is at least v0.3.5 (Gate 1 contract repair recorded)",
                 version is not None and tuple(map(int, version.groups())) >= (0, 3, 5),
                 master.splitlines()[0] if master else "missing")
    otsused = files.get("01_Idee/Otsused.md", "")
    report.check("Otsused.md records the Gate 1 technical closure row verbatim", OTSUSED_ROW in otsused.splitlines())

    full = FULL_READ.read_text(encoding="utf-8") if FULL_READ.is_file() else ""
    report.check("A2R/PAP full-read record exists with revision, access date, sections, overlap, differences",
                 all(s in full for s in ("## Draft revision", "## Access date", "## Sections read",
                                         "## Material overlap", "## Material differences", "## Contradiction check",
                                         "draft-das-6g-query-scoped-communication-handles-06", "draft-baur-pap-02",
                                         "2026-09-27")))
    report.check("full-read record: both drafts read completely and identified by SHA-256",
                 "kõik 1960 rida" in full and "kõik 5320 rida" in full
                 and "F14AA153AD4717C1F54371EBB645DDE3A6D925E07A8F9E26BE26AD21C0C78920" in full
                 and "A0C97214DF66689F8FB6B7206E8ABF1EFCC94A309044CBFE114C889C0F6C4535" in full)
    report.check("full-read record: no material contradiction; B.7 resolved for the private lock",
                 "**material contradiction: NONE**" in full and "RESOLVED FOR LP 0.1 PRIVATE LOCK" in full)


def check_secret_scan(report):
    if not SECRET_SCAN.is_file():
        report.check("scripts/secret-scan.py exists", False)
        return
    run = subprocess.run([sys.executable, str(SECRET_SCAN), "--self-test"], capture_output=True, text=True)
    report.check("secret scan self-test passes (every rule fires on synthetic material; values never printed)",
                 run.returncode == 0, run.stdout.strip().splitlines()[-1] if run.stdout.strip() else run.stderr)
    token = "gh" + "p_" + "9" + lp.b64u(lp.tv("secret-scan mutation", 32)).replace("-", "a").replace("_", "b")[:35]
    with tempfile.TemporaryDirectory(prefix="lyne-scan-mutation-") as tmp:
        (Path(tmp) / "notes").mkdir()
        (Path(tmp) / "notes" / "leak.md").write_text(f"deploy token {token}\n", encoding="utf-8")
        leaked = subprocess.run([sys.executable, str(SECRET_SCAN), "--root", tmp], capture_output=True, text=True)
        (Path(tmp) / "notes" / "leak.md").write_text("deploy token: see the vault\n", encoding="utf-8")
        clean = subprocess.run([sys.executable, str(SECRET_SCAN), "--root", tmp], capture_output=True, text=True)
    report.check("secret scan mutation: a synthetic token fails the scan with path and rule ID only",
                 leaked.returncode == 1 and "notes/leak.md: github-token" in leaked.stdout
                 and token not in leaked.stdout + leaked.stderr, leaked.stdout.strip().replace("\n", " | "))
    report.check("secret scan mutation: the same tree without the token passes", clean.returncode == 0,
                 clean.stdout.strip().replace("\n", " | "))


def check_ci(report):
    requirements = (ROOT / "requirements-dev.txt")
    pins = requirements.read_text(encoding="utf-8") if requirements.is_file() else ""
    report.check("requirements-dev.txt pins jsonschema and cryptography exactly",
                 re.search(r"^jsonschema==\d+\.\d+\.\d+$", pins, flags=re.M) is not None
                 and re.search(r"^cryptography==\d+\.\d+\.\d+$", pins, flags=re.M) is not None)
    workflow = ROOT / ".github" / "workflows" / "protocol.yml"
    wf = workflow.read_text(encoding="utf-8") if workflow.is_file() else ""
    report.check("protocol CI workflow runs on protocol/** and executes the protocol tests",
                 "'protocol/**'" in wf and "pip install -r requirements-dev.txt" in wf
                 and "python 03_Protokoll/tests/run_tests.py" in wf)
    runs = [ln.split("run:", 1)[1].strip() for ln in wf.splitlines() if ln.strip().startswith("run:")]
    order = ("python -m pip install -r requirements-dev.txt", "python 03_Protokoll/tests/run_tests.py",
             "./scripts/verify-foundation.ps1 -Ci", "python scripts/secret-scan.py")
    report.check("protocol CI runs, in order: install deps, protocol tests, foundation verify, secret scan",
                 runs == list(order), " -> ".join(runs))
    verify = (ROOT / "scripts" / "verify-foundation.ps1").read_text(encoding="utf-8")
    report.check("foundation verification requires scripts/secret-scan.py", "'scripts\\secret-scan.py'" in verify)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    report = Report()
    schemas = check_schemas(report)
    check_fixtures(report, schemas)
    check_crypto_and_lifecycle(report)
    check_signaling(report)
    check_reproducible(report)
    check_protocol(report)
    check_threat_model(report)
    check_changelog(report)
    check_gate1_contract(report)
    check_secret_scan(report)
    check_ci(report)
    print()
    total = report.passed + report.failed
    if report.failed:
        print(f"LP 0.1 GATE 1 TESTS: FAIL ({report.failed} of {total} checks failed)")
        return 1
    print(f"LP 0.1 GATE 1 TESTS: PASS ({total} checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
