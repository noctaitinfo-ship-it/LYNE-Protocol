"""LP 0.1 test library: encoding and derivation helpers for fixtures and tests only.

Implements the encoding rules of PROTOCOL.md section 2 (base64url, JCS subset, JWK thumbprint,
detached JWS with EdDSA), the derivations of sections 6.2 and 7.2 (HKDF-SHA256, HMAC-SHA256) and
the signaling envelopes of section 7.3 (AES-256-GCM with directional keys and nonce rules) so that
example fixtures can be generated and verified. It is not a protocol implementation.
Ed25519, HKDF and AES-GCM come from the `cryptography` package.
"""

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

LP_VERSION = "0.1"
RDV_BUCKET = 300
RESULT_WINDOW = 600
GRANT_MAX_LIFETIME = 86400
REDEEM_WINDOW_MAX = 900
MAX_CLOCK_SKEW = 300
DIRECTIONS = ("p2c", "c2p")
SENDER_ROLE = {"p2c": "provider", "c2p": "client"}
NONCE_BYTES = 12
TV_PREFIX = "LYNE LP 0.1 TEST VECTOR - NOT A SECRET - "

SIG_MEMBERS = {
    "thing": ("signature",),
    "state": ("signature",),
    "grant": ("signature",),
    "redemption": ("signature",),
    "redemption_receipt": ("signature",),
    "result": ("provider_sig", "client_thing_sig"),
    "signal": ("signature",),
}


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _check_subset(value):
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError("integer outside the interoperable range")
        return
    if isinstance(value, float):
        raise ValueError("LP 0.1 objects must not contain non-integer numbers")
    if isinstance(value, list):
        for item in value:
            _check_subset(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not key.isascii():
                raise ValueError("LP 0.1 member names are ASCII")
            _check_subset(item)
        return
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def jcs(value) -> bytes:
    """RFC 8785 canonical form for the LP 0.1 value subset (ASCII member names, integers only).

    For this subset, sorted-key compact JSON with ECMAScript string escaping equals JCS.
    """
    _check_subset(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def tv(label: str, length: int = 32) -> bytes:
    return hashlib.sha256((TV_PREFIX + label).encode("utf-8")).digest()[:length]


def example_private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(tv(label))


def public_b64u(private_key: Ed25519PrivateKey) -> str:
    return b64u(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def key_id(public_key_b64u: str) -> str:
    """JWK Thumbprint (RFC 7638, SHA-256) of an Ed25519 OKP key (RFC 8037)."""
    return sha256_b64u(jcs({"crv": "Ed25519", "kty": "OKP", "x": public_key_b64u}))


def signing_payload(obj: dict, kind: str) -> bytes:
    return jcs({k: v for k, v in obj.items() if k not in SIG_MEMBERS[kind]})


def sign(private_key: Ed25519PrivateKey, obj: dict, kind: str) -> str:
    header = b64u(jcs({"alg": "EdDSA", "kid": key_id(public_b64u(private_key))}))
    signing_input = (header + "." + b64u(signing_payload(obj, kind))).encode("ascii")
    return header + ".." + b64u(private_key.sign(signing_input))


def verify(jws: str, public_key_b64u: str, obj: dict, kind: str):
    parts = jws.split(".")
    if len(parts) != 3 or parts[1] != "":
        return False, "not a detached JWS"
    header_b64, _, sig_b64 = parts
    try:
        header = json.loads(b64u_decode(header_b64))
    except ValueError:
        return False, "protected header is not JSON"
    if header != {"alg": "EdDSA", "kid": key_id(public_key_b64u)}:
        return False, "protected header must be exactly alg=EdDSA and the expected kid"
    signing_input = (header_b64 + "." + b64u(signing_payload(obj, kind))).encode("ascii")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64u_decode(public_key_b64u))
        public_key.verify(b64u_decode(sig_b64), signing_input)
    except (InvalidSignature, ValueError):
        return False, "signature does not verify"
    return True, "ok"


def sha256_b64u(data: bytes) -> str:
    return b64u(hashlib.sha256(data).digest())


def state_hash(state: dict) -> str:
    return sha256_b64u(jcs(state))


def secret_commitment(grant_secret: bytes) -> str:
    return sha256_b64u(grant_secret)


def _hkdf(ikm: bytes, salt, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def redeem_key(grant_secret: bytes) -> bytes:
    return _hkdf(grant_secret, None, b"LYNE/0.1/redeem")


def secret_proof(grant_secret: bytes, grant_id: str, challenge: str, client_thing_pub: str) -> str:
    message = jcs({"challenge": challenge, "client_thing_pub": client_thing_pub, "grant_id": grant_id})
    return b64u(hmac.new(redeem_key(grant_secret), message, hashlib.sha256).digest())


def _direction(direction: str) -> str:
    if direction not in DIRECTIONS:
        raise ValueError(f"direction must be one of {DIRECTIONS}")
    return direction


def rdv_addr(grant_secret: bytes, line_salt: bytes, direction: str, thing_id: str, epoch: int,
             line_seq: int, bucket: int) -> str:
    info = f"LYNE/0.1/rdv|{_direction(direction)}|{thing_id}|{epoch}|{line_seq}|{bucket}".encode("ascii")
    return b64u(_hkdf(grant_secret, line_salt, info))


def signal_key(grant_secret: bytes, line_salt: bytes, direction: str, thing_id: str, epoch: int,
               line_seq: int) -> bytes:
    """K_signal(dir): K_signal_p2c or K_signal_c2p, an AES-256-GCM key (PROTOCOL.md section 7.2)."""
    info = f"LYNE/0.1/signal|{_direction(direction)}|{thing_id}|{epoch}|{line_seq}".encode("ascii")
    return _hkdf(grant_secret, line_salt, info)


class NonceReuse(Exception):
    """A sender tried to reuse a nonce under the same directional key."""


class EnvelopeRejected(Exception):
    """A receiver rejected a signaling envelope; the message names the rule."""


def seal_envelope(key: bytes, addr: str, plaintext: bytes, nonce: bytes) -> dict:
    """Envelope of PROTOCOL.md section 7.3: AES-256-GCM, 96-bit nonce, AAD = UTF-8(addr)."""
    if len(nonce) != NONCE_BYTES:
        raise ValueError("the AES-GCM nonce must be exactly 96 bits")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, addr.encode("utf-8"))
    return {"addr": addr, "n": b64u(nonce), "c": b64u(ciphertext)}


def open_envelope(key: bytes, envelope: dict, read_addr: str) -> bytes:
    """Decrypts with the address it was read from as AAD; raises InvalidTag on any failure."""
    nonce = b64u_decode(envelope["n"])
    return AESGCM(key).decrypt(nonce, b64u_decode(envelope["c"]), read_addr.encode("utf-8"))


class SignalSender:
    """Outbound side of one direction of one Line: never reuses a nonce under its key."""

    def __init__(self, direction: str, key: bytes):
        self.direction = _direction(direction)
        self._key = key
        self._used = set()

    def seal(self, addr: str, plaintext: bytes, nonce: bytes = None) -> dict:
        nonce = os.urandom(NONCE_BYTES) if nonce is None else nonce
        if nonce in self._used:
            raise NonceReuse(f"nonce reuse under K_signal_{self.direction}")
        envelope = seal_envelope(self._key, addr, plaintext, nonce)
        self._used.add(nonce)
        return envelope


class SignalReceiver:
    """Inbound side of one direction of one Line (PROTOCOL.md section 7.3, rules 3 and 5).

    The nonce-replay set is transient: it lives in this object and is cleared when the Line ends.
    A nonce enters it only after its envelope has authenticated.
    """

    def __init__(self, direction: str, key: bytes):
        self.direction = _direction(direction)
        self._key = key
        self._seen = set()

    def receive(self, read_addr: str, envelope: dict) -> bytes:
        if envelope.get("addr") != read_addr:
            raise EnvelopeRejected("envelope address differs from the address it was read from")
        nonce = b64u_decode(envelope["n"])
        if len(nonce) != NONCE_BYTES:
            raise EnvelopeRejected("nonce is not exactly 96 bits")
        if nonce in self._seen:
            raise EnvelopeRejected(f"duplicate nonce under K_signal_{self.direction}")
        try:
            plaintext = open_envelope(self._key, envelope, read_addr)
        except InvalidTag:
            raise EnvelopeRejected("authentication failed") from None
        self._seen.add(nonce)
        return plaintext

    def end_line(self):
        self._seen.clear()

    @property
    def replay_set_size(self) -> int:
        return len(self._seen)


def signal_message_errors(message: dict, direction: str, provider_pub: str, client_pub: str,
                          last_seq: int, now: int) -> list:
    """Receiver checks of PROTOCOL.md section 7.3 rule 5 on a decrypted signal message."""
    errors = []
    expected_from = SENDER_ROLE[_direction(direction)]
    if message.get("from") != expected_from:
        errors.append(f"from must be {expected_from} for {direction}")
        return errors
    public_key = provider_pub if expected_from == "provider" else client_pub
    ok, why = verify(message.get("signature", ""), public_key, message, "signal")
    if not ok:
        errors.append(why)
    if not message.get("seq", 0) > last_seq:
        errors.append("seq does not increase")
    if abs(unix(message["sent_at"]) - now) > MAX_CLOCK_SKEW:
        errors.append("sent_at outside MAX_CLOCK_SKEW")
    return errors


def grant_time_errors(grant: dict) -> list:
    """Time rules of PROTOCOL.md section 5.3 that JSON Schema cannot express."""
    issued, redeem_by, not_before, exp = (unix(grant[k]) for k in ("issued_at", "redeem_by", "not_before", "exp"))
    errors = []
    if not issued < redeem_by:
        errors.append("redeem_by must be after issued_at")
    if redeem_by - issued > REDEEM_WINDOW_MAX:
        errors.append("bearer window redeem_by - issued_at exceeds REDEEM_WINDOW_MAX")
    if redeem_by > exp:
        errors.append("redeem_by must not be after exp")
    if not issued <= not_before < exp:
        errors.append("issued_at <= not_before < exp violated")
    if exp - issued > GRANT_MAX_LIFETIME:
        errors.append("exp - issued_at exceeds GRANT_MAX_LIFETIME")
    if grant["line_max_seconds"] > exp - not_before:
        errors.append("line_max_seconds exceeds exp - not_before")
    return errors


def unix(timestamp: str) -> int:
    parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def iso(unix_seconds: int) -> str:
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
