"""crypto.py - the keys behind a PRIVATE journal.

  seal / open_       AES-256-GCM with the position bound in as associated data (a ciphertext moved to another place fails)
  KeyPair            an X25519 key pair (a person's 'box' key: how a key is delivered to them privately)
  wrap_for / unwrap  deliver a 32-byte secret to the owner of an X25519 public key (ephemeral key agreement + HKDF-SHA256 + AES-GCM); only that person's private key opens it
  split / combine    Shamir secret sharing (k of n) from the superproof SDK, with a check hash, for the legacy key held by executors
  Signer / verify    Ed25519 identity signatures over canonical JSON with a domain tag (owner policies, executor attestations, witness signatures)
Plain Python with the 'cryptography' library's primitives; no independent review."""
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vega_superproof.seal import keysplit


class CryptoRefused(ValueError):
    pass


def new_key() -> bytes:
    return os.urandom(32)


def _k(key):
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise CryptoRefused("a key is 32 bytes")
    return bytes(key)


def seal(key: bytes, plaintext: bytes, aad: bytes = b""):
    nonce = os.urandom(12)
    return nonce, AESGCM(_k(key)).encrypt(nonce, bytes(plaintext), bytes(aad))


def open_(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    try:
        return AESGCM(_k(key)).decrypt(bytes(nonce), bytes(ct), bytes(aad))
    except (InvalidTag, ValueError) as exc:
        raise CryptoRefused("wrong key, wrong place, or the data was altered") from exc


class KeyPair:
    def __init__(self):
        self._sk = X25519PrivateKey.generate()
        self.public = self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def unwrap(self, blob: bytes) -> bytes:
        try:
            eph, nonce, ct = bytes(blob[:32]), bytes(blob[32:44]), bytes(blob[44:])
            shared = self._sk.exchange(X25519PublicKey.from_public_bytes(eph))
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"VEGA-JOURNAL-WRAP-1|" + eph + self.public).derive(shared)
            return AESGCM(key).decrypt(nonce, ct, b"wrap")
        except (InvalidTag, ValueError) as exc:
            raise CryptoRefused("this wrapped key was not made for this key pair") from exc


def wrap_for(public: bytes, secret: bytes) -> bytes:
    if not isinstance(public, (bytes, bytearray)) or len(public) != 32:
        raise CryptoRefused("a public box key is 32 bytes")
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes(public)))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"VEGA-JOURNAL-WRAP-1|" + eph_pub + bytes(public)).derive(shared)
    nonce = os.urandom(12)
    if not isinstance(secret, (bytes, bytearray)) or not 1 <= len(secret) <= 1024:
        raise CryptoRefused("a wrapped secret is 1 to 1024 bytes")
    return eph_pub + nonce + AESGCM(key).encrypt(nonce, bytes(secret), b"wrap")


def split(secret: bytes, k: int, n: int):
    """-> (list of (x, share bytes), check). k of n shares rebuild the secret; fewer reveal nothing."""
    if not 2 <= k <= n <= 16:
        raise CryptoRefused("2 <= k <= n <= 16")
    return keysplit.split_checked(_k(secret), k, n)


def combine(shares, check: str, k: int, n: int) -> bytes:
    try:
        return keysplit.combine_checked([(int(x), bytes(b)) for x, b in shares], check, k, n)
    except (ValueError, TypeError) as exc:
        raise CryptoRefused(str(exc)) from exc


def canonical(obj) -> bytes:
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CryptoRefused("not plain data: %s" % exc) from exc


class Signer:
    def __init__(self):
        self._sk = Ed25519PrivateKey.generate()
        self.public = self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, tag: str, body) -> str:
        return self._sk.sign(b"VEGA-JOURNAL-SIG-1|" + tag.encode("ascii") + b"|" + canonical(body)).hex()


def verify(public, tag: str, body, sig_hex) -> bool:
    try:
        if not isinstance(public, (bytes, bytearray)) or len(public) != 32 or not isinstance(sig_hex, str) or len(sig_hex) != 128:
            return False
        Ed25519PublicKey.from_public_bytes(bytes(public)).verify(bytes.fromhex(sig_hex), b"VEGA-JOURNAL-SIG-1|" + tag.encode("ascii") + b"|" + canonical(body))
        return True
    except (InvalidSignature, ValueError, TypeError, CryptoRefused):
        return False


def mac(key: bytes, data: bytes) -> str:
    import hmac
    return hmac.new(_k(key), b"VEGA-JOURNAL-MAC-1|" + bytes(data), hashlib.sha256).hexdigest()
