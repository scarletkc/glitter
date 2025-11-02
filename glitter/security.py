"""
Security helpers: Diffie-Hellman key exchange, stream cipher, and hashing.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# 2048-bit MODP Group (RFC 3526)
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44"
    "C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1"
    "FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)
DH_GENERATOR = 2

# Identity fingerprint parameters (TOFU)
FINGERPRINT_BYTES = 10
_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def generate_dh_keypair() -> Tuple[int, int]:
    """Return a Diffie-Hellman private/public key pair."""

    private = secrets.randbelow(DH_PRIME - 2) + 2
    public = pow(DH_GENERATOR, private, DH_PRIME)
    return private, public


def derive_session_key(private_key: int, peer_public: int, nonce: bytes) -> bytes:
    """Derive a shared session key from DH exchange and a nonce."""

    shared = pow(peer_public, private_key, DH_PRIME)
    shared_bytes = _int_to_bytes(shared)
    return hashlib.sha256(shared_bytes + nonce).digest()


def encode_public(value: int) -> str:
    """Safe base64 encoding for DH public numbers."""

    return base64.urlsafe_b64encode(_int_to_bytes(value)).decode("ascii")


def decode_public(encoded: str) -> int:
    """Decode a base64 DH public number."""

    data = base64.urlsafe_b64decode(encoded.encode("ascii"))
    return int.from_bytes(data, "big")


def encode_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def decode_bytes(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def generate_identity_private_key() -> ed25519.Ed25519PrivateKey:
    """Generate a new Ed25519 private key for device identity."""

    return ed25519.Ed25519PrivateKey.generate()


def serialize_identity_private_key(private_key: ed25519.Ed25519PrivateKey) -> str:
    """Return a base64 string for the given Ed25519 private key."""

    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return encode_bytes(raw)


def deserialize_identity_private_key(encoded: str) -> ed25519.Ed25519PrivateKey:
    """Reconstruct an Ed25519 private key from a base64 string."""

    raw = decode_bytes(encoded)
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def identity_public_bytes(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Return the raw public key bytes for an Ed25519 private key."""

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def fingerprint_from_public_key(public_bytes: bytes, length: int = FINGERPRINT_BYTES) -> tuple[str, str]:
    """Return (display, hex) fingerprint strings for a public key."""

    digest = hashlib.sha256(public_bytes).digest()
    if length <= 0 or length > len(digest):
        length = len(digest)
    truncated = digest[:length]
    display = _format_crockford(truncated)
    return display, digest.hex()


def compute_file_sha256(path: Path) -> str:
    """Return the SHA-256 hex digest of a file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(128 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class StreamCipher:
    """
    ChaCha20-based stream cipher backed by cryptography's C extensions.

    The previous pure Python implementation saturated CPU when large files were
    transferred. Using ChaCha20 moves the heavy lifting into optimized native
    code while preserving the original interface for the rest of the transfer
    stack.
    """

    _KEY_SIZE = 32
    _NONCE_SIZE = 16

    def __init__(self, key: bytes, nonce: bytes) -> None:
        if len(key) < self._KEY_SIZE:
            raise ValueError("session key must be at least 32 bytes for ChaCha20")
        if len(nonce) != self._NONCE_SIZE:
            raise ValueError("nonce must be exactly 16 bytes for ChaCha20")
        # ChaCha20 consumes exactly 32 bytes; keep compatibility with the
        # derived session key by truncating if necessary.
        algorithm = algorithms.ChaCha20(key[: self._KEY_SIZE], nonce)
        self._context = Cipher(algorithm, mode=None).encryptor()

    def process(self, data: bytes) -> bytes:
        if not data:
            return b""
        return self._context.update(data)


def random_nonce(size: int = 16) -> bytes:
    return os.urandom(size)


def _int_to_bytes(value: int) -> bytes:
    length = (value.bit_length() + 7) // 8 or 1
    return value.to_bytes(length, "big")


def _format_crockford(data: bytes) -> str:
    """Return Crockford Base32 string grouped with hyphens."""

    encoded = _encode_crockford(data)
    if not encoded:
        return ""
    groups = [encoded[i : i + 4] for i in range(0, len(encoded), 4)]
    return "-".join(groups)


def _encode_crockford(data: bytes) -> str:
    if not data:
        return ""
    bits = 0
    value = 0
    output: list[str] = []
    for byte in data:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            shift = bits - 5
            index = (value >> shift) & 0x1F
            output.append(_CROCKFORD_ALPHABET[index])
            bits -= 5
            value &= (1 << bits) - 1 if bits else 0
    if bits:
        index = (value << (5 - bits)) & 0x1F
        output.append(_CROCKFORD_ALPHABET[index])
    return "".join(output)
