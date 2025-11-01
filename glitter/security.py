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
