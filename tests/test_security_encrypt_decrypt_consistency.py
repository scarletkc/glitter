"""
Verify StreamCipher encryption/decryption consistency and failure cases.

Tests round-trip correctness with the same key/nonce and ensures that
using a wrong key or tampered ciphertext does not produce the original
plaintext. Uses only in-memory bytes; no IO or network.
"""

from __future__ import annotations

import os
from typing import Final

import pytest

from glitter.security import StreamCipher, random_nonce


def test_streamcipher_roundtrip() -> None:
    # ChaCha20 requires 32-byte key (min) and 16-byte nonce
    key: Final[bytes] = os.urandom(32)
    nonce: Final[bytes] = random_nonce(16)
    plaintext = b"glitter-secure" * 4

    # Encrypt then decrypt with the same key/nonce; expect exact match
    enc = StreamCipher(key, nonce)
    ciphertext = enc.process(plaintext)
    dec = StreamCipher(key, nonce)
    recovered = dec.process(ciphertext)
    assert recovered == plaintext


def test_streamcipher_wrong_key_or_tampered_ciphertext() -> None:
    key: Final[bytes] = os.urandom(32)
    nonce: Final[bytes] = random_nonce(16)
    plaintext = b"data integrity check"

    enc = StreamCipher(key, nonce)
    ciphertext = enc.process(plaintext)

    # Decrypt with a different key: should not equal the original
    wrong_key = os.urandom(32)
    wrong_dec = StreamCipher(wrong_key, nonce)
    wrong_plain = wrong_dec.process(ciphertext)
    assert wrong_plain != plaintext

    # Tamper with ciphertext: decryption should differ from original
    mutated = bytearray(ciphertext)
    mutated[0] ^= 0x01
    dec = StreamCipher(key, nonce)
    tampered_plain = dec.process(bytes(mutated))
    assert tampered_plain != plaintext

