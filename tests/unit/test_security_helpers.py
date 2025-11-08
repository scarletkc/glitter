from __future__ import annotations

from pathlib import Path

import pytest

from glitter.security import (
    compute_file_sha256,
    decode_bytes,
    encode_bytes,
    fingerprint_from_public_key,
)


def test_compute_file_sha256(tmp_path: Path) -> None:
    file_path = tmp_path / "payload.bin"
    file_path.write_text("glitter", encoding="utf-8")

    digest = compute_file_sha256(file_path)

    assert len(digest) == 64
    assert digest == compute_file_sha256(file_path)


def test_encode_decode_roundtrip() -> None:
    payload = b"hello-world"
    encoded = encode_bytes(payload)
    assert decode_bytes(encoded) == payload


def test_decode_bytes_invalid() -> None:
    with pytest.raises(Exception):
        decode_bytes("@@@invalid@@@")


def test_fingerprint_from_public_key() -> None:
    public_key = b"1234567890123456"
    display, hex_value = fingerprint_from_public_key(public_key)

    assert display
    assert hex_value
