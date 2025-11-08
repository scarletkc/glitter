"""
Verify an end-to-end encrypted file transfer over loopback.

This test spins up a TransferService on an ephemeral port, immediately
accepts an incoming request into a temporary directory, sends a small
file to 127.0.0.1, and asserts the received file hash matches the
original. Uses only local sockets; no external network required.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from glitter.transfer import TransferService
from glitter.security import compute_file_sha256


def test_transfer_roundtrip_file(tmp_path: Path) -> None:
    # Prepare a small file with deterministic content
    src = tmp_path / "hello.txt"
    payload = ("Hello, Glitter!\n" * 8).encode("utf-8")
    src.write_bytes(payload)

    # Destination directory for received files
    dest_dir = tmp_path / "received"

    # Auto-accept any incoming request into dest_dir
    def on_new_request(ticket):
        ticket.accept(dest_dir)

    service = TransferService(
        device_id="",  # no stable id needed
        device_name="tester",
        language="en",
        on_new_request=on_new_request,
        bind_port=0,  # let OS pick an ephemeral port
        allow_ephemeral_fallback=False,
        encryption_enabled=True,
    )

    try:
        service.start()

        # Send the file to ourselves over loopback
        status, sent_hash, _ = service.send_file(
            target_ip="127.0.0.1",
            target_port=service.port,
            peer_name="self",
            file_path=src,
        )

        assert status == "accepted"

        # The received file should be placed in dest_dir with the same name
        received = dest_dir / src.name

        # Wait for the receiver thread to create the file
        deadline = time.time() + 2.0
        while not received.exists() and time.time() < deadline:
            time.sleep(0.01)

        assert received.exists(), "expected received file to exist"

        # Coverage tracing and other instrumentation can slow I/O, so poll until
        # the full payload lands on disk rather than assuming it is immediate.
        size_deadline = time.time() + 2.0
        while received.stat().st_size < len(payload) and time.time() < size_deadline:
            time.sleep(0.01)

        assert received.stat().st_size == len(payload)

        # Hash of the received file must match the sender-reported SHA-256
        recv_hash = compute_file_sha256(received)
        assert recv_hash == sent_hash
    finally:
        service.stop()
