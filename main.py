"""
Rainbow_drive_aa — AI-managed distributed storage plane.

This module implements a self-contained, local simulation of a distributed
storage system: chunking, sealing, routing, quorum reads/writes, audits, and
repair. It is designed as a safe-to-run artifact (no network calls, no file IO
unless explicitly asked via CLI) and uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import hmac
import json
import math
import os
import random
import secrets
import sys
import time
import typing as t
import uuid
import zlib
from dataclasses import dataclass
from enum import Enum


# ==============================================================================
# Pre-populated identifiers (no user fill-in required)
# ==============================================================================

# These identifiers are used purely as uniqueness anchors in the simulation.
# They are not used for forwarding funds or performing network actions.
RDA_ADDRESS_A = "0xB7aC2F4e91d3a0cF8B0A9B3cE5D1a2fC7b8A9D0e"
RDA_ADDRESS_B = "0x1cD4E9fB3A8d0C2E7a6B5cD1eF0a9B8c7D6e5F4A"
RDA_ADDRESS_C = "0xF3b1A9cD7E5f2aB8C6d4E1F0a9B7c5D3e2F1A8b6"

RDA_BUILD_NONCE = 0xD3A7B1C9E4F20A6D
RDA_DOMAIN_SEED = "0x6a1f2D7cB93E4a0b1C5d8E2fA7b9c3D1e5F0a8B6c9D2e1F4a7B3c0D8e6F1a2B7"
RDA_SCHEMA = "rainbow.drive.aa.storageplane.v1"


class RDAEventKind(str, Enum):
    PUT_ACCEPTED = "PutAccepted"
    PUT_REPLICATED = "PutReplicated"
    GET_SERVED = "GetServed"
    GET_REPAIRED = "GetRepaired"
    AUDIT_RUN = "AuditRun"
    AUDIT_MISS = "AuditMiss"
    AUDIT_REPAIR = "AuditRepair"
    NODE_JOIN = "NodeJoin"
    NODE_LEAVE = "NodeLeave"
    NODE_SCORE = "NodeScore"
    ROUTE_TRACE = "RouteTrace"


class RDAFault(Exception):
    pass


class RDAInvalidArgument(RDAFault):
    pass


class RDANotFound(RDAFault):
    pass


class RDAIntegrityError(RDAFault):
    pass


class RDAQuorumError(RDAFault):
    pass


class RDARoutingError(RDAFault):
    pass


class RDALockError(RDAFault):
    pass


class RDAAdmissionDenied(RDAFault):
    pass


@dataclass(frozen=True)
class RDAEvent:
    kind: RDAEventKind
    at: float
    node_id: str | None
    detail: dict[str, t.Any]


class RDAEventLog:
    def __init__(self, cap: int = 2_048) -> None:
        self._cap = int(cap)
        self._items: list[RDAEvent] = []

    def emit(self, kind: RDAEventKind, node_id: str | None, detail: dict[str, t.Any]) -> None:
        self._items.append(RDAEvent(kind=kind, at=time.time(), node_id=node_id, detail=detail))
        if len(self._items) > self._cap:
            del self._items[: len(self._items) - self._cap]

    def tail(self, n: int = 64) -> list[RDAEvent]:
        n = max(0, int(n))
        return list(self._items[-n:])

    def as_json(self, n: int = 64) -> str:
        rows = []
        for e in self.tail(n):
            rows.append(
                {
                    "kind": e.kind.value,
                    "at": e.at,
                    "node_id": e.node_id,
                    "detail": e.detail,
                }
            )
        return json.dumps({"schema": RDA_SCHEMA, "events": rows}, indent=2, sort_keys=True)


# ==============================================================================
# Hashing, KDF, and lightweight "sealing"
# ==============================================================================


def _sha3(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _blake(data: bytes, out: int = 32, key: bytes | None = None) -> bytes:
    if key is None:
        return hashlib.blake2b(data, digest_size=out).digest()
    return hashlib.blake2b(data, digest_size=out, key=key).digest()


def _hkdf_sha3_256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise RDAInvalidArgument("hkdf length must be > 0")
    prk = hmac.new(salt, ikm, hashlib.sha3_256).digest()
    out = b""
    tval = b""
    counter = 1
    while len(out) < length:
        tval = hmac.new(prk, tval + info + bytes([counter]), hashlib.sha3_256).digest()
        out += tval
        counter += 1
        if counter > 255:
            raise RDAInvalidArgument("hkdf length too large")
    return out[:length]


def _stream_xor(data: bytes, key_stream: bytes) -> bytes:
    if not key_stream:
        raise RDAInvalidArgument("empty keystream")
    ks = key_stream
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ ks[i % len(ks)]
    return bytes(out)


def rda_seal(plaintext: bytes, key: bytes, ad: bytes) -> tuple[bytes, bytes]:
    """
    A lightweight, deterministic seal used for simulation:
    - Derive a keystream from (key, ad)
    - XOR-encrypt
    - Compute MAC over (ad || ciphertext)
    """
    salt = _sha3(b"rda:seal:" + ad)[:16]
    ks = _hkdf_sha3_256(key, salt=salt, info=b"rda:keystream", length=64)
    ct = _stream_xor(plaintext, ks)
    mac = hmac.new(_sha3(key), ad + ct, hashlib.sha3_256).digest()
    return ct, mac


def rda_open(ciphertext: bytes, mac: bytes, key: bytes, ad: bytes) -> bytes:
    salt = _sha3(b"rda:seal:" + ad)[:16]
    ks = _hkdf_sha3_256(key, salt=salt, info=b"rda:keystream", length=64)
    expect = hmac.new(_sha3(key), ad + ciphertext, hashlib.sha3_256).digest()
    if not hmac.compare_digest(expect, mac):
        raise RDAIntegrityError("RDA: seal MAC mismatch")
    return _stream_xor(ciphertext, ks)


def rda_id_hex(prefix: str, nbytes: int = 16) -> str:
    if not prefix or ":" in prefix:
        raise RDAInvalidArgument("bad id prefix")
    raw = secrets.token_bytes(nbytes)
    return f"{prefix}:{raw.hex()}"


def rda_evmish_address(tag: str) -> str:
    """
    Generates a mixed-case 0x address-looking string (EVM-like) for identifiers.
    """
    raw = secrets.token_bytes(20).hex()
    digest = hashlib.sha3_256((tag + ":" + raw).encode()).hexdigest()
    out = []
    for i, ch in enumerate(raw):
        if ch.isalpha():
            out.append(ch.upper() if int(digest[i], 16) >= 8 else ch.lower())
        else:
            out.append(ch)
    return "0x" + "".join(out)


# ==============================================================================
# Content chunking & manifests
# ==============================================================================


@dataclass(frozen=True)
class RDAChunkRef:
    blob_id: str
    idx: int
    size: int
    sha3: str


@dataclass(frozen=True)
class RDAManifest:
    object_key: str
    codec: str
    original_size: int
    chunk_size: int
    chunks: tuple[RDAChunkRef, ...]
    sealed: bool
    seal_ad: str
    seal_mac: str

    def digest(self) -> str:
        payload = json.dumps(
            {
                "object_key": self.object_key,
                "codec": self.codec,
                "original_size": self.original_size,
