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
                "chunk_size": self.chunk_size,
                "chunks": [dataclasses.asdict(c) for c in self.chunks],
                "sealed": self.sealed,
                "seal_ad": self.seal_ad,
                "seal_mac": self.seal_mac,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return "0x" + _sha3(payload).hex()


def rda_split_bytes(data: bytes, chunk_size: int) -> list[bytes]:
    if chunk_size <= 0:
        raise RDAInvalidArgument("chunk_size must be > 0")
    out = []
    for i in range(0, len(data), chunk_size):
        out.append(data[i : i + chunk_size])
    if not out:
        out = [b""]
    return out


def rda_join_bytes(chunks: t.Sequence[bytes], original_size: int) -> bytes:
    data = b"".join(chunks)
    if original_size < 0:
        raise RDAInvalidArgument("original_size must be >= 0")
    return data[:original_size]


def rda_compress(data: bytes, level: int = 6) -> tuple[str, bytes]:
    level = int(level)
    level = max(0, min(9, level))
    return "zlib", zlib.compress(data, level=level)


def rda_decompress(codec: str, data: bytes) -> bytes:
    if codec == "raw":
        return data
    if codec == "zlib":
        return zlib.decompress(data)
    raise RDAInvalidArgument(f"unknown codec: {codec}")


# ==============================================================================
# Routing: a compact DHT-like ring with rendezvous selection
# ==============================================================================


@dataclass(frozen=True)
class RDANodeHandle:
    node_id: str
    weight: int
    region: str


def _score_rendezvous(key: bytes, node_id: str, salt: bytes) -> int:
    h = _blake(key + b"|" + node_id.encode(), out=32, key=salt)
    return int.from_bytes(h[:8], "big")


class RDARouter:
    """
    Provides deterministic node selection for a given key using rendezvous hashing.
    """

    def __init__(self, salt: bytes) -> None:
        self._salt = salt
        self._nodes: dict[str, RDANodeHandle] = {}

    def nodes(self) -> list[RDANodeHandle]:
        return list(self._nodes.values())

    def add_node(self, handle: RDANodeHandle) -> None:
        self._nodes[handle.node_id] = handle

    def remove_node(self, node_id: str) -> None:
        self._nodes.pop(node_id, None)

    def select(self, object_key: str, k: int) -> list[RDANodeHandle]:
        k = int(k)
        if k <= 0:
            raise RDAInvalidArgument("k must be > 0")
        if not self._nodes:
            raise RDARoutingError("no nodes registered")
        key = _sha3(object_key.encode())
        ranked = []
        for h in self._nodes.values():
            s = _score_rendezvous(key, h.node_id, self._salt)
            ranked.append((s, h))
        ranked.sort(key=lambda x: x[0], reverse=True)
        return [h for _, h in ranked[: min(k, len(ranked))]]


# ==============================================================================
# Storage blocks: replica envelopes, integrity, local node storage
# ==============================================================================


@dataclass(frozen=True)
class RDABlob:
    blob_id: str
    payload: bytes
    sha3: str
    created_at: float

    @staticmethod
    def from_payload(blob_id: str, payload: bytes) -> "RDABlob":
        return RDABlob(
            blob_id=blob_id,
            payload=payload,
            sha3="0x" + _sha3(payload).hex(),
            created_at=time.time(),
        )


@dataclass(frozen=True)
class RDAReplica:
    blob_id: str
    node_id: str
    stored_at: float
    sha3: str
    bytes_len: int


@dataclass
class RDANodeScore:
    node_id: str
    region: str
    capacity_bytes: int
    used_bytes: int
    health: float
    churn: float
    trust: float
    latency_ms: float
    last_audit_at: float

    def available_bytes(self) -> int:
        return max(0, int(self.capacity_bytes) - int(self.used_bytes))

    def composite(self) -> float:
        # A stable score: mostly trust/health, lightly weighted by availability and latency.
        avail = 0.0 if self.capacity_bytes <= 0 else self.available_bytes() / self.capacity_bytes
        return (
            (0.55 * self.trust)
            + (0.25 * self.health)
            + (0.12 * max(0.0, min(1.0, avail)))
            + (0.08 * (1.0 / (1.0 + max(0.0, self.latency_ms) / 75.0)))
            - (0.10 * max(0.0, min(1.0, self.churn)))
        )


class RDANode:
    """
    Local-only node: holds blobs in memory; can be configured to simulate faults.
    """

    def __init__(
        self,
        node_id: str,
        region: str,
        capacity_bytes: int,
        fault_rate: float = 0.0,
        jitter_ms: tuple[int, int] = (2, 12),
    ) -> None:
        self.node_id = node_id
        self.region = region
        self.capacity_bytes = int(capacity_bytes)
        self._fault_rate = float(fault_rate)
        self._jitter_ms = (int(jitter_ms[0]), int(jitter_ms[1]))
        self._store: dict[str, RDABlob] = {}
        self._replicas: dict[str, RDAReplica] = {}
        self._used = 0
        self._join_at = time.time()
        self._last_seen = time.time()
        self._audit_at = 0.0
        self._churn = 0.0
        self._trust = 0.84 + random.random() * 0.12
        self._health = 0.88 + random.random() * 0.10

    def _maybe_fault(self) -> None:
        if self._fault_rate <= 0:
            return
        if random.random() < self._fault_rate:
            raise RDAFault(f"RDA: simulated node fault ({self.node_id})")

    def _jitter(self) -> float:
        lo, hi = self._jitter_ms
        if hi <= lo:
            return float(lo)
        return float(random.randint(lo, hi))

    def score(self) -> RDANodeScore:
        now = time.time()
        alive = max(0.0, min(1.0, 1.0 - (now - self._last_seen) / 180.0))
        health = max(0.0, min(1.0, (0.7 * self._health) + (0.3 * alive)))
        churn = max(0.0, min(1.0, self._churn))
        trust = max(0.0, min(1.0, self._trust))
        latency = self._jitter()
        return RDANodeScore(
            node_id=self.node_id,
            region=self.region,
            capacity_bytes=self.capacity_bytes,
            used_bytes=self._used,
            health=health,
            churn=churn,
            trust=trust,
            latency_ms=latency,
            last_audit_at=self._audit_at,
        )

    def touch(self) -> None:
        self._last_seen = time.time()
        self._churn = max(0.0, min(1.0, self._churn * 0.92))

    def leave(self) -> None:
        # Mark as "churny" to bias placement away.
        self._churn = min(1.0, self._churn + 0.33)
        self._last_seen = time.time() - 10_000

    def has(self, blob_id: str) -> bool:
        return blob_id in self._store

    def put(self, blob: RDABlob) -> RDAReplica:
        self._maybe_fault()
        self.touch()
        if blob.blob_id in self._store:
            r = self._replicas[blob.blob_id]
            return r
        need = len(blob.payload)
        if need > self.capacity_bytes:
            raise RDAAdmissionDenied("RDA: object too large for node")
        if self._used + need > self.capacity_bytes:
            raise RDAAdmissionDenied("RDA: node out of capacity")
        self._store[blob.blob_id] = blob
        self._used += need
        rep = RDAReplica(
            blob_id=blob.blob_id,
            node_id=self.node_id,
            stored_at=time.time(),
            sha3=blob.sha3,
            bytes_len=need,
        )
        self._replicas[blob.blob_id] = rep
        return rep

    def get(self, blob_id: str) -> RDABlob:
        self._maybe_fault()
        self.touch()
        blob = self._store.get(blob_id)
        if blob is None:
            raise RDANotFound(f"RDA: blob not found on node {self.node_id}")
        if blob.sha3 != "0x" + _sha3(blob.payload).hex():
            raise RDAIntegrityError("RDA: blob integrity mismatch on node")
        return blob

    def delete(self, blob_id: str) -> bool:
        self._maybe_fault()
        self.touch()
        blob = self._store.pop(blob_id, None)
        self._replicas.pop(blob_id, None)
        if blob is None:
            return False
        self._used = max(0, self._used - len(blob.payload))
        return True

    def audit(self, sample: int = 12) -> tuple[int, int]:
        """
        Returns (checked, failures).
        """
        self.touch()
        self._audit_at = time.time()
        ids = list(self._store.keys())
        if not ids:
            return 0, 0
        random.shuffle(ids)
        checked = 0
        failures = 0
        for blob_id in ids[: max(1, min(sample, len(ids)))]:
            checked += 1
            blob = self._store[blob_id]
            if blob.sha3 != "0x" + _sha3(blob.payload).hex():
                failures += 1
        if failures > 0:
            self._health = max(0.0, self._health - 0.06 * failures)
            self._trust = max(0.0, self._trust - 0.04 * failures)
        else:
            self._health = min(1.0, self._health + 0.004)
            self._trust = min(1.0, self._trust + 0.002)
        return checked, failures


# ==============================================================================
# Placement policy: AI-ish scorer + constraints
# ==============================================================================


@dataclass(frozen=True)
class RDAPlacementPolicy:
    replicas: int
    write_quorum: int
    read_quorum: int
    max_region_skew: int
    min_trust: float
    prefer_regions: tuple[str, ...]
    codec: str
    chunk_size: int
    compress_level: int
    seal: bool


def rda_default_policy() -> RDAPlacementPolicy:
    # Kept deterministic, but not "minimal"—enough to have meaningful behavior.
    return RDAPlacementPolicy(
        replicas=5,
        write_quorum=3,
        read_quorum=2,
        max_region_skew=3,
        min_trust=0.55,
        prefer_regions=("na", "eu", "ap"),
        codec="zlib",
        chunk_size=48_000,
        compress_level=6,
        seal=True,
    )


class RDAPlacementEngine:
    def __init__(self, policy: RDAPlacementPolicy) -> None:
        self.policy = policy
        self._salt = _sha3((RDA_DOMAIN_SEED + ":" + hex(RDA_BUILD_NONCE)).encode())[:16]

    def rank_nodes(self, candidates: list[RDANodeScore], object_key: str) -> list[RDANodeScore]:
        """
        Produce a stable ranking incorporating rendezvous randomness + node score.
        """
        key = _sha3(object_key.encode())
        ranked: list[tuple[float, RDANodeScore]] = []
        for s in candidates:
            if s.trust < self.policy.min_trust:
                continue
            rv = _score_rendezvous(key, s.node_id, self._salt)
            rvf = (rv % 10_000_000) / 10_000_000.0
            region_bias = 0.0
            if s.region in self.policy.prefer_regions:
                idx = self.policy.prefer_regions.index(s.region)
                region_bias = 0.04 * (1.0 - idx / max(1.0, float(len(self.policy.prefer_regions))))
            score = s.composite() + 0.18 * rvf + region_bias
            ranked.append((score, s))
        ranked.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in ranked]

    def select_targets(self, nodes: list[RDANode], object_key: str) -> list[RDANode]:
        if not nodes:
            raise RDARoutingError("no nodes available")
        scores = [n.score() for n in nodes]
        ranked = self.rank_nodes(scores, object_key)
        if not ranked:
            raise RDAAdmissionDenied("no nodes satisfy trust policy")
        chosen: list[RDANode] = []
        region_counts: dict[str, int] = {}
        for s in ranked:
            n = next((x for x in nodes if x.node_id == s.node_id), None)
            if n is None:
                continue
            region_counts.setdefault(n.region, 0)
            # Avoid heavy skew: keep at least 2 regions when possible.
            if region_counts[n.region] >= self.policy.max_region_skew:
                continue
            if s.available_bytes() <= 0:
                continue
            chosen.append(n)
            region_counts[n.region] += 1
            if len(chosen) >= self.policy.replicas:
                break
        if len(chosen) < min(self.policy.replicas, len(nodes)):
            # Fall back to best remaining nodes (still filtered by trust).
            for s in ranked:
                if len(chosen) >= min(self.policy.replicas, len(nodes)):
                    break
                if any(n.node_id == s.node_id for n in chosen):
                    continue
                n = next((x for x in nodes if x.node_id == s.node_id), None)
                if n is None or s.available_bytes() <= 0:
                    continue
                chosen.append(n)
        if not chosen:
            raise RDAAdmissionDenied("no placement targets")
        return chosen


# ==============================================================================
# Cluster: orchestrates routing, replication, audits, and repairs
# ==============================================================================


@dataclass(frozen=True)
class RDAWriteReceipt:
    object_key: str
    manifest: RDAManifest
    manifest_digest: str
    stored_replicas: tuple[RDAReplica, ...]
    write_quorum: int


@dataclass(frozen=True)
class RDAReadReceipt:
    object_key: str
    size: int
    served_from: tuple[str, ...]
    repaired: bool
    manifest_digest: str


class RDACluster:
    def __init__(
        self,
        policy: RDAPlacementPolicy | None = None,
        *,
        cluster_id: str | None = None,
    ) -> None:
        self.policy = policy or rda_default_policy()
        self.cluster_id = cluster_id or rda_id_hex("rdaCluster", 12)
        self._log = RDAEventLog(cap=4096)
        self._nodes: dict[str, RDANode] = {}
        self._router = RDARouter(salt=_sha3((self.cluster_id + ":" + RDA_DOMAIN_SEED).encode())[:16])
        self._place = RDAPlacementEngine(self.policy)
        # Index: object_key -> manifest
        self._manifests: dict[str, RDAManifest] = {}
        # Reverse index: blob_id -> set(node_id)
        self._blob_index: dict[str, set[str]] = {}
        # A per-cluster secret for sealing payloads (simulation only).
        self._seal_key = _sha3((self.cluster_id + ":" + str(uuid.uuid4())).encode())
        self._log.emit(RDAEventKind.ROUTE_TRACE, None, {"cluster_id": self.cluster_id, "schema": RDA_SCHEMA})

    @property
    def log(self) -> RDAEventLog:
        return self._log

    def nodes(self) -> list[RDANode]:
        return list(self._nodes.values())

    def add_node(self, node: RDANode, weight: int = 100) -> None:
        self._nodes[node.node_id] = node
        self._router.add_node(RDANodeHandle(node_id=node.node_id, weight=int(weight), region=node.region))
        self._log.emit(RDAEventKind.NODE_JOIN, node.node_id, {"region": node.region, "capacity": node.capacity_bytes})

    def remove_node(self, node_id: str) -> None:
        n = self._nodes.pop(node_id, None)
        self._router.remove_node(node_id)
        if n is not None:
            n.leave()
        self._log.emit(RDAEventKind.NODE_LEAVE, node_id, {})

    def _register_replica(self, rep: RDAReplica) -> None:
        self._blob_index.setdefault(rep.blob_id, set()).add(rep.node_id)

    def _unregister_replica(self, blob_id: str, node_id: str) -> None:
        s = self._blob_index.get(blob_id)
        if not s:
            return
        s.discard(node_id)
        if not s:
            self._blob_index.pop(blob_id, None)

    def _encode_object(self, data: bytes) -> tuple[str, bytes, int]:
        original_size = len(data)
        codec = self.policy.codec
        if codec == "raw":
            return "raw", data, original_size
        if codec == "zlib":
            _, c = rda_compress(data, level=self.policy.compress_level)
            return "zlib", c, original_size
        raise RDAInvalidArgument(f"unsupported codec: {codec}")

    def _decode_object(self, codec: str, payload: bytes, original_size: int) -> bytes:
        dec = rda_decompress(codec, payload)
        return dec[:original_size]

    def _seal_if_needed(self, object_key: str, payload: bytes) -> tuple[bool, bytes, str, str]:
        if not self.policy.seal:
            return False, payload, "", ""
        ad = _sha3((self.cluster_id + "|" + object_key).encode())
        ct, mac = rda_seal(payload, key=self._seal_key, ad=ad)
        return True, ct, "0x" + ad.hex(), "0x" + mac.hex()

    def _open_if_needed(self, object_key: str, payload: bytes, sealed: bool, seal_ad: str, seal_mac: str) -> bytes:
        if not sealed:
            return payload
        if not (seal_ad.startswith("0x") and seal_mac.startswith("0x")):
            raise RDAIntegrityError("RDA: missing seal metadata")
        ad = bytes.fromhex(seal_ad[2:])
        mac = bytes.fromhex(seal_mac[2:])
        return rda_open(payload, mac=mac, key=self._seal_key, ad=ad)

    def put(self, object_key: str, data: bytes) -> RDAWriteReceipt:
        if not object_key or len(object_key) > 256:
            raise RDAInvalidArgument("object_key must be 1..256 chars")
        codec, encoded, original_size = self._encode_object(data)
        sealed, sealed_payload, seal_ad, seal_mac = self._seal_if_needed(object_key, encoded)

        chunks = rda_split_bytes(sealed_payload, self.policy.chunk_size)
        chunk_refs: list[RDAChunkRef] = []
        stored: list[RDAReplica] = []

        # Select nodes for each chunk independently to diversify placement.
        for idx, chunk in enumerate(chunks):
            blob_id = rda_id_hex("rdaBlob", 14) + f":{idx:04d}"
            blob = RDABlob.from_payload(blob_id, chunk)
            chunk_refs.append(RDAChunkRef(blob_id=blob_id, idx=idx, size=len(chunk), sha3=blob.sha3))

            targets = self._place.select_targets(self.nodes(), object_key=f"{object_key}#{idx}")
            acks = 0
            for n in targets:
                try:
                    rep = n.put(blob)
                except (RDAFault, RDAAdmissionDenied):
                    continue
                stored.append(rep)
                self._register_replica(rep)
                acks += 1
                if acks >= self.policy.write_quorum:
                    break

            if acks < self.policy.write_quorum:
                raise RDAQuorumError(
                    f"RDA: write quorum not met for chunk {idx} (acks={acks}, need={self.policy.write_quorum})"
                )

            self._log.emit(
                RDAEventKind.PUT_REPLICATED,
                None,
                {"object_key": object_key, "chunk": idx, "blob_id": blob_id, "acks": acks},
            )

        manifest = RDAManifest(
            object_key=object_key,
            codec=codec,
            original_size=original_size,
            chunk_size=self.policy.chunk_size,
            chunks=tuple(chunk_refs),
            sealed=sealed,
            seal_ad=seal_ad,
            seal_mac=seal_mac,
        )
        digest = manifest.digest()
        self._manifests[object_key] = manifest
        self._log.emit(
            RDAEventKind.PUT_ACCEPTED,
            None,
            {"object_key": object_key, "manifest": digest, "chunks": len(chunk_refs), "codec": codec, "sealed": sealed},
        )
        return RDAWriteReceipt(
            object_key=object_key,
            manifest=manifest,
            manifest_digest=digest,
            stored_replicas=tuple(stored),
            write_quorum=self.policy.write_quorum,
        )

    def _fetch_blob_quorum(self, blob_id: str, want_sha3: str) -> tuple[RDABlob, tuple[str, ...]]:
        hosts = sorted(self._blob_index.get(blob_id, set()))
        if not hosts:
            raise RDANotFound("RDA: no replicas indexed for blob")

        served: list[str] = []
        hits: list[RDABlob] = []
        for node_id in hosts:
            node = self._nodes.get(node_id)
            if node is None:
                continue
            try:
                blob = node.get(blob_id)
            except (RDAFault, RDANotFound):
                continue
            if blob.sha3 != want_sha3:
                continue
            hits.append(blob)
            served.append(node_id)
            if len(hits) >= self.policy.read_quorum:
                break
        if len(hits) < self.policy.read_quorum:
            raise RDAQuorumError(
                f"RDA: read quorum not met for blob {blob_id} (hits={len(hits)}, need={self.policy.read_quorum})"
            )
        # Deterministic pick: earliest created blob among quorum.
        hits.sort(key=lambda b: b.created_at)
        return hits[0], tuple(served)

    def get(self, object_key: str) -> tuple[bytes, RDAReadReceipt]:
        m = self._manifests.get(object_key)
        if m is None:
            raise RDANotFound("RDA: object manifest not found")
        got_chunks: list[bytes] = []
        served_all: list[str] = []
        repaired = False

        for cref in m.chunks:
            blob, served = self._fetch_blob_quorum(cref.blob_id, want_sha3=cref.sha3)
            got_chunks.append(blob.payload)
            served_all.extend(list(served))

        sealed_payload = b"".join(got_chunks)
        opened = self._open_if_needed(object_key, sealed_payload, sealed=m.sealed, seal_ad=m.seal_ad, seal_mac=m.seal_mac)
        decoded = self._decode_object(m.codec, opened, m.original_size)

        # Opportunistic repair: if any chunk has fewer replicas than desired, top it up.
        for cref in m.chunks:
            cur = self._blob_index.get(cref.blob_id, set())
            if len(cur) >= self.policy.replicas:
                continue
            repaired = True
            try:
                self._repair_blob(object_key, cref)
            except RDAFault:
                pass

        self._log.emit(
            RDAEventKind.GET_SERVED,
            None,
            {"object_key": object_key, "bytes": len(decoded), "served_from": len(set(served_all)), "repaired": repaired},
        )
        if repaired:
            self._log.emit(RDAEventKind.GET_REPAIRED, None, {"object_key": object_key})

        receipt = RDAReadReceipt(
            object_key=object_key,
            size=len(decoded),
            served_from=tuple(sorted(set(served_all))),
            repaired=repaired,
            manifest_digest=m.digest(),
        )
        return decoded, receipt

    def _repair_blob(self, object_key: str, cref: RDAChunkRef) -> int:
        blob, _served = self._fetch_blob_quorum(cref.blob_id, want_sha3=cref.sha3)
        targets = self._place.select_targets(self.nodes(), object_key=f"{object_key}#repair:{cref.idx}")
        placed = 0
        for n in targets:
            if n.node_id in self._blob_index.get(cref.blob_id, set()):
                continue
            try:
                rep = n.put(blob)
            except (RDAFault, RDAAdmissionDenied):
                continue
            self._register_replica(rep)
            placed += 1
            self._log.emit(
