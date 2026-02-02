"""Hash-based (post-quantum) signing primitives for Bitcoin-style workflows.

This module implements a Lamport one-time signature (OTS) scheme and a simple
Merkle-tree-based keychain for multiple signatures. Hash-based signatures are
believed to be resistant to quantum attacks (no trapdoor math), but this is
still an educational implementation and **not** production-ready.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

HASH_NAME = "sha3_256"
HASH_BYTES = 32
LAMPORT_BITS = 256
LAMPORT_PRIVATE_KEY_SIZE = LAMPORT_BITS * 2


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_NAME, data).digest()


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, HASH_NAME).digest()


def _chunked(iterable: Sequence[bytes], size: int) -> Iterable[Sequence[bytes]]:
    for i in range(0, len(iterable), size):
        yield iterable[i : i + size]


@dataclass(frozen=True)
class LamportPrivateKey:
    pairs: Tuple[Tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class LamportPublicKey:
    pairs: Tuple[Tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class MerkleKeychain:
    seed: bytes
    height: int

    def leaf_count(self) -> int:
        return 1 << self.height

    def public_key(self, index: int) -> LamportPublicKey:
        private_key = generate_lamport_private_key(self._derive_seed(index))
        return derive_lamport_public_key(private_key)

    def address(self) -> str:
        root = merkle_root(self.leaf_hashes())
        return f"AQB-{root.hex()}"

    def leaf_hashes(self) -> List[bytes]:
        return [self._leaf_hash(i) for i in range(self.leaf_count())]

    def _leaf_hash(self, index: int) -> bytes:
        public_key = self.public_key(index)
        return hash_public_key(public_key)

    def _derive_seed(self, index: int) -> bytes:
        if not 0 <= index < self.leaf_count():
            raise ValueError("index out of range for keychain")
        index_bytes = index.to_bytes(4, "big")
        return _hmac(self.seed, b"lamport-ots" + index_bytes)


def generate_master_seed() -> bytes:
    return os.urandom(HASH_BYTES)


def generate_lamport_private_key(seed: bytes) -> LamportPrivateKey:
    if len(seed) != HASH_BYTES:
        raise ValueError(f"seed must be {HASH_BYTES} bytes")
    pairs: List[Tuple[bytes, bytes]] = []
    for i in range(LAMPORT_PRIVATE_KEY_SIZE):
        key_material = _hmac(seed, i.to_bytes(4, "big"))
        if i % 2 == 0:
            pairs.append((key_material, b""))
        else:
            left, _ = pairs[-1]
            pairs[-1] = (left, key_material)
    return LamportPrivateKey(pairs=tuple(pairs))


def derive_lamport_public_key(private_key: LamportPrivateKey) -> LamportPublicKey:
    public_pairs = tuple((_hash(left), _hash(right)) for left, right in private_key.pairs)
    return LamportPublicKey(pairs=public_pairs)


def hash_public_key(public_key: LamportPublicKey) -> bytes:
    flattened = b"".join(left + right for left, right in public_key.pairs)
    return _hash(flattened)


def sign_message(private_key: LamportPrivateKey, message: bytes) -> Tuple[bytes, ...]:
    digest = _hash(message)
    bits = bin(int.from_bytes(digest, "big"))[2:].zfill(LAMPORT_BITS)
    signature = []
    for bit, (left, right) in zip(bits, private_key.pairs):
        signature.append(left if bit == "0" else right)
    return tuple(signature)


def verify_message(
    public_key: LamportPublicKey,
    message: bytes,
    signature: Sequence[bytes],
) -> bool:
    if len(signature) != LAMPORT_BITS:
        return False
    digest = _hash(message)
    bits = bin(int.from_bytes(digest, "big"))[2:].zfill(LAMPORT_BITS)
    for bit, sig, (left, right) in zip(bits, signature, public_key.pairs):
        expected = left if bit == "0" else right
        if _hash(sig) != expected:
            return False
    return True


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        raise ValueError("leaves must not be empty")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for left, right in _chunked(level, 2):
            next_level.append(_hash(left + right))
        level = next_level
    return level[0]


def build_transaction_stub(sender: str, recipient: str, amount_sats: int) -> bytes:
    if amount_sats <= 0:
        raise ValueError("amount_sats must be positive")
    payload = f"from={sender};to={recipient};amount={amount_sats}".encode()
    return _hash(payload)


def sign_transaction(
    keychain: MerkleKeychain,
    index: int,
    sender: str,
    recipient: str,
    amount_sats: int,
) -> Tuple[bytes, Tuple[bytes, ...], LamportPublicKey]:
    payload = build_transaction_stub(sender, recipient, amount_sats)
    private_key = generate_lamport_private_key(keychain._derive_seed(index))
    signature = sign_message(private_key, payload)
    public_key = derive_lamport_public_key(private_key)
    return payload, signature, public_key


def verify_transaction(
    public_key: LamportPublicKey,
    payload: bytes,
    signature: Sequence[bytes],
) -> bool:
    return verify_message(public_key, payload, signature)


__all__ = [
    "HASH_NAME",
    "HASH_BYTES",
    "LamportPrivateKey",
    "LamportPublicKey",
    "MerkleKeychain",
    "generate_master_seed",
    "generate_lamport_private_key",
    "derive_lamport_public_key",
    "hash_public_key",
    "sign_message",
    "verify_message",
    "merkle_root",
    "build_transaction_stub",
    "sign_transaction",
    "verify_transaction",
]
