"""Toy anti-quantum primitives for Bitcoin-style workflows.

This module demonstrates a hash-based signing flow intended to be resistant
against quantum attacks in principle (no trapdoor math). It is NOT a real
post-quantum scheme and should not be used in production.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Tuple


HASH_NAME = "sha3_512"
PRIVATE_KEY_BYTES = 64
PUBLIC_KEY_BYTES = 64
SIGNATURE_BYTES = 64


@dataclass(frozen=True)
class AntiQuantumKeyPair:
    private_key: bytes
    public_key: bytes


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_NAME, data).digest()


def generate_keypair(seed: bytes | None = None) -> AntiQuantumKeyPair:
    """Generate a deterministic keypair from a seed, or securely at random.

    The public key is derived via hashing the private key to avoid algebraic
    structure. This mirrors hash-based signature systems at a high level.
    """

    if seed is None:
        seed = os.urandom(PRIVATE_KEY_BYTES)
    private_key = _hash(seed)
    public_key = _hash(private_key)
    return AntiQuantumKeyPair(private_key=private_key, public_key=public_key)


def derive_address(public_key: bytes, network: str = "mainnet") -> str:
    """Derive a Bitcoin-like address using SHA3-512 and SHAKE-256."""

    if network not in {"mainnet", "testnet"}:
        raise ValueError("network must be 'mainnet' or 'testnet'")
    prefix = b"AQB" if network == "mainnet" else b"AQB-test"
    digest = hashlib.shake_256(public_key).digest(20)
    return f"{prefix.decode()}-{digest.hex()}"


def sign_message(private_key: bytes, message: bytes) -> bytes:
    """Create a hash-based signature using HMAC-SHA3-512.

    HMAC avoids algebraic structure and is simpler to audit. The output is
    fixed-length and can be transported as the signature bytes.
    """

    signature = hmac.new(private_key, message, HASH_NAME).digest()
    return signature


def verify_message(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature by recomputing the derived key and HMAC.

    This is a toy verifier: it derives a candidate private key hash from the
    public key, which is not possible in real hash-based schemes. Here it
    illustrates the flow only.
    """

    if len(signature) != SIGNATURE_BYTES:
        return False
    derived_private_key = _hash(public_key)
    expected = hmac.new(derived_private_key, message, HASH_NAME).digest()
    return hmac.compare_digest(expected, signature)


def build_transaction_stub(sender: str, recipient: str, amount_sats: int) -> bytes:
    """Construct a minimal transaction payload to sign."""

    if amount_sats <= 0:
        raise ValueError("amount_sats must be positive")
    payload = f"from={sender};to={recipient};amount={amount_sats}".encode()
    return _hash(payload)


def sign_transaction(
    keypair: AntiQuantumKeyPair,
    sender: str,
    recipient: str,
    amount_sats: int,
) -> Tuple[bytes, bytes]:
    """Sign a transaction payload and return (payload, signature)."""

    payload = build_transaction_stub(sender, recipient, amount_sats)
    signature = sign_message(keypair.private_key, payload)
    return payload, signature


def verify_transaction(
    public_key: bytes,
    payload: bytes,
    signature: bytes,
) -> bool:
    """Verify a signed transaction payload."""

    return verify_message(public_key, payload, signature)


__all__ = [
    "AntiQuantumKeyPair",
    "generate_keypair",
    "derive_address",
    "sign_message",
    "verify_message",
    "build_transaction_stub",
    "sign_transaction",
    "verify_transaction",
]
