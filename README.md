# Anti-Quantum Bitcoin (Toy)

This repository contains a **toy** hash-based signing flow for Bitcoin-style
transactions. It uses a Lamport one-time signature (OTS) scheme and a simple
Merkle tree for batching multiple OTS keys under a single address. This is
intended for education and experimentation only.

> ⚠️ **Do not use this code in production.**

## What this provides

- Lamport OTS key generation and signing
- Merkle tree aggregation for multiple signatures
- Minimal transaction payload creation and verification

## Usage

```python
from anti_quantum_bitcoin import (
    MerkleKeychain,
    generate_master_seed,
    sign_transaction,
    verify_transaction,
)

seed = generate_master_seed()
keychain = MerkleKeychain(seed=seed, height=4)
address = keychain.address()

payload, signature, public_key = sign_transaction(
    keychain,
    index=0,
    sender=address,
    recipient="AQB-0000000000000000000000000000000000000000",
    amount_sats=1000,
)

assert verify_transaction(public_key, payload, signature)
```

## Notes

- Lamport signatures are **one-time**: each OTS key must only sign a single
  message. The Merkle keychain helps manage many OTS keys.
- For real post-quantum deployments, use standardized algorithms (e.g.
  CRYSTALS-Dilithium or SPHINCS+) with vetted libraries.
