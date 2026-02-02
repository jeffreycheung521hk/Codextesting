# Anti-Quantum Bitcoin (Toy)

This repository contains a **toy** "anti-quantum" signing flow for Bitcoin-style
transactions. It is designed for educational exploration only and **must not**
be used for real funds or security-critical systems.

## What this provides

- Hash-based key derivation with SHA3-512
- Address derivation with SHAKE-256
- HMAC-based signing for fixed-size signatures
- Minimal transaction payload creation and verification

## Usage

```python
from anti_quantum_bitcoin import (
    generate_keypair,
    derive_address,
    sign_transaction,
    verify_transaction,
)

keypair = generate_keypair()
address = derive_address(keypair.public_key)

payload, signature = sign_transaction(
    keypair,
    sender=address,
    recipient="AQB-0000000000000000000000000000000000000000",
    amount_sats=1000,
)

assert verify_transaction(keypair.public_key, payload, signature)
```

## Notes

- The verifier intentionally cuts corners to keep the example small. Real
  post-quantum signature systems do **not** allow reconstructing the private
  key from the public key.
- If you need a real post-quantum scheme, consider standardized algorithms like
  CRYSTALS-Dilithium or SPHINCS+ and use vetted libraries.
