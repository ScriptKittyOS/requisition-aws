# The Ed25519 public key of an AWS KMS signing key of Requisition's evaluation environment

`ed25519-public-key.json` holds one entry of the key file of Requisition's evaluation environment, as of 2026-11-10:
the Ed25519 public key that an AWS KMS key of the evaluation environment returned through `GetPublicKey`, with its
signer label (the key file's fingerprint of it, the sha256 of the 32 key bytes, was checked equal and is left out).
The entry's key id, its note and the key's ARN are left out: they name a real AWS account. A public key is published
by design. This one is kept so that `tests/test_ed25519_material.py` checks an Ed25519 key that AWS KMS made for the
evaluation environment against the prime-order rule.

```
4069a51e362fb8c5376f9206efb50ca3cc2c769defb977daac6b12eeae1828bb  ed25519-public-key.json
```
