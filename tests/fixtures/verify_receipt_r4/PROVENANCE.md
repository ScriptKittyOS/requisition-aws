# verify_receipt.py as published in receipt-verification r4

`verify_receipt.py` is Requisition's released receipt verifier, `bench/holytrinity-v2/verifier/verify_receipt.py`, as
published in receipt-verification r4 (HolyTrinity-Benchmark tag `receipt-verification-r4`,
`receipt-verification/verifier/verify_receipt.py`), byte for byte:

```
6414bcb3f4a4a02c14a70ffe7e74dc6bb5b5725d6dc9f83ead38f5bd5286db8c  verify_receipt.py
```

`bin/vendor/ed25519_rfc8032.py` was derived from its lines 58 to 134 (`bin/vendor/VENDORED.md`);
`tests/test_verify_chain_vendored.py` checks the derivation against this copy.
