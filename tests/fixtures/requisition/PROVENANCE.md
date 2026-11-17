# Two files of the Requisition repository, byte for byte

Copied from the Requisition repository (its files with the sha256 below), at the same relative paths, so that
`bin/lab-verify` finds `verify_receipt.py` where it looks for it (`../bench/holytrinity-v2/verifier/` from its own
folder). The tests run `bin/verify_offline.py` with this `bin/lab-verify` (its `--lab-verify`), and compare the key
rule's source text in it with `requisition_aws/keys.py` (`tests/test_key_rule.py`).

```
deef717c897d2daa17597ebe7f2cca5ff96b4cef8b9b6875cc1e05b41d9b83f1  bin/lab-verify
162c2e4d1ee0a129e2cc6899e638ad67847896eb3605ba3338089c8906213539  bench/holytrinity-v2/verifier/verify_receipt.py
```

Requisition's own test suite checks that these two files are still byte copies of its own and that the sha256 lines
above are theirs; when Requisition changes either file, that check fails until the copies here are refreshed.
