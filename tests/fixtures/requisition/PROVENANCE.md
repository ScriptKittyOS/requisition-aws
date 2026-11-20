# Two files of the Requisition repository, byte for byte

Copied from the Requisition repository (its files with the sha256 below), at the same relative paths, so that
`bin/lab-verify` finds `verify_receipt.py` where it looks for it (`../bench/holytrinity-v2/verifier/` from its own
folder). The tests run `bin/verify_offline.py` with this `bin/lab-verify` (its `--lab-verify`), and compare the key
rule's source text in it with `requisition_aws/keys.py` (`tests/test_key_rule.py`).

```
f1eb3e83eaca075343a88d4431de0ba0a893b3bf1a15bce9dabf7659acb28b94  bin/lab-verify
7eb65bcd2cf2d87e962e32603702315397b41c2d19d386629782e4713bc90351  bench/holytrinity-v2/verifier/verify_receipt.py
```

Requisition's own test suite checks that these two files are still byte copies of its own and that the sha256 lines
above are theirs; when Requisition changes either file, that check fails until the copies here are refreshed.
