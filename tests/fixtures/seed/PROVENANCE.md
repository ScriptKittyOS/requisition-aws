# The lab seed that registers `payments.refund_send` (schema version 1)

`aws_demo.v1.json` is the seed file (last written 2026-11-09) from which the demo lab registers
`payments.refund_send` (README, "Running the demo", precondition 1), in Requisition's `requisition.lab.seed.v1`
format; the demos read the seed file the operator names (`--seed`, or `REQUISITION_SEED`), and a dry rehearsal
reads this copy. It is in no Requisition commit. Its top-level `note`, which pointed at a private planning document, is left out; `schema`,
`set` and `act_types` are unchanged. The sha256 of `act_types` written as sorted, compact JSON is the same in the
original and here:

```
c603ddad61fa5de5a63c3ec369634071c5ea0517d08df3b16f51e161607fd76b  act_types (sorted keys, separators "," ":")
91869d4fb510e449499cd751b4c2020675c01900fdd0f704e5a2c46bac89cbe5  aws_demo.v1.json
```

`tests/test_canonical.py` checks that the tests' copy of the display schema (`SEED_SCHEMA`) is this file's.
