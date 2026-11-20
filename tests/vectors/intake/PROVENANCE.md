# Intake vectors (shared with requisition-ts)

`intake.json` is written by requisition-ts's `tools/gen_python_vectors.py`, which runs this repository's own
`requisition_aws` code (`client.loads_tool_call`, the tool-call body reader, `canonical.check_arguments`, `canonical.encode`,
`canonical.ArgsSchema`) over raw JSON texts and argument objects and records each answer. requisition-ts commits the
same file, byte for byte, as `test/vectors/python/intake.json`, and replays it against its own intake.

requisition_aws tree: `9006aacc2210a0470fed1cc53503f47ff843522b` (`git rev-parse HEAD:requisition_aws`)

| file | SHA-256 |
|---|---|
| `intake.json` | `5905a2bc1c446da041b97c3eba378fe9f7887cb218f574db58cc8419241b9b1f` |

Never edit it by hand. `tests/test_intake_vectors.py` checks the SHA-256 above and replays every row against the
code in this checkout.
