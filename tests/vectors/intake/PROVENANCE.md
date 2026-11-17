# Intake vectors (shared with requisition-ts)

`intake.json` is written by requisition-ts's `tools/gen_python_vectors.py`, which runs this repository's own
`requisition_aws` code (`client.loads_tool_call`, the tool-call body reader, `canonical.check_arguments`, `canonical.encode`,
`canonical.ArgsSchema`) over raw JSON texts and argument objects and records each answer. requisition-ts commits the
same file, byte for byte, as `test/vectors/python/intake.json`, and replays it against its own intake.

requisition_aws tree: `d7c9330bbdf5d28edfa97d30f93647c94cfcfcf5` (`git rev-parse HEAD:requisition_aws`)

| file | SHA-256 |
|---|---|
| `intake.json` | `bd6888a77c5624057bdd21269eae9ebb6e22ef4670b90bea93e39c2b537e2418` |

Never edit it by hand. `tests/test_intake_vectors.py` checks the SHA-256 above and replays every row against the
code in this checkout.
