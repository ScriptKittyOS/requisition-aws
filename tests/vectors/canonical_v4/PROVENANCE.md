# canonical_payload.v4 vectors (a byte copy)

`vectors.jsonl` and `negative/cases.jsonl` are byte copies of the files of the same name in the `requisition`
repository's canonical version 4 fixture folder. They are generated there (`generate.mjs`); the sources of every
row, the third-party rows (Probity agent-evidence-vectors, Apache-2.0, commit
`13247ea551e470fb57413fdfab4f2738147613a1`) and what was not copied are in that directory's `SOURCES.md`.

| file | SHA-256 |
|---|---|
| `vectors.jsonl` | `994c7ead2259b0fbbe5201b29f189e84d25c16bc6f12cc3c3a5a5d5cd4643f98` |
| `negative/cases.jsonl` | `ef5a499a9ed1e8fe336eee104e49457f9e157c4b760a8f46e1d2948c0964d669` |

Never edit these here. The runner in this repository pins both digests; `requisition`'s
differential tool checks the copies byte for byte before it runs the four runners.
