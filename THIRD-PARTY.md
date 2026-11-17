# Third-party files

This repository is licensed under the Apache License 2.0 (`LICENSE`, `NOTICE`). The files below are not its own
work. Each keeps its own licence and carries no header of this repository.

| file | what it is | licence | licence text |
|---|---|---|---|
| `bin/vendor/mldsa.py` | mldsa-py 1.0.1 by Filippo Valsorda, `src/mldsa/mldsa.py`, byte for byte (`bin/vendor/VENDORED.md`) | CC0-1.0 OR 0BSD | the file's own header; `bin/vendor/LICENSE.mldsa` |
| `tests/vectors/mldsa87/wycheproof_mldsa_87_verify_test.json` | C2SP Wycheproof test vectors at commit `d17cc89f`, byte for byte (`tests/vectors/mldsa87/PROVENANCE.md`) | Apache-2.0 | `tests/vectors/mldsa87/LICENSE.wycheproof` |
| `tests/vectors/mldsa87/acvp_sigver_mldsa87_pure_external.json` | NIST ACVP-Server v1.1.0.43 test vectors, a subset (`tests/vectors/mldsa87/PROVENANCE.md`) | NIST-developed software notice | `tests/vectors/mldsa87/LICENSE.nist-acvp-server` |

`tests/fixtures/interceptor/*.json` are request and response shapes written from the examples in the Amazon Bedrock
AgentCore documentation; each file names its source page in `_source`.
