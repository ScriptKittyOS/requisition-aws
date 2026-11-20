# Real lab records (read-only copies)

Copied 2026-11-10, byte for byte (the key files' notes changed since, see the end), from records the Requisition lab
signed and the demo runs saved on 2026-11-09. Nothing here was produced by `tests/fake_requisition.py`.
No credentials: the files hold signed records (lab dev keys, `profile: lab`, `signer: dev`) and the
public key files served at `GET /v1/keys`; checked with `grep -E "rqc_|Bearer|password|secret"` (none).

| here | what it is |
|---|---|
| `dress-1/1-strands/0{1..4}-*.record.json` | the records the Strands demo saved in dress rehearsal 1 (local lab) |
| `dress-1/2-interceptor/0{1,2}-decision.record.json` | the records the interceptor demo saved in dress rehearsal 1 (the same record twice: the reused-id replay) |
| `dress-1/3-target/0{1..3}-*.record.json` | the records the target demo saved in dress rehearsal 1 |
| `dress-1/lab-keys.json` | the lab key file saved beside the Strands records of dress rehearsal 1 (byte-equal to the one saved beside the target records) |
| `aws-instance/20261109T213617Z/{statement,v0-4}.json` | the statement and decision one demo run saved against the lab instance of the AWS demo deployment |
| `aws-instance/20261109T214355Z/{statement,v0-6}.json` | the same, from a second run (its agent's records) |
| `aws-instance/instance-lab-keys.json` | that lab instance's key file (dev keys) |

Each record file is `{"record"|"statement"|"decision": <four-field envelope>, "cosignature": <ML-DSA-87 envelope>}`.
Every primary (Ed25519) signature and co-signature verified under its key file on 2026-11-10
(`requisition_aws.keys.KeyRegistry`).

The chains as saved (measured 2026-11-10):

* `dress-1`: scope `requisition-lab:account:8979bed4-...`, sequences 3, 4, 5, 6, 8, 9, 10, 11; each
  `previous_hash` links to the record before it except across 7, which no demo run saved (a real gap
  in what was kept, not in the lab's chain); 1 and 2 were not saved either.
* `aws-instance`: scope `requisition-lab:account:ca893414-...`, sequences 3, 4, 5, 6, linked; 1 and 2
  not saved.

sha256 (of the copies; equal to the sources, except the two key files, see below):

```
d8637dfe0601ca39db5c80c54023aac8adc31d9cbb9d7c8a5c41e07da17ea818  dress-1/1-strands/01-statement.record.json
df466a99d5df2dd49a8d21d8188a62ea2c4ad8050e0b79a46f279a425c21a6c1  dress-1/1-strands/02-decision.record.json
8fd78307f10077cd58a4e2d2f2d45f281f6d7591a71e35bd63e21889db13fcd2  dress-1/1-strands/03-outcome.record.json
75717777f09c6c0361bc9e4e8ccaea317d0f6491f3f7623c20de92bad9db26d3  dress-1/1-strands/04-decision.record.json
7ce3c6d97fc4f001d3e149c9cf717d9a6186bd3b20e448fa8f986a29348c30ab  dress-1/2-interceptor/01-decision.record.json
7ce3c6d97fc4f001d3e149c9cf717d9a6186bd3b20e448fa8f986a29348c30ab  dress-1/2-interceptor/02-decision.record.json
78886ce9e12e232b9f1c77efdf79578efe4911628cd23be2b4012f4590514375  dress-1/3-target/01-statement.record.json
fb2f79591c90a61e1951f3bd229e9188fc04ee9fa5bf415111170e47c794c8c0  dress-1/3-target/02-decision.record.json
28d5b2b112925f397a8781e8065aea67c54ded0ab49ffc5450f5e643dfc7b413  dress-1/3-target/03-outcome.record.json
400b726903417291d6a8f3e83958fabc2b739b93b10d1b8908d2799f069e9a26  dress-1/lab-keys.json
ca105a9b528c183c1aeeec7a492ff1a254783ae8099ccc76da8a3332c96b04ce  aws-instance/20261109T213617Z/statement.json
c16fd706d6a5dbeed094a0f0f1f967abc741feed9251cebef540248fe49babc5  aws-instance/20261109T213617Z/v0-4.json
e728a4fc8ff2962d27495e1bc1d9f328c58f0ab220319c17d9d8724597596b38  aws-instance/20261109T214355Z/statement.json
42550ed29a12bb2a8e9b6734151d412686b72d498cad23a61c0ccea209355433  aws-instance/20261109T214355Z/v0-6.json
c6c4dee2a4afd176e6b53168ca6a33c8f237a24ea0bb9f06c6a9f4eab6759ea9  aws-instance/instance-lab-keys.json
```

**Changed 2026-11-16: the two key files' notes.** In `dress-1/lab-keys.json` and
`aws-instance/instance-lab-keys.json`, each `note` member (three per file) began with an internal reference number;
that prefix was removed. A key file's note is not signed and no check reads it; every other byte of both files is as
saved (keys, fingerprints, windows, signers, statuses). Their sha256 above are of the changed files; the records are
unchanged.

**Changed 2026-11-19: the same notes again.** Each of those `note` members named the command of the issuing server
that made the key; it now says "the evaluation environment's key command". Nothing else changed, and the sha256
above are of the files as they are now.

`tests/test_verify_chain.py` reads these read-only (it copies before any tamper).
