# requisition-aws

AWS demo adapters for Requisition: a Strands Agents hook, an AgentCore Gateway REQUEST interceptor,
and an offline check. They let an agent's tool call run only on Requisition's signed `allow` for
that call's exact arguments.

Every Requisition feature these adapters use belongs to Requisition's evaluation environment: the
`/v1` API, the records it signs (Ed25519, with an ML-DSA-87 co-signature when one is configured,
under development keys or AWS KMS keys), and its single-use execute. A production release of
Requisition does not serve `/v1`, and it signs its own receipts with Ed25519 under a key it reads
from its environment.

**Licence:** Apache License 2.0 (`LICENSE`, `NOTICE`). Third-party files keep their own licences; they are
listed in `THIRD-PARTY.md`.

## The pieces

| file | what it is |
|---|---|
| `requisition_aws/canonical.py` | A port of Requisition's `CanonicalPayload` v3 encoder and of `act_hash` (`sha384+canonical_payload.v3`: SHA-384 of v3 over the arguments with `act_type` put inside). It also ports the intake rules: a float anywhere in the arguments refused `float_refused` (with its path, before any other check), Unicode Cc/Cf/Zl/Zp refused, NFC required, and the redactor's patterns (`display_value_redactable`). Every refusal happens **before** anything is sent, never as a truncation. |
| `requisition_aws/client.py` | A stdlib HTTP client for the lab `/v1` API: propose, get request, execute, keys. It can also use a Unix socket. |
| `requisition_aws/store.py` | The idempotency store. It is a local JSON file with flock-guarded atomic conditional writes. It holds `request_id`s keyed on `act_hash`, the exact execute body bytes keyed on the call's idempotency key, and the hook's "tool ran" marks. |
| `requisition_aws/gate.py` | The flow both adapters share: deduplicated propose, the sanction read, idempotent execute, and a check of every signed record against what was sent. |
| `requisition_aws/strands_hook.py` | A Strands `HookProvider`. The flow is: propose, then `event.interrupt` with `{request_id, approval_url}`, then resume, then the hook re-reads the request, then execute, then the tool runs only on a signed allow. `AfterToolCallEvent` sets the "tool ran" mark. Every other outcome is `cancel_tool` (fail closed). |
| `requisition_aws/interceptor.py` | A Lambda handler for an AgentCore Gateway REQUEST interceptor on MCP targets. It is **not deployed**. |
| `requisition_aws/registry.py` | The tool to act type registry. An unregistered tool is denied. |
| `requisition_aws/scripted_model.py` | A Strands `Model` with no network, used by the tests and by `--scripted`. |
| `requisition_aws/demo_flow.py` | The demo's app loop: print the link, poll, resume, replay, verify, write the transcript. |
| `bin/verify_offline.py` | Stdlib plus one vendored file; run it with `python3 -I`. It recomputes `act_hash` and the arguments digest from the arguments the approvers were shown, compares them with the signed record, then runs Requisition's unchanged `bin/lab-verify`. For an ML-DSA-87 record, or a record's ML-DSA-87 co-signature, it checks the post-quantum signature itself. `--require-pq` makes that signature mandatory. |
| `bin/vendor/mldsa.py` | Filippo Valsorda's pure-Python ML-DSA verifier (PyPI `mldsa` 1.0.1, CC0-1.0 OR 0BSD), byte for byte, loaded by path under a pinned SHA-256. See `bin/vendor/VENDORED.md`. |
| `requisition_aws/mcp_target.py` | **Requisition as the AgentCore Gateway target.** An MCP server (Streamable HTTP; 2026-07-28 and the 2025 versions) that owns the refund tool and runs it only on a signed allow it has checked. It writes `REFUND SENT` to a local ledger, then reports the outcome. `deploy/target/Dockerfile` packages it for AgentCore Runtime (ARM64, `0.0.0.0:8000/mcp`). Not built for ARM64 and not deployed. |
| `requisition_aws/pq.py` | The package's loader for the vendored verifier. `keys.KeyRegistry` uses it for `mldsa87` key entries. |
| `requisition_aws/target_flow.py` | The target form's demo loop. It speaks MCP to the served target over HTTP, as a Gateway would. |
| `demo/run_demo.py` | The Strands demo (`--airgap`; `--require-pq`, default on, applies at run time and in the offline check; `REQUISITION_LAB_KEY_FILE` required and compared with `GET /v1/keys`). |
| `demo/run_interceptor_local.py` | The interceptor demo. |
| `demo/run_target_local.py` | The target-form demo. |
| `demo/run_airgap.py` | Re-checks a finished run's records in `docker run --rm --network none` after a network probe, then shows a one-character change FAIL. |
| `requisition_aws/fence.py` | **F1, the relying party's own memory.** Every signed record a form reads (statement, decision, outcome) is remembered by its signed `(chain_scope, sequence)`; a different record at a held position is refused `authority_equivocated` and both are kept as evidence. Before acting on an allow, every form claims the statement **and** the `approval_request_id` it names, so a re-minted statement for an approval already acted on is refused `approval_already_used`. `Store.admit` does all of it in one transaction, persisted before the effect. No ordering rule: the lab's chain is the whole account's, so gaps are normal. |
| `bin/verify_chain.py` | **F1b, a stranger's offline check** of one account chain export against held records (a relying party's position memory or evidence): `link_broken`, `sequence_gap`, `sequence_duplicate`, `export_not_from_genesis`, `held_record_differs`, `export_short`, `equivocation`, `signature_invalid`, `held_record_invalid`, `held_other_scope`, `pq_missing`. Stdlib plus two pinned vendored files: the Ed25519 routine copied from Requisition's `verify_receipt.py`, and `mldsa.py`. Active keys only: a chain with records under a rotated key FAILs `signature_invalid` for them. It judges the export it is given, not the live service. |
| `bin/export_chain.sh` | The read-only SQL export of one account chain (`psql`, a READ ONLY transaction, `COPY (SELECT ... ORDER BY sequence) TO STDOUT` as CSV; the scope only as a `psql` variable). Point it at a `bin/scratch-db` copy or the demo database. |
| `demo/run_rollback_local.py` | **The rollback demo, local only.** It runs inside Requisition's `bin/scratch-db` (a database created for the run and dropped after it) on a copy of the demo database, with a second server on another port (`demo/rollback/serve_scratch.exs`). The refund runs once; the database is restored to before the mint; the restored service re-mints and would allow again; the target refuses `authority_equivocated`; `verify_chain.py` FAILs the restored export. `--dry-run` checks the copy and the restore round trip without a server. Its claim, word for word: "If Requisition's database is rolled back, the same executor, with its own records intact, refuses to act again, and the rollback leaves two different records signed by the service's key at one chain position, which anyone can check offline. Lab profile, lab key. (when nothing was appended between the snapshot and the mint; step 7 checks this and stops otherwise)." |
| `demo/rehearse.sh` | The one-command dress rehearsal: the Strands demo, the interceptor, the target, then the airgap check. Each step prints a short transcript through `demo/present.py`, with credentials elided. `REHEARSE_DRY=1` runs all four against a local fake. |

## Install

The package is `requisition_aws`; its one dependency outside the standard library is `cryptography`. The wheel also
carries the vendored ML-DSA verifier (`bin/vendor/mldsa.py`) inside the package. From PyPI:

```sh
python3 -m pip install requisition-aws==0.1.0
```

On a machine without network access, use the release's offline bundle: the wheel, the wheel of every dependency,
and a `requirements.txt` that pins each of them by SHA-256. In the unpacked bundle:

```sh
python3 -m venv .venv
.venv/bin/pip install --no-index --find-links wheels --require-hashes -r requirements.txt
```

pip installs only files whose SHA-256 is listed, and `--no-index` keeps it off the network. The bundle's `README.md`
says how to check the bundle itself before installing. The scripts in `bin/` and `demo/` are not in the wheel; they
are in the source archive and in this repository.

## Tests

```sh
uv sync
uv run pytest -q
```

The tests run against an in-process fake of `/v1` (`tests/fake_requisition.py`). The fake follows the
cited code's rules: nonce claims and exact retry by body digest, a single spend, and Ed25519-signed
lab records. The tests never write to a running Requisition, and they need no Requisition checkout: what they
use of Requisition is committed under `tests/fixtures/`, each folder with a `PROVENANCE.md` that names its source
and sha256:

- **`tests/fixtures/requisition/`**: Requisition's `bin/lab-verify` and the `verify_receipt.py` it runs, byte for
  byte, with their sha256 in that folder's `PROVENANCE.md`. The real `bin/lab-verify` checks records that the fake signed.
- **`tests/fixtures/seed/`**: the lab seed whose `display_schema` is compared with the test copy.
- **`tests/fixtures/verify_receipt_r4/`**: the source of the vendored Ed25519 routine.

What compares this repository with Requisition's own files (that the copies above are still Requisition's, the
key-rule texts and vector file, the act hash over Requisition's vectors V1 and V2, which are **never copied here**
because their arguments are effector material, and the published kit's record) runs in Requisition's test suite,
where both trees are present.

The ML-DSA-87 verifier is checked against these vectors (provenance in `tests/vectors/mldsa87/PROVENANCE.md`):

- NIST ACVP sigVer, ML-DSA-87 pure external, at ACVP-Server `975de31e`.
- All 241 Wycheproof ML-DSA-87 verify vectors at `d17cc89f`. They include tcId 21, the repeated hint (the class of CVE-2026-24850).

It is also compared with two other implementations:

- `cryptography`'s ML-DSA-87, live.
- Erlang/OTP 28.5.0.8 `:crypto` over OpenSSL 3.5.9. The run is recorded in `tests/otp/` and re-run when that toolchain is present.

The fake also produces four shapes that the Requisition version it follows (of 2026-10-26) does not have (the co-signature, the outcome record, the act_hash lookup and the propose idempotency key), behind `newer_routes=True` and `cosign=...`, and the tests label them that way.

`tests/fixtures/elixir_differential/` holds answers from the compiled Requisition modules:
4,010 redactor strings and 1,500 encoder terms. `PROVENANCE.md` there records how they were made:
plain `elixir -pa`, so no app started and no database was opened.

## Running the demo

Preconditions are on the demo database (`autonomous_agency_aws_demo`, server on `127.0.0.1:4103`):

1. `payments.refund_send` is registered from `lab/seed/aws_demo.v1.json`.
2. A caller grant covers that act type at class `high` or above, with scope `propose_execute`.
3. You have that grant's credential and principal.

```sh
cd requisition-aws
export REQUISITION_DEMO_DIR=/path/to/demo     # required: req/ is a Requisition checkout; transcripts go to log/
# export REQUISITION_LOAD_WRAPPER=/path/to/cmd # optional: a command placed before docker (--airgap)
export REQUISITION_URL=http://127.0.0.1:4103
export REQUISITION_CRED='rqc_...'        # never printed; elided from the transcript
export REQUISITION_PRINCIPAL='rqp_...'
# export REQUISITION_SOCKET=/path.sock   # only if the server runs with REQUISITION_LAB_SOCKET=true
uv run python demo/run_demo.py --scripted \
  --transcript "$REQUISITION_DEMO_DIR/log/demo-scripted.txt"     # no model
uv run python demo/run_demo.py \
  --transcript "$REQUISITION_DEMO_DIR/log/demo-live.txt"         # Bedrock
```

What each mode uses:

- **Live mode** uses Amazon Bedrock `openai.gpt-oss-120b-1:0` in `us-east-1` through the AWS
  profile named by `AWS_PROFILE` (boto3's default chain when unset), with synthetic prompts only.
- **`--scripted`** calls no model. It drives the same hook path, with the same interrupt and resume.

When the agent's tool call is held, the run prints `APPROVE AT http://127.0.0.1:4103/approvals`. Two
approver accounts approve in the console. The app polls `GET /v1/sanction-requests/<id>`, resumes,
and the stub prints `REFUND SENT` only on a signed allow. The run then executes the same statement
under a fresh nonce, which is a signed deny `statement_spent`. Finally it checks every record
offline. Records, the pinned `GET /v1/keys` file and the store go to `<transcript>-records/`.

Check before the live run:

- **Time limits.** The statement expires 300 s after the second approval. A row with
  `sanctioners_required >= 2` takes the first time line (`vocabulary.ex:40`, `:86-87`). An allow's
  `exec_not_after` is at most 60 s after the decision (`execute.ex:601-605`).
- **The key file.** `cmp <records>/lab-keys.json "$REQUISITION_LAB_KEY_FILE"` must report the same
  bytes.
- **The model.** Whether gpt-oss calls tools through Strands' Bedrock provider is unverified.
  The model may also write a `reason` that the redactor refuses, such as anything containing `sk-`
  (`task-`, `disk-`) or "secret". The hook then cancels with the code, and nothing is proposed.

## The dress rehearsal

```sh
export REQUISITION_DEMO_DIR=/path/to/demo     # as above; REQUISITION_LOAD_WRAPPER too, if you use one
# required: demo/rehearse.sh has no default and stops without it
export REQUISITION_URL=http://127.0.0.1:4103 REQUISITION_CRED='rqc_...' REQUISITION_PRINCIPAL='rqp_...'
export REQUISITION_LAB_KEY_FILE=...   # required: steps 1 and 3 refuse unless GET /v1/keys serves these bytes;
                                      # step 2 checks every signature against this file
demo/rehearse.sh                      # STRANDS_MODE=scripted to skip Bedrock
                                      # REQUIRE_PQ=0 against a server without co-signatures: with 1 (the default)
                                      # all three forms refuse, AT RUN TIME, any record without a checked
                                      # ML-DSA-87 signature, and the offline and airgap checks fail it
REHEARSE_DRY=1 demo/rehearse.sh       # a dry run: a local fake /v1 that auto-approves; no lab, no Bedrock
```

What each part does:

- Each step stops at `APPROVE AT` until two approver accounts approve.
- Full transcripts and records go to `$OUT`, by default `$REQUISITION_DEMO_DIR/log/rehearsal-<UTC>/`.
- Step 4 runs docker after `REQUISITION_LOAD_WRAPPER` when it is set.

## Requisition as the Gateway target (not deployed)

**Why an MCP server target on AgentCore Runtime, not a Lambda target** (AWS docs, fetched 2026-11-09, cited in
`mcp_target.py`):

- **Lambda target.** It receives only the tool arguments, plus gateway, target and request ids. AWS does not
  document how a returned error reaches the agent.
- **MCP server target.** It returns its own `CallToolResult`, so "awaiting approval", a signed deny and
  "Requisition unavailable" each reach the agent as `isError` results.
- **Outbound auth.** On Runtime the target takes IAM (SigV4) outbound auth, so the hop from the Gateway to the
  tool needs no stored secret.

The tool runs **only** on a checked allow, before its `exec_not_after`, and **at most once per statement**:

- The run is claimed in the store first.
- A Gateway retry of the same invocation returns the stored result. The tool does not run again.
- A crash mid-run leaves the claim. The call then fails closed and the tool does not run twice.

## The interceptor's configuration (not deployed)

| variable | meaning |
|---|---|
| `REQUISITION_URL`, `REQUISITION_CRED`, `REQUISITION_PRINCIPAL` | The `/v1` caller. |
| `REQUISITION_GATEWAY_ID` | This gateway's id, set at deploy. It is used instead of `GATEWAY_ARN`, which is documented for HTTP targets only. |
| `REQUISITION_TOOLS` | JSON mapping `{"<target>___<tool>": "<act type>"}`. AWS's tool naming is `${target_name}___${tool_name}`. A v2 act type that pins several tool digests takes `{"act_type": ..., "tool_digest": "<this gateway's digest>"}` (G2). |
| `REQUISITION_CALLER_SOURCE` | `legacy_session` (the default, the pre-G1 behaviour), `sigv4` (the SigV4 access-key id of the forwarded `Authorization`), or `jwt` (with `REQUISITION_JWT_ISSUER`, `REQUISITION_JWT_JWKS_FILE`, and `REQUISITION_JWT_AUDIENCE` and/or `REQUISITION_JWT_CLIENTS`). Any other value refuses to start. See `requisition_aws/caller.py`. |
| `REQUISITION_SEED` | The lab seed file holding each act type's `display_schema`. |
| `REQUISITION_STORE` | The idempotency store path. |
| `REQUISITION_AGENT` | The `agent` member of the arguments object. |
| `REQUISITION_APPROVAL_BASE` | The console base URL used in approval links. |
| `REQUISITION_KEYS_FILE` | **Required.** The pinned lab key file. Without it the handler refuses every call. Every statement and decision signature is checked against it, and an allow whose signature was not checked is never passed through. |
| `REQUISITION_REQUIRE_PQ` | Default `1`: every record must carry an ML-DSA-87 signature checked here (the record's own, or its co-signature). Set `0` only against a server without co-signatures. |
| `REQUISITION_ALLOW_PLAINTEXT_PRIVATE` | `1` allows `http://` to a private or link-local IP literal (the VPC case). Otherwise `REQUISITION_URL` must be `https`, unless the host is loopback. |

The interceptor needs `passRequestHeaders: true`. Without the caller's header (`Mcp-Session-Id` under
`legacy_session`, `Authorization` under `sigv4` or `jwt`), it refuses every `tools/call` with
`caller_identity_absent`, fail closed.

Every `tools/call` logs the names of the request's headers, never their values. Whether the Gateway
forwards the SigV4 `Authorization` under AWS_IAM has not been measured yet. One live call shows it,
and until then the default stays `legacy_session`.

Methods are denied by default. Only `initialize`, `ping`, `notifications/*`, `tools/list` and
`server/discover` pass through. Every other method gets JSON-RPC -32601, including `resources/*`, `prompts/*`,
`completion/complete`, `subscriptions/listen` and `logging/setLevel`.

Each method on it is one an agent needs in order to call a
gated tool, and none of them reaches an effect. The cost: a 2026-07-28 client cannot subscribe to `list_changed`
notifications through this Gateway (`subscriptions/listen`), so it has to list again.

For a v2 act type that pins tool digests (G2, `requisition_aws/catalog.py`):

- The RESPONSE interception point on `tools/list` withholds a drifted tool and marks it. The mark is keyed by
  gateway id, tool and pin, so a re-pin (a new registration, which two approver accounts approve) is not blocked
  by the old pin's mark.
- A later call to a marked tool is refused. A marked tool is also withheld from every later listing.
- Only the operator clears a mark: `python -m requisition_aws.catalog --clear-mark <gateway-id> <tool> --store PATH`
  Each clear is appended to `catalog_marks_cleared` as `<mark key>:<n>` and never overwritten.
  Clearing approves nothing. The tool waits as `catalog_recheck_pending`, and calls are refused, until the next
  `tools/list` re-checks it: a tool still drifted is re-marked, and the registered definition is served.
- The deployed gateway has no RESPONSE point yet. Adding it is part of
  `deploy/gateway/g12-change-set.sh`, run by the operator of the Gateway's stack.

The fixtures under `tests/fixtures/interceptor/` are each labelled "AWS documented shape, fetched
2026-11-09, not a live Gateway", with their source URLs.

## Limits, stated

- **Authorization, not execution.** The record proves the act was **authorized once**. It does not
  prove that it ran.
- **The key.** The demo key is a **lab key** served by the lab. It is not a trust root:
  `bin/lab-verify` says `DEGRADED (lab)`, `verdict_code: lab_dev_key`, exit 5.
- **The hook form.** The Strands hook runs **in the agent's own process**, so a compromised agent
  can skip it. The interceptor and target forms do not have this weakness.
- **Spend before effect.** A statement spent in a REQUEST interceptor stays spent even if AgentCore
  Policy then denies or the target fails. Only the target form binds the spend to the effect.
  - **At most one pass-through per statement, always.** The interceptor writes a durable "passed" mark per statement before it passes a call
    through. Any later invocation that resolves to the same statement is refused with "this approval
    was already used; a new call needs a new approval": a client reusing its JSON-RPC id, a Gateway
    retry, anything. Requisition answers an exact execute retry with the stored allow and no spend
    check (`execute.ex:606-642`), so this mark is what stops a replay.
  - **A Gateway retry after a timed-out first pass-through is therefore refused** (fail closed). The
    approval may be lost and the agent must file again. Only the target form binds the spend to the
    effect.
  - `exec_not_after` is checked on every allow, replayed or not.
- **Removing the interceptor.** Anyone with `UpdateGateway` can remove the interceptor, and then
  calls leave no record at all. Detecting the absence rests on the outcome record (`POST /v1/outcomes`).
- **The store.** The idempotency store is one local file:
  - the single-use claims (the interceptor's "passed" mark, the hook's and the target's "ran"
    claims, each taken before the effect) are per host;
  - a Lambda's `/tmp` is per execution environment;
  - a deployment on AWS needs a durable conditional-write store; none is built here.
- **Approvers.** The demos' acts are approved by two separate accounts ("two approver accounts"), held by one
  person in the lab (the signed records' `hands` member says so). Web sign-in has no second factor.
- **Single use.** In Requisition's evaluation environment, where its execute API runs, single use holds
  within one database, not across a restore or clone, and that stays open at Requisition. F1 (`fence.py`) adds a refusal by **the executor
  that already acted, with its store intact**: after a rollback the restored service re-mints the approval under a new statement id, and that
  executor refuses it (`authority_equivocated` when the re-mint lands at a position it holds,
  `approval_already_used` otherwise). Not covered:
  - **a different executor** with its own store never saw the first use (open until decisions name their one
    audience);
  - **the deployed Lambda interceptor and the AgentCore Runtime target make NO rollback claim**: their
    store is `/tmp`, per execution environment or microVM, so the memory is lost with it (until their
    store is durable). The claim holds for the Strands hook and the local
    target and interceptor runs, whose store survives;
  - the evidence is two records signed by **the lab key** at one position: it shows that the holder of
    that key signed two histories (lab profile), not a general proof of rollback.
- **The outcome record.** The outcome record is **the caller's report, not proof** that the effect happened.
  The target form is the one that binds the effect to the allow, because the tool runs inside the target.
- **The ML-DSA-87 check.** The vendored verifier checks only ML-DSA-87, pure, with an empty context. Both of
  the lab's keys are dev keys, not trust roots.
- **The approval link.** `GET /v1/sanction-requests/:id` does not return the approval request id
  while a request is pending (`sanction_requests.ex:492`). Until the statement exists, the link is
  the console's `/approvals` list.
