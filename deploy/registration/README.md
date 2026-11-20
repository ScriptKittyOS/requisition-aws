# The v2 refund act type: registration payload (G2)

Nothing in this repository registers this act type or holds a credential to do so. The steps below are for the
operator of the Requisition lab.

`payments.refund_send_v2` is `payments.refund_send` at `schema_version` 2. The schema is v1's plus `tool_digest`, an
enum of the approved tool-definition digests (`requisition_aws/catalog.py`).

**Why a new name:** a second row named `payments.refund_send` is refused (a unique index on
the account and the name).

For every act type, this one included, a float anywhere in the arguments (`1250.0` included) is refused `float_refused`
by these adapters before anything is sent; `amount_minor` is an integer in the currency's smallest unit.

**What changes once it is registered:**
- Requisition refuses any other digest at propose (`malformed_member`).
- The approval page shows the digest, not the description.

## Steps

1. **Capture the Gateway's listing (read only, live).**

   ```
   python deploy/gateway/capture_tools_list.py --go --url <gateway mcp url> --save <dir>/capture.json
   ```

   It sends tools/list and nothing else.
2. **Complete the payload (local).**

   ```
   python deploy/registration/fill_gateway_digest.py --incomplete deploy/registration/aws_demo_v2.INCOMPLETE.json \
       --captured <dir>/capture.json --tool refunds___payments_refund_send --out <dir>/aws_demo_v2.v1.json
   ```

   The enum then holds two digests: the Strands one and the Gateway one.
3. **Register through the registration that two approver accounts approve.**
   1. Copy `<dir>/aws_demo_v2.v1.json` into the seed folder of the Requisition checkout, under the same name.
   2. Run Requisition's lab seed command for the set `aws_demo_v2`, with the account and the filer's email. This
      files the request.
   3. Two other accounts approve and co-approve it in the console.
   4. Run the same command again. This applies the registration.
4. **Point the adapters at it.** Set `REQUISITION_TOOLS` to
   `{"refunds___payments_refund_send": {"act_type": "payments.refund_send_v2", "tool_digest": "<the Gateway digest>"}}`.

The demo stays on `payments.refund_send` (v1) until this is done and the demo has been re-run.

**The guard on `aws_demo_v2.INCOMPLETE.json` is a naming convention, not a lock.**
- Its `set` is `aws_demo_v2_incomplete`, so the seed command for the set `aws_demo_v2` refuses it
  (`seed_file_set_mismatch`).
- Copied into the seed folder as `aws_demo_v2_incomplete.v1.json` and seeded under that name, it WOULD register an
  enum with only the Strands digest.
- That fails closed: every Gateway propose is then refused `malformed_member`. It is not a safety issue. Do not seed
  it; complete it first.
