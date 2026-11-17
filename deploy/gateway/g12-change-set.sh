#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# G1/G2: ONE operator-run CloudFormation change set on the Gateway's stack.
# The stack's OPERATOR runs this; nothing in this repository does. It is never an imperative UpdateGateway: a later full deploy of the
# stack would silently revert that, and it drifts the stack. With --go the template change is written back to
# $TEMPLATE (default $STACK_DIR/template.yaml; backed up first), so later deploys keep it.
#
# What changes in the Gateway ($TEMPLATE):
#   G1  ProtocolConfiguration.Mcp.SupportedVersions: ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]
#       (the property, like UpdateGateway, REPLACES the list, so every version the gateway keeps is named)
#   G2  InterceptionPoints: [REQUEST, RESPONSE], PassRequestHeaders: true kept (the tool definitions reach the
#       interceptor only at RESPONSE, gateway-interceptors-types.html)
#   D2  AWS::Lambda::Permission InterceptorInvokeFromGateway: Principal bedrock-agentcore.amazonaws.com,
#       SourceArn = this Gateway's ARN, SourceAccount = this account.
#
# LIMIT (D2, stated, not solved here): a Lambda permission only ADDS an allow. In one account, a principal whose
# identity policy allows lambda:InvokeFunction on the interceptor (a full-access profile is one) is not
# stopped by it, and can invoke the interceptor directly with a forged Authorization header. Gateway-only invoke
# also needs every other invoke grant removed, or an SCP or permissions boundary denying it. The Gateway itself
# invokes with its own role (GatewayInvokePolicy), so this permission scopes nothing by itself.
#
# Create the change set, describe it, and REFUSE (delete it, execute nothing) if it
# would Remove anything or Replace anything (Replacement True or Conditional). If the Gateway itself shows Replace,
# that refusal is the finding to report. The change set is executed only with --go --execute.
#
#   STACK_DIR=<folder with the stack's template.yaml> bash deploy/gateway/g12-change-set.sh      # dry: writes the patched template + diff locally; no AWS call
#   STACK_DIR=<folder with the stack's template.yaml> bash deploy/gateway/g12-change-set.sh --go # creates + describes the change set (AWS writes), stops
#   STACK_DIR=<folder with the stack's template.yaml> bash deploy/gateway/g12-change-set.sh --go --execute # ... and executes it if it replaces and removes nothing
#
# A test account only (region us-east-2 by default). Undo: a change set back to the backed-up template.
set -euo pipefail

STACK_DIR=${STACK_DIR:?set STACK_DIR to the folder that holds the stack template.yaml}
TEMPLATE=${TEMPLATE:-$STACK_DIR/template.yaml}
REGION=${REGION:-us-east-2}
PROFILE=${PROFILE:-}
STACK=${STACK:-reqdemo}
OUT=${OUT:-$PWD/g12-change-set-out}
WLOG=${WLOG:-$STACK_DIR/AWS-WRITES.md}
GO=0
EXECUTE=0
for arg in "$@"; do
  case "$arg" in
    --go) GO=1 ;;
    --execute) EXECUTE=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
AWSP=(--region "$REGION"); [ -n "$PROFILE" ] && AWSP+=(--profile "$PROFILE")

stop() { echo; echo "STOP: $*" >&2; exit 1; }
step() { echo; echo "== $(date -u +%H:%M:%SZ) $*"; }
logw() { printf '| %s | `%s` | %s | %s |\n' "$(date -u +%FT%TZ)" "$1" "$2" "$3" >> "$WLOG"; }

# ---- 0. the template change (local) -----------------------------------------------------------------------------
step "0 the template change (local only)"
if [ ! -f "$TEMPLATE" ]; then
  echo "would patch $TEMPLATE (not found here) and create a change set on stack $STACK; nothing done"
  [ "$GO" = 1 ] && stop "no template at $TEMPLATE"
  exit 0
fi
mkdir -p "$OUT"
PATCHED=$OUT/template.g12.yaml
python3 - "$TEMPLATE" "$PATCHED" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src).read()

def once(old, new):
    global text
    if text.count(old) != 1:
        sys.exit(f"refused: expected exactly one {old.strip()[:60]!r} in the template, found {text.count(old)}")
    text = text.replace(old, new)

if "InterceptorInvokeFromGateway:" in text:
    sys.exit("refused: the template already carries the G1/G2 change")
once("            InterceptionPoints: [REQUEST]\n", "            InterceptionPoints: [REQUEST, RESPONSE]\n")
once("      ProtocolType: MCP\n",
     "      ProtocolType: MCP\n"
     "      ProtocolConfiguration:\n"
     "        Mcp:\n"
     "          SupportedVersions: [\"2026-07-28\", \"2025-11-25\", \"2025-06-18\", \"2025-03-26\"]\n")
once("  RefundsLambdaTarget:\n",
     "  InterceptorInvokeFromGateway:\n"
     "    Type: AWS::Lambda::Permission\n"
     "    Condition: FullInterceptor\n"
     "    Properties:\n"
     "      FunctionName: !GetAtt InterceptorFunction.Arn\n"
     "      Action: lambda:InvokeFunction\n"
     "      Principal: bedrock-agentcore.amazonaws.com\n"
     "      SourceArn: !GetAtt Gateway.GatewayArn\n"
     "      SourceAccount: !Ref AWS::AccountId\n"
     "\n"
     "  RefundsLambdaTarget:\n")
open(dst, "w").write(text)
PY
diff -u "$TEMPLATE" "$PATCHED" > "$OUT/template.g12.diff" || true
cat "$OUT/template.g12.diff"
echo "patched template: $PATCHED (sha256 $(sha256sum "$PATCHED" | cut -c1-12))"

if [ "$GO" != 1 ]; then
  echo
  echo "would: aws cloudformation create-change-set --stack-name $STACK (UPDATE, every parameter UsePreviousValue) from"
  echo "       $PATCHED, describe-change-set, refuse on any Remove or Replace, and execute only with --go --execute;"
  echo "       then write the patched template back to $TEMPLATE (backed up first). Nothing was sent to AWS."
  exit 0
fi

# ---- 1. checks (read-only) --------------------------------------------------------------------------------------
step "1 checks (read-only)"
NAME=$(aws account get-account-information ${PROFILE:+--profile "$PROFILE"} --query AccountName --output text) || stop "cannot read the account"
[ "$NAME" = "Test" ] || stop "profile ${PROFILE:-(default)} is account '$NAME', not Test"
aws cloudformation validate-template "${AWSP[@]}" --template-body "file://$PATCHED" > /dev/null || stop "validate-template failed"
PARAMS=()
for key in $(aws cloudformation describe-stacks "${AWSP[@]}" --stack-name "$STACK" --query 'Stacks[0].Parameters[].ParameterKey' --output text); do
  PARAMS+=("ParameterKey=$key,UsePreviousValue=true")
done
[ "${#PARAMS[@]}" -gt 0 ] || stop "no parameters read from $STACK"

# ---- 2. the change set (AWS writes) -----------------------------------------------------------------------------
step "2 change set on $STACK that must replace and remove NOTHING"
CS=reqdemo-g12-$(date -u +%Y%m%dT%H%M%SZ)
aws cloudformation create-change-set "${AWSP[@]}" --stack-name "$STACK" --change-set-name "$CS" --change-set-type UPDATE \
    --template-body "file://$PATCHED" --capabilities CAPABILITY_IAM --tags Key=project,Value=requisition-aws-demo \
    --parameters "${PARAMS[@]}" > /dev/null || stop "create-change-set failed"
logw "aws cloudformation create-change-set --stack-name $STACK --change-set-name $CS (g12 template sha256 $(sha256sum "$PATCHED" | cut -c1-12))" "$CS" "created"
aws cloudformation wait change-set-create-complete "${AWSP[@]}" --stack-name "$STACK" --change-set-name "$CS" || stop "change set $CS did not complete"
echo "the change set (Action / resource / Replacement):"
aws cloudformation describe-change-set "${AWSP[@]}" --stack-name "$STACK" --change-set-name "$CS" \
  --query 'Changes[].ResourceChange.[Action,LogicalResourceId,Replacement]' --output text | tee "$OUT/$CS.txt"
BAD=$(awk '$1=="Remove" || $3=="True" || $3=="Conditional"' "$OUT/$CS.txt")
if [ -n "$BAD" ]; then
  aws cloudformation delete-change-set "${AWSP[@]}" --stack-name "$STACK" --change-set-name "$CS" || true
  logw "aws cloudformation delete-change-set --change-set-name $CS (refused: it would replace or remove)" "$CS" "deleted"
  echo "$BAD"; stop "refused: the change set would REPLACE or REMOVE the resources above; nothing was executed (report this)"
fi
if [ "$EXECUTE" != 1 ]; then
  echo "change set $CS is clean and NOT executed (re-run with --go --execute, or execute it in the console)"
  exit 0
fi
aws cloudformation execute-change-set "${AWSP[@]}" --stack-name "$STACK" --change-set-name "$CS" || stop "execute-change-set failed"
logw "aws cloudformation execute-change-set --stack-name $STACK --change-set-name $CS (g12)" "$CS" "submitted"
aws cloudformation wait stack-update-complete "${AWSP[@]}" --stack-name "$STACK" || stop "$STACK did not reach UPDATE_COMPLETE"
sed -i '$ s/submitted |$/UPDATE_COMPLETE |/' "$WLOG"

# ---- 3. keep the change in $TEMPLATE ---------------------------------------------------------------------
step "3 the template change kept (so a later full deploy of the stack does not revert it)"
cp "$TEMPLATE" "$OUT/template.before-g12.yaml"
cp "$PATCHED" "$TEMPLATE"
echo "template now $(sha256sum "$TEMPLATE" | cut -c1-12); the previous one is $OUT/template.before-g12.yaml"
