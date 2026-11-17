# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# Requisition as the AgentCore Gateway TARGET: requisition_aws.mcp_target in a container for AgentCore
# Runtime's MCP contract (fetched 2026-11-09,
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html):
# ARM64, host 0.0.0.0, port 8000, POST /mcp, GET /ping, stateless Streamable HTTP.
#
# NOT BUILT FOR ARM64 HERE AND NOT DEPLOYED. Building and pushing to ECR, creating the Runtime and the
# Gateway target (IAM/SigV4 outbound auth) are not done here.
#
#   docker buildx build --platform linux/arm64 -f deploy/target/Dockerfile -t requisition-aws-target .
#
# Runtime configuration (environment; see requisition_aws/mcp_target.py from_env):
#   REQUISITION_URL REQUISITION_CRED REQUISITION_PRINCIPAL   the /v1 caller (CRED from a secret, never baked)
#   REQUISITION_KEYS_FILE=/app/keys/lab-keys.json            the pinned key file (mount or bake; required)
#   REQUISITION_SEED=/app/seed/aws_demo.v1.json              the act types' display_schema
#   REQUISITION_TARGET_ID, REQUISITION_SESSION_HEADER (a header the Gateway forwards via metadataConfiguration)
#   REQUISITION_REQUIRE_PQ=1 (set below; the default)       refuse any record without a checked ML-DSA-87 signature
#   REQUISITION_ALLOW_PLAINTEXT_PRIVATE=1                    only for http to a private IP literal (the VPC case)
FROM --platform=linux/arm64 python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
# deploy/target/requirements.txt: `uv export --no-dev --no-emit-project` from uv.lock, every wheel hashed
COPY deploy/target/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.txt
WORKDIR /app
COPY requisition_aws/ /app/requisition_aws/
COPY bin/vendor/ /app/bin/vendor/
ENV REQUISITION_REQUIRE_PQ=1
ENV MCP_HOST=0.0.0.0 MCP_PORT=8000 MCP_PATH=/mcp \
    REQUISITION_STORE=/tmp/requisition-aws/target-store.json \
    REQUISITION_LEDGER=/tmp/requisition-aws/refund-ledger.jsonl \
    PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
EXPOSE 8000
CMD ["python", "-m", "requisition_aws.mcp_target"]
