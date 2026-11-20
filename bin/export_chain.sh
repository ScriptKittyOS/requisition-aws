#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# export_chain.sh -- a READ-ONLY export of one Requisition lab ACCOUNT chain, for bin/verify_chain.py
#
#   PGDATABASE=<db> [PGHOST= PGPORT= PGUSER=] bin/export_chain.sh 'requisition-lab:account:<id>' > export.csv
#
# Writes the stored rows of authority_lab_receipts for that one scope, ordered by sequence, as CSV with a
# header: chain_scope,sequence,signature,key_id,signed_payload,receipt_hash,cosignature,cosignature_key_id
# (the columns of Requisition's lab record table; signed_payload is the exact signed bytes, and
# verify_chain.py reads every position from it, never from the lookup columns).
#
# Read only, three ways: the session default (PGOPTIONS default_transaction_read_only=on), an explicit
# READ ONLY transaction, and one SELECT inside COPY ... TO STDOUT (client side; no server file, no
# superuser). The scope reaches psql only as a variable (-v scope=...; :'scope' quotes it as a literal),
# and is checked against the account form first: anything else exits 2 before psql runs. Connection
# settings come from the libpq environment (PGDATABASE, PGHOST, ...; a password from the libpq password file, never
# the command line). Point it at a copy made by Requisition's scratch-database wrapper, or at the demo database --
# never a database in use.
set -euo pipefail

scope="${1-}"
if [[ $# -ne 1 || ! "$scope" =~ ^requisition-lab:account:[A-Za-z0-9-]{1,64}$ ]]; then
  echo "usage: export_chain.sh 'requisition-lab:account:<id>'  (account chains only)" >&2
  exit 2
fi

PGOPTIONS="${PGOPTIONS:-} -c default_transaction_read_only=on" \
exec psql -X -q -v ON_ERROR_STOP=1 -v "scope=$scope" <<'SQL'
BEGIN TRANSACTION READ ONLY;
COPY (
  SELECT chain_scope, sequence, signature, key_id, signed_payload, receipt_hash, cosignature, cosignature_key_id
    FROM authority_lab_receipts
   WHERE chain_scope = :'scope'
   ORDER BY sequence
) TO STDOUT WITH (FORMAT csv, HEADER);
COMMIT;
SQL
