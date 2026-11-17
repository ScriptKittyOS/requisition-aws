# Elixir differential fixtures

Generated 2026-11-09 by `diff.exs` (in this folder), run once, read-only, against the compiled
Requisition modules of a Requisition checkout of its version of 2026-10-26 (its `_build/dev`):

    env -i HOME=$HOME PATH=$PATH ASDF_ERLANG_VERSION=28.5.0.8-openssl-3.5.9 \
      elixir -pa _build/dev/lib/autonomous_agency/ebin -pa _build/dev/lib/jason/ebin \
             -pa _build/dev/lib/decimal/ebin diff.exs <this folder>

Plain `elixir -pa`: the application is not started, no database is opened, nothing in the tree is
written. `env -i` leaves every configured-secret variable unset, so `redact_configured_secrets` is a
no-op (as in the Python port's default).

* `redact_cases.json` -> `redact_out.json`: `Security.Redaction.redact_text/1` over 4,010 strings
  (random concatenations of secret-shaped words and separators, plus named cases).
* `enc_cases.json` -> `enc_out.json`: `CanonicalPayload.encode/1` over 1,500 random float-free
  terms (base64 of the bytes), including control characters, non-BMP keys and U+2028.

Not effector material. `tests/test_elixir_differential.py` pins the Python port to these answers.
