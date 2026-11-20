# Elixir differential fixtures

Generated 2026-11-09 by a script kept in Requisition's repository, run once against the compiled
modules of the Requisition version of 2026-10-26, with plain `elixir -pa` under `env -i`: the application is not
started, no database is opened, nothing in that tree is written. `env -i` leaves every configured-secret variable
unset, so the redactor's configured-secret step is a no-op (as in the Python port's default).
The run used the Erlang/OTP build that the asdf version manager names `28.5.0.8-openssl-3.5.9` (the command set
`ASDF_ERLANG_VERSION` to that value); no Elixir version was written down.

* `redact_cases.json` -> `redact_out.json`: Requisition's redactor over 4,010 strings
  (random concatenations of secret-shaped words and separators, plus named cases).
* `enc_cases.json` -> `enc_out.json`: Requisition's canonical payload encoder (version 3) over 1,500 random float-free
  terms (base64 of the bytes), including control characters, non-BMP keys and U+2028.

Not effector material. `tests/test_elixir_differential.py` pins the Python port to these answers.
