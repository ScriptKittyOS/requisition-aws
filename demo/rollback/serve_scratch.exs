# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# The rollback demo's SECOND server (demo/run_rollback_local.py): the Requisition demo checkout's dev endpoint on
# 127.0.0.1:$ROLLBACK_PORT against REQ_E2E_DB_NAME (bin/scratch-db's database), with no asset watchers and
# no code reloader and no Oban queues or plugins -- that checkout's scripts/serve.exs with the port taken from the environment, so the
# live demo server on 4103 is never touched. Run with `mix run --no-start` (the app starts here, after
# the endpoint config is set).
port = String.to_integer(System.fetch_env!("ROLLBACK_PORT"))
if port == 4103, do: raise("ROLLBACK_PORT 4103 is the live demo server's port")

cfg = Application.get_env(:autonomous_agency, AutonomousAgencyWeb.Endpoint)

Application.put_env(
  :autonomous_agency,
  AutonomousAgencyWeb.Endpoint,
  Keyword.merge(cfg,
    server: true,
    watchers: [],
    code_reloader: false,
    http: [ip: {127, 0, 0, 1}, port: port]
  )
)

# No Oban on the copy: jobs copied in the dump never run a second time, and no
# cron plugin appends to the chain or reaches outside (the approval and mint path enqueues nothing).
Application.put_env(
  :autonomous_agency,
  Oban,
  Keyword.merge(Application.get_env(:autonomous_agency, Oban, []), queues: false, plugins: false)
)

{:ok, _} = Application.ensure_all_started(:autonomous_agency)
IO.puts("ROLLBACK SCRATCH SERVER UP on 127.0.0.1:#{port}, database #{System.get_env("REQ_E2E_DB_NAME")}, Oban queues and plugins off, pid #{System.pid()}")
Process.sleep(:infinity)
