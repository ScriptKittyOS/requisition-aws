# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
alias AutonomousAgency.Security.Redaction
alias AutonomousAgency.AuthorityAssurance.CanonicalPayload
[dir] = System.argv()
cases = File.read!(Path.join(dir, "redact_cases.json")) |> Jason.decode!()
out = Enum.map(cases, &Redaction.redact_text/1)
File.write!(Path.join(dir, "redact_out.json"), Jason.encode!(out))
enc = File.read!(Path.join(dir, "enc_cases.json")) |> Jason.decode!()
eout = Enum.map(enc, fn t -> {:ok, b} = CanonicalPayload.encode(t); Base.encode64(b) end)
File.write!(Path.join(dir, "enc_out.json"), Jason.encode!(eout))
IO.puts("ok")
