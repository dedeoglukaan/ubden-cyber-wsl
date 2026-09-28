# offensive-ext — post-UBDEN offensive + report layer

UBDEN answers "what is exposed" (read-only). This layer answers "and here is how an attacker
turns that into Domain Admin", with evidence, then folds the findings back into UBDEN's report as
an attack narrative with CVSS, chain-aware severity, a coverage matrix and ATT&CK tags.

Nothing here modifies UBDEN. It reads a finished run folder, writes its own evidence into
`<run>/offensive-ext/`, appends findings to `review.json`, and re-runs `report_v2.py`.

## Modules (each has `--self-test`, all offline-safe)

| File | Role |
|---|---|
| `doctor.py` | Pre-engagement readiness check (GO/NO-GO): tools installed, scope valid, credential present, DC reachable (TCP only, no auth). Run this FIRST. |
| `guard.py` | Lockout-aware auth guard — reads domain policy, budgets attempts, hard-stops on lockout. Wraps all guessing. |
| `attack.py` | Offensive orchestrator — reads UBDEN JSON, runs a READ-ONLY-FIRST chain (ADCS→BloodHound→AS-REP→kerberoast→auth-matrix→coerce-scan), evidence into `<run>/offensive-ext`. Writes/dumps gated behind `--enable-writes`+confirm. |
| `parse.py` | Tool output → normalized findings (certipy/kerberoast/asrep/nxc/coercer). |
| `score.py` | CVSS 3.1 (self-tested vs known vectors) + chain-aware severity (chain→DA = Critical). |
| `attck.py` | MITRE ATT&CK tagging + Navigator layer JSON. |
| `narrate.py` | Kill-chain narrative (Turkish, client-facing). |
| `coverage.py` | Coverage matrix (tested/attempted/skipped) from executed steps. |
| `crack.py` | Offline kerberoast/AS-REP cracking helper — writes ready `.hash` files + exact hashcat/john commands; ingests results back as CRACKED-credential findings. No network, no lockout. |
| `remediation.py` | Prioritized remediation roadmap (Turkish) grouped by root cause + quick-wins. |
| `emit.py` | Writes findings into UBDEN `review.json` (verified when evidence hash-matches) + re-runs report_v2. The analyst signature written to `reviewed_by` comes from `--reviewer` / `$UBDEN_REVIEWER`, defaulting to `Analist`. |
| `pipeline.py` | A-to-Z: attack → parse (+cracked.json) → score → attck → chain → narrate → coverage → remediation → emit. |
| `setup-offensive.sh` | Installs the offensive toolchain on Kali (run once, on the box). |
| `ARCHITECTURE.md` | The full design + what each idea was borrowed from. |
| `RUNBOOK.md` | Step-by-step operator guide for engagement day — the long form. |
| `CHEATSHEET.md` | The same commands on one page, for use during the engagement. |
| `SAFETY.md` | What the default chain can and cannot do to a client machine, and what is gated. |

## Run (on the Kali box, after UBDEN finishes)

```bash
sudo bash offensive-ext/setup-offensive.sh                  # once
EXT="$PWD/offensive-ext"; PY="$EXT/.venv/bin/python3"
export UBDEN_REVIEWER='<analyst or company name>'           # -> "Doğrulayan analist" in the report

printf '10.0.0.0/24\n<DC_IP>\n<DC_FQDN>\n' > scope.txt     # REQUIRED allowlist (fail-closed)

"$PY" "$EXT/doctor.py"   --scope scope.txt --run-dir <RUN> \
      --dc <DC_FQDN> --domain <DOMAIN> --ip <DC_IP> --user <U> --password '***'   # GO/NO-GO first

"$PY" "$EXT/pipeline.py" --run-dir <RUN> --scope scope.txt \
      --dc <DC_FQDN> --domain <DOMAIN> --ip <DC_IP> --user <U> --password '***' --dry-run   # preview

"$PY" "$EXT/pipeline.py" --run-dir <RUN> --scope scope.txt \
      --dc <DC_FQDN> --domain <DOMAIN> --ip <DC_IP> --user <U> --password '***'             # live

"$PY" "$EXT/pipeline.py" --run-dir <RUN> --skip-attack       # rebuild the report layer only, no network
```

`--skip-attack` is the offline half: it re-parses whatever evidence is already in the run folder,
re-scores, and regenerates the report. It sends no packets, so it is safe to re-run at any time.

Safety (see SAFETY.md): `--scope` allowlist is mandatory (no allowlist ⇒ zero packets); a guarded
credential pre-flight aborts before any fan-out if the password is wrong; every auth step is per-host
single-thread and output-scanned for lockout (hard-stop on the first signal); a `STOP` file in the run
dir is a kill-switch; evidence is 0600; writes/dumps need `--enable-writes` + `YETKILIYIM`, DCSync also
`--allow-dcsync`. Passwords are redacted in all logs. DC-breaking tooling (Zerologon/noPac/EternalBlue)
is denylisted and absent.

## Test everything

```bash
for m in doctor guard attack score parse attck narrate coverage emit pipeline remediation crack; do
  offensive-ext/.venv/bin/python3 offensive-ext/$m.py --self-test | tail -1; done
```

Every module is self-testing and offline — no lab, no network, no target needed.
