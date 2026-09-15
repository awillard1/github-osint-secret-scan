# Recon toolchain validation — 2026-09-15

This record supplements the earlier assessment control-plane validation. The
operator contract and compatibility limits are in [Recon toolchain](recon-toolchain.md).

## Delivered behavior

- One registry supplies tool inventory, modes, configuration, actual executable
  detection, parsed versions, installation definitions and pipeline ordering.
- Settings → Recon Tools exposes explicit, separate passive/active installation,
  updates, verification, configuration guidance and installation status.
- Assessment profiles require active authorization and resolve selected missing
  tools before execution. Domain scope and normalized upstream observations gate
  downstream DNS, HTTP, crawl, port and template stages.
- Subfinder, DNSX, HTTPX, Naabu, Katana, Nuclei, compatible Amass and gau adapters
  feed canonical observations alongside crt.sh, Wayback, RDAP and WHOIS.
- Canonical domains/assets, provenance, relationships and Nuclei findings/evidence
  feed Discovery Results, assessment relationships, exports and optional AI advice.
- GitHub discovery retains connection isolation and adds bounded repository
  branch/language/tree metadata without executing repository code.
- Migration 20260915_0015 adds recon assets. Upgrade preservation and tenant-scoped
  projection protections cover the added data family.

## Validation method

Final full-suite result: **885 passed, 7 skipped, 2 warnings in 682.28 seconds**.
The warnings are upstream Starlette/AnyIO deprecations. Command:

```sh
.venv/bin/python -m pytest -o 'pythonpath=src /tmp/orgscan-recon-test-deps'
```

The temporary path supplies the newly declared PyYAML dependency for source tests;
the clean wheel installation resolves its own runtime dependencies normally.

Focused tests exercise real services and disposable database/browser workflows
with fake external processes and network responses. They cover executable identity,
failed-update preservation, installation permissions, explicit active consent,
missing tools, input/scope validation before execution, template restrictions,
correlation, canonical findings/evidence, deadlines, redirect restrictions,
resource limits and credential-safe projection.

The wheel was built with `python -m build --no-isolation`. The clean-install script
passed in a disposable environment: dependency checks, migrations, CLI, API
lifespan/health, scan, JSON/SARIF reports and encrypted evidence/reveal. Doctor
against a disposable database returned success with zero errors; optional
dependency warnings remain expected. Compile checks and `git diff --check` passed.

PyYAML is declared as a runtime dependency. Source tests used a temporary dependency
directory; the developer virtual environment was not modified to add it. No recon
binary was installed and no live reconnaissance was performed. The configured
application database was not migrated. Changes are uncommitted and undeployed.

### Operator-requested follow-up

After the implementation validation, the operator explicitly requested migration,
doctor, a commit and the `codex-recon-toolchain` tag. PyYAML 6.0.3 was then installed
in the project virtual environment. `orgscan migrate-db` successfully upgraded the
configured SQLite database from 0014 to **20260915_0015**. `orgscan doctor` exited
successfully: all required checks passed, with 35 warnings. No recon executable
was installed. The earlier statements above describe the implementation run before
this explicit operational follow-up.

## Operational limits

Amass supports its v3 passive contract; newer majors need a separately validated
adapter. Nuclei accepts a restricted local GET/HEAD HTTP template policy, with no
automatic acquisition. Uncover is deliberately deferred pending connection/key
and query policy. RDAP currently enriches domain registrations, not standalone IP
network registrations. Live upstream/GHES/Windows compatibility is not certified.

Installation runs in the API process with persisted status and explicit retry
after interruption. Pipeline concurrency coordinates workers sharing a POSIX lock
directory; it is not distributed scheduling or an OS resource sandbox. Existing
cross-tenant duplicate-domain conflicts continue to fail closed. Configuration
guidance uses administrator environment settings; it does not edit arbitrary
executable paths through the browser. The relationship table is the graph view.
