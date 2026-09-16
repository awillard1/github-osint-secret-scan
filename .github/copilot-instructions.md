# orgscan repository instructions

Read `AGENTS.md` before making changes.

`AGENTS.md` is authoritative for architecture, testing, security, scanner behavior, and definition of done.

Additional references:

- `docs/architecture.md`
- `docs/development-plan.md`
- `docs/scanner-contract.md`
- `docs/testing.md`

Keep API/CLI/job adapters thin and put shared business behavior in services.

Never log raw discovered secrets or execute code from scanned repositories.

Preserve existing CLI/API compatibility during structural refactors unless a task explicitly changes the contract.
