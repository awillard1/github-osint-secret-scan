# Testing and Validation

## Baseline

Before a phase:

```bash
pytest
```

If the project has baseline failures, record them before changing code.

## Required test levels

### Unit

Use for:

- scanner parsers;
- fingerprints;
- scan-plan resolution;
- lifecycle transitions;
- retry classification;
- auth/authorization decisions.

### Service tests

Use a temporary SQLite database and fakes for external dependencies.

Test use cases independently of FastAPI/Typer.

### API tests

Verify:

- status codes;
- validation;
- authorization;
- compatibility of documented endpoints;
- no secret leakage in response errors.

### CLI tests

Verify documented command compatibility and exit codes.

Do not duplicate all service business-rule tests at the CLI layer.

### Migration tests

For schema changes:

- upgrade a representative previous schema;
- verify newly required fields/indexes;
- verify SQLite compatibility.

### External process tests

Mock/fake subprocess behavior.

Cover:

- executable missing;
- success;
- scanner findings;
- no findings;
- timeout;
- malformed output;
- non-zero exit.

## Security regression tests

Maintain tests for:

- path traversal in archive extraction;
- unsafe symlink handling;
- secret redaction;
- authorization/tenant boundaries;
- command injection avoidance;
- scanner timeout;
- artifact cleanup;
- unsafe filename handling.

## Test organization

Prefer test files aligned to architectural modules after decomposition:

```text
tests/
    api/
    cli/
    services/
    scanners/
    storage/
```

Do not reorganize the entire suite only for cosmetics. Move tests alongside corresponding refactors.

## Completion command

Minimum:

```bash
pytest
```

If Ruff/mypy are introduced/configured later:

```bash
ruff check .
mypy src/orgscan
pytest
```

Do not make `AGENTS.md` require a static tool until it exists in project configuration.

## Performance-sensitive tests

Repository history tests must use small synthetic git repositories.

Never clone large public repositories in the normal test suite.

## Determinism

Tests must not depend on:

- GitHub being reachable;
- crt.sh being reachable;
- current public DNS;
- local installation of Gitleaks/TruffleHog/Semgrep/YARA;
- Redis being externally available.

Use recorded fixtures or fakes.
