# Agent instructions

This repository scans untrusted third-party code. Keep that boundary intact:

- Never build, install or execute plugin content. Fetch, unpack and read only.
- Treat file names, code excerpts and store entries as untrusted: run steps that process
  them through `scripts/no-workflow-commands.sh`, escape them in the overview
  (`scripts/summary.py`) and pass them to shell steps only via environment variables.
- Fail closed: an incomplete or failed scan must never count as a pass.
- Every new rule needs `ruleid`/`ok` cases in `tests/rules/`; every gate or script change
  needs a test in `tests/`.

Checks to run before a pull request (CI runs the same in `rules-test.yml`):

```bash
uvx semgrep==1.182.1 scan --test --metrics=off --config rules/ tests/rules/
```

```bash
SEMGREP_VERSION=1.182.1 python3 -I -m unittest discover -s tests
```

```bash
scripts/install-osv-scanner.sh /tmp/osv-scanner && SEMGREP_VERSION=1.182.1 tests/test_evasion.sh /tmp/osv-scanner
```

This repository ships no baselines; do not add accepted findings for store plugins here.
