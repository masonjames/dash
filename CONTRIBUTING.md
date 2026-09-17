# Contributing to Dash Ops

Read [AGENTS.md](AGENTS.md) for the service boundaries and [README.md](README.md)
for configuration and maintenance commands. Use Python 3.12+ with the locked
project dependencies. Keep changes focused and preserve reader/writer/indexer
separation, canonical data, and migration checksums.

Before opening a pull request, run:

```bash
ruff format --check .
ruff check .
mypy .
python -m pytest -q --ignore=tests/test_postgres_search_path_integration.py
python -m evals control-loop --verbose
```

`./scripts/format.sh` applies formatting and import sorting;
`./scripts/validate.sh` runs Ruff, mypy, and pytest. PostgreSQL integration tests
require the explicitly configured disposable database described in the README.
Include relevant validation results and explain any checks not run.

Contributions are licensed under [Apache License 2.0](LICENSE).
