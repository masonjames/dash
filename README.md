# Dash Ops

Dash is a private, read-only Ops service for Dockhand. It validates canonical
evidence, investigates operational failures, retrieves relevant canonical records,
and evaluates verification outcomes. Dockhand owns policy, approvals, canonical
writes, and execution; Dash returns typed results and catalog-bound proposals.

## Private API

The default Docker command starts `app.ops_main:app` on port **8001** through
`scripts/entrypoint.sh`. The service exposes exactly three routes, with no public
UI or OpenAPI endpoints:

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/internal/health/ready` | Check reader privileges, schema and hybrid index readiness |
| POST | `/internal/ops/investigate` | Investigate scoped canonical evidence |
| POST | `/internal/ops/evaluate-outcome` | Evaluate a canonical verification outcome |

All routes require HMAC authentication using `DASH_INTERNAL_API_SECRET` and
`X-Dash-Timestamp`, `X-Dash-Nonce`, and `X-Dash-Signature`. The signature covers
newline-separated timestamp, nonce, uppercase method, path, and raw body bytes.
Requests enforce clock skew and nonce replay checks.

## Roles and configuration

Use the placeholders in [example.env](example.env) to configure each process
independently. Export the appropriate variables in that process's environment;
the API and maintenance commands do not automatically load `.env`.

- **API reader:** all five `OPS_DB_*` settings are required, with no fallback to
  `DB_*`. Use `dash_ops_reader`, which has SELECT-only access and read-only
  transactions. The API also requires the internal HMAC secret and
  `OPENAI_API_KEY` for query embeddings.
- **Indexer:** all five `OPS_INDEXER_DB_*` settings are independently required,
  with no fallback to reader or general DB credentials. `dash_ops_indexer` reads
  canonical records and writes only the derived retrieval documents and status.
  It requires `OPENAI_API_KEY` for document embeddings.
- **Canonical writer:** `dockhand_ops_writer` belongs to Dockhand, isolated from
  the API reader and derived indexer. Do not give its credentials to the API.
- **Migration process:** `DB_*` supplies the database owner connection. It also
  requires all four role passwords listed in `example.env`. Provisioning retains
  `dash_api_runtime`; retiring the demo does not remove database roles or data.

Canonical retrieval combines lexical search and OpenAI `text-embedding-3-small`
embeddings. Readiness checks index coverage and freshness; the default maximum
index age is 7200 seconds (`DASH_OPS_INDEX_MAX_AGE_SECONDS`).
`DASH_OPS_MODEL_VERSION` optionally overrides the returned detector version label.

## Runtime and maintenance commands

With Python 3.12+ and the locked project dependencies available:

```bash
# Migration owner environment only: applies checksummed migrations and role grants
python -m scripts.migrate_ops

# Independent indexer environment; one-shot or recurring projection
python -m scripts.index_ops
python -m scripts.index_ops --interval-seconds 1800

# Reader environment only; also the Docker default
uvicorn app.ops_main:app --host 0.0.0.0 --port 8001
```

The ten migrations in `db/migrations/` are immutable once applied.
`db/runtime_role_privileges.sql` reconciles grants even after a restore with an
existing migration ledger. Canonical `dash.validated_queries` remains available
to retrieval and readiness; zero validated-query rows are allowed.

Preserved Ops reference knowledge is under `dash/knowledge/`: `tables/ops_*.json`,
`business/ops_metrics.json`, and `queries/ops_queries.sql`. The canonical indexer
in `dash/ops_indexer.py` projects database records, independently of those files.

## Offline validation and synthetic replay

```bash
ruff format --check .
ruff check .
mypy .
python -m pytest -q --ignore=tests/test_postgres_search_path_integration.py
python -m evals control-loop --verbose
python -m evals control-loop --json
python -m scripts.export_control_loop_corpus --out /tmp/dash-control-loop.jsonl
```

`./scripts/format.sh` formats and sorts imports; `./scripts/validate.sh` runs Ruff,
mypy, and pytest. PostgreSQL integration tests require an explicitly configured,
disposable `dash_search_path_ci` database via `DASH_TEST_POSTGRES_DSN`.

Replay and corpus export use synthetic scenarios without model calls. Replay
results do not establish live operational readiness. Run the full pinned Dagger
gate before opening a PR, and build/smoke-test image changes locally without
publishing:

```bash
./scripts/run-dagger-ci.sh check
./scripts/run-dagger-ci.sh call build
```

The Dagger build and GHCR workflow retain their exact three-route image smoke checks.
