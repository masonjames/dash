# Dash Ops contributor guidance

This repository serves the private Ops API in `app/ops_main.py`, default port
8001. Keep its route set exact: `GET /internal/health/ready`,
`POST /internal/ops/investigate`, and `POST /internal/ops/evaluate-outcome`.
All three require HMAC authentication; public docs and OpenAPI routes are disabled.

## Boundaries

- `dash/internal_ops.py` validates evidence, readiness, and outcome requests.
  Preserve HMAC/replay protection, typed contracts, and fail-closed behavior.
- The API uses explicit `OPS_DB_*` credentials for `dash_ops_reader`, with
  read-only transactions and SELECT-only access. Never fall back to `DB_*`.
- Dockhand owns canonical writes, approvals, and execution through its isolated
  `dockhand_ops_writer` identity. Dash only returns typed results/proposals.
- `dash/ops_indexer.py` uses independent `OPS_INDEXER_DB_*` credentials for
  `dash_ops_indexer`. It may mutate only derived retrieval documents/status.
- Preserve canonical retrieval in `dash/ops_retrieval.py`, OpenAI query/document
  embeddings, and Ops runtime settings (`DASH_OPS_INDEX_MAX_AGE_SECONDS`,
  `DASH_OPS_MODEL_VERSION`). See `example.env` for process-specific placeholders.
- Keep all ten checksummed SQL migrations unchanged. The owner-only migration
  runner in `scripts/migrate_ops.py` provisions four roles, including
  `dash_api_runtime`, and reapplies `db/runtime_role_privileges.sql`.
- Preserve `dash.validated_queries`, including support for zero rows, and all
  nested Ops knowledge: `dash/knowledge/tables/ops_*.json`,
  `dash/knowledge/business/ops_metrics.json`, and
  `dash/knowledge/queries/ops_queries.sql`.

## Commands

Run from the repository root with project dependencies already available:

```bash
uvicorn app.ops_main:app --host 0.0.0.0 --port 8001
python -m scripts.migrate_ops                    # owner + four role passwords
python -m scripts.index_ops                      # independent indexer credentials
python -m scripts.index_ops --interval-seconds 1800
ruff format --check .
ruff check .
mypy .
python -m pytest -q --ignore=tests/test_postgres_search_path_integration.py
python -m evals control-loop --json
python -m scripts.export_control_loop_corpus --out /tmp/dash-control-loop.jsonl
```

`./scripts/format.sh` applies formatting/import sorting;
`./scripts/validate.sh` runs Ruff, mypy, and pytest. PostgreSQL integration tests
use only an explicitly configured disposable `dash_search_path_ci` database
(`DASH_TEST_POSTGRES_DSN`). Synthetic replay and corpus export require no model
calls and make no live readiness claims.

Keep the separation assertions in `tests/test_private_ops.py`, migration and
role tests, and the three-route image smoke checks in `.dagger` and
`.github/workflows/ghcr-build.yml`. Preserve the entrypoint's CMD pass-through.
Run `./scripts/run-dagger-ci.sh check` before opening a PR. For image changes,
also run `./scripts/run-dagger-ci.sh call build` for the local build and smoke
check. Local tests, image checks, publication, and deployment are separate
results. Do not infer permission for live operations from a local code task.
