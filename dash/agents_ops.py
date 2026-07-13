"""
Ops Dash Agent
==============

Ops-flavored Dash variant that queries the platform operations warehouse.
Points SQLTools at the ops warehouse tables (desired_services, actual_services,
drift_observations, etc.) and uses ops-specific semantic models and business rules.

Test: python -m dash.agents_ops
"""

from os import getenv
from pathlib import Path

from agno.agent import Agent
from agno.models.openai import OpenAIResponses
from agno.tools.reasoning import ReasoningTools
from agno.tools.sql import SQLTools
from sqlalchemy import URL, create_engine

from dash.context.business_rules import build_business_context
from dash.context.semantic_model import build_semantic_model, format_semantic_model
from dash.tools import create_introspect_schema_tool

# ============================================================================
# Ops-specific paths
# ============================================================================

_OPS_KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"
_OPS_TABLES_DIR = _OPS_KNOWLEDGE_DIR / "tables"
_OPS_BUSINESS_DIR = _OPS_KNOWLEDGE_DIR / "business"

# ============================================================================
# Database
# ============================================================================

_REQUIRED_OPS_SETTINGS = ("OPS_DB_HOST", "OPS_DB_PORT", "OPS_DB_USER", "OPS_DB_PASS", "OPS_DB_DATABASE")


def _ops_reader_url() -> URL:
    values = {name: getenv(name, "").strip() for name in _REQUIRED_OPS_SETTINGS}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise RuntimeError(f"explicit Ops reader settings are required: {', '.join(missing)}")
    try:
        port = int(values["OPS_DB_PORT"])
    except ValueError as exc:
        raise RuntimeError("OPS_DB_PORT must be an integer") from exc
    return URL.create(
        "postgresql+psycopg",
        username=values["OPS_DB_USER"],
        password=values["OPS_DB_PASS"],
        host=values["OPS_DB_HOST"],
        port=port,
        database=values["OPS_DB_DATABASE"],
    )


_ops_db_url = _ops_reader_url()
_ops_engine = create_engine(
    _ops_db_url,
    connect_args={"options": "-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000"},
)

# ============================================================================
# Ops Semantic Model & Business Context
# ============================================================================

# Only load ops_* table definitions (filter by prefix)
_ops_semantic_model = build_semantic_model(_OPS_TABLES_DIR)
_ops_semantic_str = format_semantic_model(_ops_semantic_model)
_ops_business_context = build_business_context(_OPS_BUSINESS_DIR)

# ============================================================================
# Tools
# ============================================================================

introspect_schema = create_introspect_schema_tool(str(_ops_db_url), engine=_ops_engine)

# Dash is deliberately read-only. The database role enforces SELECT-only SQL,
# while Dockhand owns evidence capture, proposal policy, approvals, and execution.
ops_base_tools: list = [
    SQLTools(db_engine=_ops_engine),
    introspect_schema,
]

# ============================================================================
# Instructions
# ============================================================================

OPS_INSTRUCTIONS = f"""\
You are Ops Dash, a self-learning infrastructure analyst that provides **operational insights** \
from the platform's operational data warehouse.

## Your Purpose

You are the platform operator's data analyst — one that knows every service, every deploy, \
every drift item, and every incident. You turn operational exhaust into actionable intelligence.

You don't just fetch data. You interpret it through the lens of operational risk, correlate \
events across systems, and explain what the data means for platform reliability.

## Workflow

1. Write SELECT-only SQL (LIMIT 50, no SELECT *, ORDER BY for rankings)
2. If a query fails, use `introspect_schema` and retry without mutating data
3. Provide operational insights with canonical evidence identifiers
4. Direct all action requests through the private investigation contract

## Key Concepts

**Drift Debt Score**: Risk-weighted sum of unresolved drift items.
Formula: severity_weight × blast_radius × age_days × exposure_multiplier
Where exposure_multiplier: 3.0 (public Traefik), 2.0 (platform-core), 1.5 (prod), 1.0 (test)

**Priority Tiers**: P0 (Traefik/edge), P1 (monitoring), P2 (automation), P3 (apps), P4 (datastores)
Updates are applied in reverse order: P4 first (lowest risk), P0 last.

**Platform Hosts**: platform-core (control plane), prod (production workloads)

## Insights, Not Just Data

| Bad | Good |
|-----|------|
| "3 drift items found" | "3 drift items, but Traefik's is 60% of total risk due to public exposure × 12-day age" |
| "5 deploys this week" | "5 deploys, 80% success rate — the Ghost failure correlates with the MySQL OOM at 03:12" |

## Execution Boundary

You never submit jobs, create or resolve incidents, write learnings, or mutate operational data.
Dockhand is the sole policy, scheduling, approval, and execution authority.
When action may be useful, return a typed proposal through the private investigation API;
never generate shell commands, code, or unregistered job kinds.

## SQL Rules

- LIMIT 50 by default
- Never SELECT * — specify columns
- ORDER BY for top-N queries
- No DROP, DELETE, UPDATE, INSERT
- Use JSONB operators (->> , ?) for traefik_labels and details columns
- Use ANY() for TEXT[] array membership checks

---

## SEMANTIC MODEL

{_ops_semantic_str}
---

{_ops_business_context}\
"""

# ============================================================================
# Create Agent
# ============================================================================

ops_dash = Agent(
    name="Ops Dash",
    model=OpenAIResponses(id="gpt-5.2"),
    instructions=OPS_INSTRUCTIONS,
    tools=ops_base_tools,
    add_datetime_to_context=True,
    markdown=True,
)

reasoning_ops_dash = ops_dash.deep_copy(
    update={
        "name": "Reasoning Ops Dash",
        "tools": ops_base_tools + [ReasoningTools(add_instructions=True)],
    }
)

if __name__ == "__main__":
    ops_dash.print_response("What services are running on platform-core?", stream=True)
