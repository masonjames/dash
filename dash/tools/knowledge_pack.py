"""Knowledge Pack Pipeline tools (Phase 5.4).

Legacy read-only helper for turning a resolved incident into reviewable candidates:
- Query candidate: must pass the execution-backed save_validated_query gate
- Learning candidate: must be admitted by Dockhand into the canonical ledger
- Runbook suggestion: markdown patch for human review

This module never writes operational truth or disposable vector stores. Dockhand
owns canonical learning admission and desired-state changes remain PR suggestions.
"""

from __future__ import annotations

from datetime import datetime
from agno.knowledge import Knowledge
from agno.tools import tool
from agno.utils.log import logger
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DatabaseError, OperationalError


def create_knowledge_pack_tools(
    db_url: str,
    knowledge: Knowledge,
    learnings: Knowledge,
) -> list:
    """Create knowledge pack pipeline tools.

    Args:
        db_url: SQLAlchemy database URL for the ops warehouse.
        knowledge: The ops_knowledge Knowledge instance (for validated queries).
        learnings: The ops_learnings Knowledge instance (for incident signatures).

    Returns:
        List of @tool-decorated functions for knowledge pack generation.
    """
    engine = create_engine(db_url)

    # ── Tool: generate_knowledge_pack ────────────────────────────

    @tool
    def generate_knowledge_pack(incident_id: int) -> str:
        """Generate a knowledge pack from a resolved incident.

        Reads the incident marker, extracts the timeline query, root cause,
        resolution, and affected services, then generates reviewable candidates.

        Call this AFTER resolving an incident with resolve_incident().

        Args:
            incident_id: The resolved incident's ID.

        Returns:
            Summary of generated knowledge artifacts.
        """
        try:
            with engine.connect() as conn:
                result = conn.execute(
                    text(
                        "SELECT id, title, severity, started_at, resolved_at, "
                        "affected_services, root_cause, resolution, "
                        "timeline_query, knowledge_pack "
                        "FROM incident_markers WHERE id = :id"
                    ),
                    {"id": incident_id},
                )
                row = result.fetchone()

            if not row:
                return f"Error: Incident #{incident_id} not found."

            title = row[1]
            severity = row[2]
            started_at = str(row[3]) if row[3] else "unknown"
            resolved_at = str(row[4]) if row[4] else None
            services = row[5] or []
            root_cause = row[6]
            resolution = row[7]
            timeline_query = row[8]
            existing_kp = row[9] or {}

            if not resolved_at:
                return f"Error: Incident #{incident_id} is not yet resolved. Resolve it first."

            if not root_cause or not resolution:
                return (
                    f"Error: Incident #{incident_id} is missing root_cause or resolution. "
                    "Both are required to generate a knowledge pack."
                )

            artifacts = []

            # ── 1. Retain an unvalidated query candidate ─────────
            # A resolved incident is not proof that a stored query still executes
            # or returns the expected shape. Reuse is admitted only through the
            # execution-backed save_validated_query gate.
            if timeline_query:
                query_name = f"incident_{incident_id}_timeline"
                artifacts.append(
                    f"Query candidate '{query_name}' requires execution and result-shape validation before reuse"
                )

            # ── 2. Save incident signature as learning ───────────
            signature = {
                "type": "incident_signature",
                "incident_id": incident_id,
                "title": title,
                "severity": severity,
                "affected_services": services,
                "symptoms": _extract_symptoms(title, root_cause, existing_kp),
                "root_cause": root_cause,
                "resolution": resolution,
                "started_at": started_at,
                "resolved_at": resolved_at,
                "duration_minutes": _compute_duration(row[3], row[4]),
            }

            # Merge any gotchas from the existing knowledge pack
            if isinstance(existing_kp, dict) and existing_kp.get("gotchas"):
                signature["gotchas"] = existing_kp["gotchas"]

            learning_name = f"incident_sig_{incident_id}_{_slugify(title)}"
            artifacts.append(
                f"Incident signature candidate '{learning_name}' with {len(signature['symptoms'])} normalized "
                "symptom(s) requires Dockhand canonical admission"
            )

            # ── 3. Generate runbook suggestion ───────────────────
            runbook_md = _generate_runbook_suggestion(
                incident_id=incident_id,
                title=title,
                severity=severity,
                services=services,
                root_cause=root_cause,
                resolution=resolution,
                started_at=started_at,
                resolved_at=resolved_at,
                existing_kp=existing_kp,
            )
            artifacts.append("Runbook suggestion generated (see below)")

            # ── Build response ───────────────────────────────────
            lines = [
                f"**Knowledge Pack Generated** for Incident #{incident_id}: {title}",
                "",
                "**Artifacts:**",
            ]
            for a in artifacts:
                lines.append(f"- {a}")

            lines.extend(["", "---", "", "**Runbook Suggestion** (review before merging):", "", runbook_md])

            return "\n".join(lines)

        except OperationalError as e:
            logger.error("Knowledge pack generation failed: %s", e)
            return f"Error: Database connection failed — {e}"
        except DatabaseError as e:
            logger.error("Knowledge pack query error: %s", e)
            return f"Error: {e}"

    # ── Tool: get_incident_knowledge_pack ─────────────────────────

    @tool
    def get_incident_knowledge_pack(incident_id: int) -> str:
        """Retrieve the knowledge pack for a resolved incident.

        Returns the full knowledge pack including root cause, resolution,
        gotchas, validated queries, and any learnings generated.

        Args:
            incident_id: The incident ID to look up.

        Returns:
            Formatted knowledge pack contents or error message.
        """
        try:
            with engine.connect() as conn:
                result = conn.execute(
                    text(
                        "SELECT id, title, severity, root_cause, resolution, "
                        "affected_services, knowledge_pack, resolved_at "
                        "FROM incident_markers WHERE id = :id"
                    ),
                    {"id": incident_id},
                )
                row = result.fetchone()

            if not row:
                return f"Error: Incident #{incident_id} not found."

            title = row[1]
            severity = row[2]
            root_cause = row[3]
            resolution = row[4]
            services = row[5] or []
            kp = row[6] or {}
            resolved_at = row[7]

            lines = [
                f"**Knowledge Pack** — Incident #{incident_id}: {title}",
                f"- Severity: {severity}",
                f"- Services: {', '.join(services) if services else 'unknown'}",
                f"- Status: {'Resolved' if resolved_at else 'ONGOING'}",
                "",
            ]

            if root_cause:
                lines.append(f"**Root Cause:** {root_cause}")
            if resolution:
                lines.append(f"**Resolution:** {resolution}")

            if isinstance(kp, dict) and kp:
                lines.append("")
                if kp.get("gotchas"):
                    lines.append("**Gotchas:**")
                    for g in kp["gotchas"]:
                        lines.append(f"- {g}")
                if kp.get("artifacts"):
                    lines.append("")
                    lines.append("**Linked Artifacts:**")
                    art = kp["artifacts"]
                    if art.get("validated_query"):
                        lines.append(f"- Query: `{art['validated_query']}`")
                    if art.get("learning"):
                        lines.append(f"- Learning: `{art['learning']}`")
                if kp.get("generated_at"):
                    lines.append(f"\n_Knowledge pack generated: {kp['generated_at']}_")
            else:
                lines.append("\n_No knowledge pack generated yet. Use `generate_knowledge_pack` after resolving._")

            return "\n".join(lines)

        except OperationalError as e:
            logger.error("Knowledge pack retrieval failed: %s", e)
            return f"Error: Database connection failed — {e}"
        except DatabaseError as e:
            logger.error("Knowledge pack query error: %s", e)
            return f"Error: {e}"

    return [generate_knowledge_pack, get_incident_knowledge_pack]


# ── Helpers ──────────────────────────────────────────────────────────


def _slugify(text: str) -> str:
    """Convert text to a short, safe slug for naming."""
    slug = text.lower().replace(" ", "_")
    # Keep only alphanumeric and underscores
    slug = "".join(c for c in slug if c.isalnum() or c == "_")
    return slug[:40]


def _extract_symptoms(title: str, root_cause: str, kp: dict | None) -> list[str]:
    """Extract symptom keywords from incident data."""
    symptoms = []
    text = f"{title} {root_cause}".lower()

    symptom_patterns = {
        "oom": "Out of memory / OOM kill",
        "crash": "Service crash / restart loop",
        "timeout": "Request timeout",
        "502": "HTTP 502 Bad Gateway",
        "503": "HTTP 503 Service Unavailable",
        "521": "Cloudflare 521 (origin down)",
        "cert": "TLS certificate issue",
        "dns": "DNS resolution failure",
        "disk": "Disk space exhaustion",
        "memory": "Memory pressure",
        "cpu": "CPU saturation",
        "connection refused": "Connection refused",
        "deploy": "Deployment failure",
        "rollback": "Rollback required",
    }

    for pattern, description in symptom_patterns.items():
        if pattern in text:
            symptoms.append(description)

    if isinstance(kp, dict) and kp.get("symptoms"):
        symptoms.extend(kp["symptoms"])

    return list(dict.fromkeys(symptoms))  # deduplicate preserving order


def _compute_duration(started_at, resolved_at) -> int | None:
    """Compute incident duration in minutes."""
    if not started_at or not resolved_at:
        return None
    try:
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at)
        if isinstance(resolved_at, str):
            resolved_at = datetime.fromisoformat(resolved_at)
        delta = resolved_at - started_at
        return max(0, int(delta.total_seconds() / 60))
    except (ValueError, TypeError):
        return None


def _generate_runbook_suggestion(
    incident_id: int,
    title: str,
    severity: str,
    services: list[str],
    root_cause: str,
    resolution: str,
    started_at: str,
    resolved_at: str,
    existing_kp: dict | None,
) -> str:
    """Generate a markdown runbook patch suggestion."""
    svc_str = ", ".join(services) if services else "unknown"
    gotchas = ""
    if isinstance(existing_kp, dict) and existing_kp.get("gotchas"):
        gotchas_list = "\n".join(f"- {g}" for g in existing_kp["gotchas"])
        gotchas = f"\n### Gotchas\n\n{gotchas_list}\n"

    return f"""### Incident #{incident_id}: {title}

**Severity:** {severity}
**Affected Services:** {svc_str}
**Duration:** {started_at} → {resolved_at}

### Root Cause

{root_cause}

### Resolution Steps

{resolution}
{gotchas}
### Prevention

<!-- TODO: Add prevention steps based on root cause analysis -->

### Detection

To detect this issue early, monitor for:
- Timeline query: `incident_{incident_id}_timeline` (saved to knowledge base)
- Similar incidents: `find_similar_incidents(services="{svc_str}")` or keywords from root cause

---
_Auto-generated from incident #{incident_id}. Review before merging into runbooks._"""
