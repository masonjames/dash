"""Read-only hybrid retrieval over disposable canonical-ID index documents."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from os import getenv
from typing import Any, Awaitable, Callable

from openai import AsyncOpenAI, OpenAIError


logger = logging.getLogger(__name__)
_EMBEDDING_MODEL = "text-embedding-3-small"


@dataclass(frozen=True)
class RetrievalHit:
    canonical_type: str
    canonical_id: str
    environment: str | None
    service: str | None
    incident_type: str | None
    outcome_status: str | None
    score: float
    lexical_relevance: float
    semantic_similarity: float | None


async def embed_query(query_text: str) -> list[float] | None:
    """Return a query embedding when configured; lexical retrieval remains available otherwise."""

    api_key = getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        response = await AsyncOpenAI(api_key=api_key, timeout=5.0, max_retries=0).embeddings.create(
            model=_EMBEDDING_MODEL,
            input=query_text,
        )
    except (OpenAIError, TimeoutError, ValueError) as exc:
        logger.warning("Ops query embedding unavailable; using lexical retrieval: %s", type(exc).__name__)
        return None
    if not response.data:
        return None
    values = list(response.data[0].embedding)
    if len(values) != 1536:
        logger.warning("Ops query embedding has an unexpected dimension; using lexical retrieval")
        return None
    return values


async def search_canonical_documents(
    connect: Callable[[], Awaitable[Any]],
    *,
    query_text: str,
    environment: str | None,
    service: str | None,
    incident_type: str | None,
    outcome_status: str | None,
    canonical_types: tuple[str, ...] = ("outcome",),
    limit: int = 20,
    query_embedding: list[float] | None = None,
    max_age_seconds: int = 7_776_000,
    require_hybrid: bool = True,
) -> list[RetrievalHit]:
    """Fuse FTS and pgvector relevance while returning canonical pointers only.

    The index is intentionally disposable. Freshness and scope metadata are
    enforced before ranking, and only the newest document for each canonical
    record participates so re-indexing cannot overweight an outcome.
    """

    if not query_text.strip() or not canonical_types or not 1 <= limit <= 50 or not 1 <= max_age_seconds <= 31_536_000:
        return []
    embedding = query_embedding if query_embedding is not None else await embed_query(query_text)
    if embedding is not None and len(embedding) != 1536:
        return []
    if require_hybrid and embedding is None:
        logger.warning("Ops hybrid retrieval is unavailable because no query embedding was produced")
        return []
    embedding_literal = f"[{','.join(str(value) for value in embedding)}]" if embedding else None
    query = """
        WITH latest AS (
            SELECT DISTINCT ON (canonical_type, canonical_id)
                   id, canonical_type, canonical_id, environment, service,
                   incident_type, outcome_status, search_vector, embedding,
                   source_updated_at, fresh_until
            FROM ops.ops_retrieval_documents
            WHERE canonical_type = ANY(%s)
            ORDER BY canonical_type, canonical_id, source_updated_at DESC, indexed_at DESC, id
        ),
        filtered AS (
            SELECT id, canonical_type, canonical_id, environment, service,
                   incident_type, outcome_status, search_vector, embedding
            FROM latest
            WHERE (%s::text IS NULL OR LOWER(environment) = LOWER(%s))
              AND (%s::text IS NULL OR LOWER(service) = LOWER(%s))
              AND (%s::text IS NULL OR incident_type = %s)
              AND (%s::text IS NULL OR outcome_status = %s)
              AND (fresh_until IS NULL OR fresh_until > NOW())
              AND source_updated_at >= NOW() - make_interval(secs => %s)
        ),
        lexical AS (
            SELECT id,
                   ts_rank_cd(search_vector, websearch_to_tsquery('english', %s)) AS relevance,
                   ROW_NUMBER() OVER (
                       ORDER BY ts_rank_cd(search_vector, websearch_to_tsquery('english', %s)) DESC, id
                   ) AS rank
            FROM filtered
            WHERE search_vector @@ websearch_to_tsquery('english', %s)
            LIMIT 50
        ),
        semantic AS (
            SELECT id,
                   GREATEST(0.0, LEAST(1.0, 1.0 - (embedding <=> %s::vector))) AS similarity,
                   ROW_NUMBER() OVER (ORDER BY embedding <=> %s::vector, id) AS rank
            FROM filtered
            WHERE %s::text IS NOT NULL AND embedding IS NOT NULL
            LIMIT 50
        ),
        candidates AS (
            SELECT id FROM lexical
            UNION
            SELECT id FROM semantic
        )
        SELECT f.canonical_type, f.canonical_id, f.environment, f.service,
               f.incident_type, f.outcome_status,
               CASE
                   WHEN semantic.similarity IS NOT NULL AND lexical.relevance IS NOT NULL
                       THEN 0.55 * semantic.similarity
                          + 0.45 * (lexical.relevance / (1.0 + lexical.relevance))
                   WHEN semantic.similarity IS NOT NULL THEN semantic.similarity
                   ELSE lexical.relevance / (1.0 + lexical.relevance)
               END AS score,
               COALESCE(lexical.relevance, 0.0) AS lexical_relevance,
               semantic.similarity
        FROM candidates
        JOIN filtered f USING (id)
        LEFT JOIN lexical USING (id)
        LEFT JOIN semantic USING (id)
        ORDER BY score DESC, f.canonical_type, f.canonical_id
        LIMIT %s
    """
    params = (
        list(canonical_types),
        environment,
        environment,
        service,
        service,
        incident_type,
        incident_type,
        outcome_status,
        outcome_status,
        max_age_seconds,
        query_text,
        query_text,
        query_text,
        embedding_literal,
        embedding_literal,
        embedding_literal,
        limit,
    )
    async with await connect() as conn:
        cursor = await conn.execute(query, params)
        rows = await cursor.fetchall()
    return [
        RetrievalHit(
            canonical_type=str(row[0]),
            canonical_id=str(row[1]),
            environment=str(row[2]) if row[2] is not None else None,
            service=str(row[3]) if row[3] is not None else None,
            incident_type=str(row[4]) if row[4] is not None else None,
            outcome_status=str(row[5]) if row[5] is not None else None,
            score=float(row[6]),
            lexical_relevance=float(row[7]),
            semantic_similarity=float(row[8]) if row[8] is not None else None,
        )
        for row in rows
    ]
