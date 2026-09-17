# ===========================================================================
# Dash - Private Ops Service
# ===========================================================================

FROM agnohq/python:3.12

# ---------------------------------------------------------------------------
# Application code
# ---------------------------------------------------------------------------
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY . .
RUN uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:${PATH}"
ENV PYTHONPATH=/app

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
RUN chmod +x /app/scripts/entrypoint.sh
ENTRYPOINT ["/app/scripts/entrypoint.sh"]

# ---------------------------------------------------------------------------
# Default private Ops command
# ---------------------------------------------------------------------------
CMD ["uvicorn", "app.ops_main:app", "--host", "0.0.0.0", "--port", "8001"]
