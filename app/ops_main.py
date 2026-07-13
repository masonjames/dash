"""Minimal private process for Dockhand-to-Dash Ops contracts.

Run separately from the public AgentOS process:

    uvicorn app.ops_main:app --host 0.0.0.0 --port 8001
"""

from fastapi import FastAPI

from dash.internal_ops import router as internal_ops_router

app = FastAPI(
    title="Dash Private Ops",
    version="1",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.include_router(internal_ops_router)
