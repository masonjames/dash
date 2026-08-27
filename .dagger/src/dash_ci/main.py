from __future__ import annotations

import asyncio
import json
import re

import dagger
from dagger import check as dagger_check
from dagger import dag, function, object_type


PYTHON_IMAGE = (
    "python:3.12.11-bookworm@"
    "sha256:13c9584604a99ca134c4f41800f74ffc64ee6ac8cf555cf1e704a6087fc84f12"
)
PGVECTOR_IMAGE = (
    "agnohq/pgvector@"
    "sha256:e502d095cfb097bc6a4ac8b4bf12224d64c0a0d79fc2fe2b691a268ea2452681"
)
TARGET_PLATFORM = dagger.Platform("linux/amd64")
IMAGE_REPOSITORY = "ghcr.io/masonjames/dash"

SOURCE_IGNORES = [
    ".git",
    "**/.git",
    ".dagger/sdk",
    ".tools",
    ".tools/**",
    ".venv",
    ".venv/**",
    "**/__pycache__",
    "**/.pytest_cache",
    "**/.ruff_cache",
    "**/.mypy_cache",
    "**/.env",
    "**/.env.*",
    "**/*.key",
    "**/*.pem",
    "build",
    "dist",
]

POSTGRES_WAIT_SCRIPT = r"""
import os
import time

import psycopg

dsn = os.environ["DASH_TEST_POSTGRES_DSN"]
for attempt in range(60):
    try:
        with psycopg.connect(dsn):
            break
    except psycopg.OperationalError:
        if attempt == 59:
            raise
        time.sleep(1)
"""

IMAGE_SMOKE_SCRIPT = r"""
from app.ops_main import app
from dash.ops_indexer import INDEXER_NAME

assert INDEXER_NAME == "dash-canonical-hybrid-v1"
assert sorted(route.path for route in app.routes) == [
    "/internal/health/ready",
    "/internal/ops/evaluate-outcome",
    "/internal/ops/investigate",
]
"""

SOURCE_DIGEST_SCRIPT = r"""
import hashlib
import os
from pathlib import Path

root = Path("/source")
digest = hashlib.sha256()
for current, directories, files in os.walk(root):
    directories.sort()
    files.sort()
    current_path = Path(current)
    for directory in directories:
        path = current_path / directory
        if path.is_symlink():
            raise SystemExit("filtered source contains a symbolic-link directory")
        digest.update(b"D\0" + path.relative_to(root).as_posix().encode() + b"\0")
    for filename in files:
        path = current_path / filename
        if path.is_symlink() or not path.is_file():
            raise SystemExit("filtered source contains a non-regular file")
        executable = b"1" if path.stat().st_mode & 0o111 else b"0"
        digest.update(
            b"F\0"
            + path.relative_to(root).as_posix().encode()
            + b"\0"
            + executable
            + b"\0"
        )
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        digest.update(b"\0")
print("sha256:" + digest.hexdigest())
"""


@object_type
class DashCi:
    @function
    @dagger_check
    async def check(self, ws: dagger.Workspace) -> str:
        """Run Ruff, mypy, pytest, and the PostgreSQL boundary proof."""
        source = self._source(ws)
        postgres = (
            dag.container(platform=TARGET_PLATFORM)
            .from_(PGVECTOR_IMAGE)
            .with_env_variable("POSTGRES_USER", "ai")
            .with_env_variable("POSTGRES_DB", "dash_search_path_ci")
            .with_env_variable("POSTGRES_HOST_AUTH_METHOD", "trust")
            .with_exposed_port(5432)
            .as_service()
        )
        postgres_test = (
            self._test_environment(source)
            .with_service_binding("postgres-search-path", postgres)
            .with_env_variable(
                "DASH_TEST_POSTGRES_DSN",
                "postgresql://ai@postgres-search-path:5432/dash_search_path_ci",
            )
            .with_exec(["python", "-c", POSTGRES_WAIT_SCRIPT])
            .with_exec(
                [
                    "uv",
                    "run",
                    "pytest",
                    "-q",
                    "tests/test_postgres_search_path_integration.py",
                ]
            )
        )
        offline_test = (
            self._test_environment(source)
            .with_exec(["uv", "run", "ruff", "format", "--check", "."])
            .with_exec(["uv", "run", "ruff", "check", "."])
            .with_exec(["uv", "run", "mypy", "."])
            .with_exec(
                [
                    "uv",
                    "run",
                    "pytest",
                    "-q",
                    "--ignore=tests/test_postgres_search_path_integration.py",
                ]
            )
        )
        await asyncio.gather(postgres_test.sync(), offline_test.sync())
        return "passed"

    @function
    async def ci(self, ws: dagger.Workspace) -> str:
        """Compatibility alias for the complete portable check."""
        return await self.check(ws)

    @function
    async def build(self, ws: dagger.Workspace) -> dagger.Container:
        """Build and smoke-test the linux/amd64 production image."""
        image = self._image(ws)
        await (
            image.with_entrypoint([])
            .with_exec(["python", "-c", IMAGE_SMOKE_SCRIPT])
            .sync()
        )
        return image

    @function
    async def source_digest(self, ws: dagger.Workspace) -> str:
        """Return a SHA-256 digest of the canonical filtered source input."""
        return (
            await dag.container(platform=TARGET_PLATFORM)
            .from_(PYTHON_IMAGE)
            .with_directory("/source", self._source(ws))
            .with_exec(["python", "-c", SOURCE_DIGEST_SCRIPT])
            .stdout()
        ).strip()

    @function
    async def publish(
        self,
        ws: dagger.Workspace,
        request: dagger.File,
        registry_username: str,
        registry_token: dagger.Secret,
    ) -> str:
        """Publish an approved exact-revision image and return a digest-only reference."""
        document = json.loads(await request.contents())
        revision = self._validate_publish_request(document)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", registry_username):
            raise ValueError("registry_username is not a valid GHCR identity")
        published_reference = await (
            self._image(ws)
            .with_registry_auth("ghcr.io", registry_username, registry_token)
            .publish(f"{IMAGE_REPOSITORY}:{revision}")
        )
        digest = published_reference.rsplit("@", 1)[-1]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("registry did not return an immutable image digest")
        return f"{IMAGE_REPOSITORY}@{digest}"

    @staticmethod
    def _source(ws: dagger.Workspace) -> dagger.Directory:
        return ws.directory("/", exclude=SOURCE_IGNORES, gitignore=True)

    @staticmethod
    def _test_environment(source: dagger.Directory) -> dagger.Container:
        return (
            dag.container(platform=TARGET_PLATFORM)
            .from_(PYTHON_IMAGE)
            .with_directory("/src", source)
            .with_workdir("/src")
            .with_exec(["python", "-m", "pip", "install", "--no-cache-dir", "uv==0.7.7"])
            .with_exec(["uv", "sync", "--frozen", "--extra", "dev"])
        )

    @classmethod
    def _image(cls, ws: dagger.Workspace) -> dagger.Container:
        return cls._source(ws).docker_build(
            dockerfile="Dockerfile",
            platform=TARGET_PLATFORM,
        )

    @staticmethod
    def _validate_publish_request(document: object) -> str:
        required = {
            "kind",
            "schema_version",
            "repository",
            "source_revision",
            "operation",
            "target_platform",
            "requester_identity",
            "approval_reference",
        }
        if not isinstance(document, dict) or set(document) != required:
            raise ValueError("publication requires an exact BuildRequestV1 shape")
        if document["kind"] != "BuildRequestV1" or document["schema_version"] != 1:
            raise ValueError("unsupported build request version")
        if document["repository"] != "masonjames/dash":
            raise ValueError("build request repository does not match this module")
        revision = document["source_revision"]
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("publication requires an exact source revision")
        if document["operation"] != "publish":
            raise ValueError("publish requires a publication build request")
        if document["target_platform"] != "linux/amd64":
            raise ValueError("publish target must be linux/amd64")
        for field in ("requester_identity", "approval_reference"):
            if not isinstance(document[field], str) or not document[field]:
                raise ValueError(f"{field} must be present")
        return revision
