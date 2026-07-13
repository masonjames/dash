"""Static release-boundary regression tests."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_container_install_is_frozen_to_uv_lock() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY pyproject.toml uv.lock" in dockerfile
    assert dockerfile.count("uv sync --frozen --no-dev") == 2
    assert "requirements.txt" not in dockerfile


def test_entrypoint_cannot_dump_process_environment() -> None:
    entrypoint = (ROOT / "scripts" / "entrypoint.sh").read_text(encoding="utf-8")

    assert "PRINT_ENV_ON_LOAD" not in entrypoint
    assert "printenv" not in entrypoint


def test_ci_and_manual_publication_use_only_full_commit_sha_tags() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ghcr-build.yml").read_text(encoding="utf-8")
    builder = (ROOT / "scripts" / "build_image.sh").read_text(encoding="utf-8")

    assert "type=sha,format=long,prefix=" in workflow
    assert "latest=false" in workflow
    assert "type=ref" not in workflow
    assert "type=raw" not in workflow
    assert "^[a-f0-9]{40}$" in builder
    assert 'IMAGE_TAG="latest"' not in builder
