from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]
MODULE = ROOT / ".dagger/src/dash_ci/main.py"


def test_dagger_pin_and_repository_bootstrap_are_exact() -> None:
    config = json.loads((ROOT / "dagger.json").read_text())
    bootstrap = (ROOT / "scripts/bootstrap-dagger.sh").read_text()
    assert config["engineVersion"] == "v0.21.8"
    assert 'readonly DAGGER_VERSION="0.21.8"' in bootstrap
    assert "binary_checksum=" in bootstrap
    assert "command -v dagger" not in bootstrap


def test_portable_surface_covers_dash_quality_image_and_postgres_contracts() -> None:
    source = MODULE.read_text()
    for function_name in ("check", "ci", "build", "source_digest", "publish"):
        assert f"async def {function_name}(" in source
    for command in (
        '"ruff", "format", "--check", "."',
        '"ruff", "check", "."',
        '"mypy", "."',
        '"tests/test_postgres_search_path_integration.py"',
        '"--ignore=tests/test_postgres_search_path_integration.py"',
    ):
        assert command in source
    assert 'TARGET_PLATFORM = dagger.Platform("linux/amd64")' in source
    assert "postgres = (\n            dag.container()\n            .from_(PGVECTOR_IMAGE)" in source
    assert "platform=TARGET_PLATFORM" in source.split("def _image(", 1)[1]
    assert "with_service_binding" in source
    assert 'dockerfile="Dockerfile"' in source
    assert "IMAGE_SMOKE_SCRIPT" in source


def test_publication_is_exact_request_and_secret_bound() -> None:
    source = MODULE.read_text()
    for required in (
        "request: dagger.File",
        "registry_token: dagger.Secret",
        'IMAGE_REPOSITORY = "ghcr.io/masonjames/dash"',
        'document["source_revision"]',
        '"approval_reference",',
        '.publish(f"{IMAGE_REPOSITORY}:{revision}")',
        'return f"{IMAGE_REPOSITORY}@{digest}"',
    ):
        assert required in source
    for forbidden in (
        "registry_token: str",
        "docker service",
        "docker stack",
        "dokploy",
        "terraform apply",
    ):
        assert forbidden not in source.lower()


def test_wrapper_is_credential_isolated_and_does_not_use_ambient_dagger() -> None:
    wrapper = (ROOT / "scripts/run-dagger-ci.sh").read_text()
    assert 'dagger_bin="$("$ROOT/scripts/bootstrap-dagger.sh")"' in wrapper
    assert 'export DOCKER_CONFIG="$public_config"' in wrapper
    assert '"$dagger_bin" "$@"' in wrapper
    assert "docker login" not in wrapper
    assert '"${RUNNER_ENVIRONMENT:-}" == "self-hosted"' in wrapper
    assert "DAGGER_CI_HOST_GUARD" in wrapper
    assert 'DAGGER_CI_BIN="$dagger_bin" "$host_guard" --' in wrapper


def test_dependabot_caps_routine_updates_and_keeps_majors_separate() -> None:
    document = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    uv_update = document["updates"][0]
    assert uv_update["package-ecosystem"] == "uv"
    assert uv_update["cooldown"]["default-days"] == 7
    assert uv_update["open-pull-requests-limit"] == 2
    assert uv_update["groups"]["routine-minor-patch"]["update-types"] == [
        "minor",
        "patch",
    ]
    assert all(update["open-pull-requests-limit"] == 0 for update in document["updates"][1:])
