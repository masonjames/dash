#!/usr/bin/env bash
# Run the repository-pinned Dagger CLI with credential-isolated Docker config.
set -euo pipefail

# All Mac callers, including local shells, share the installed admission lease.
if [[ "$(uname -s)" == "Darwin" ]]; then
  mac_ci_guard=/Users/masonjames/.local/libexec/dagger-ci-host-guard
  [[ -x "$mac_ci_guard" ]] || { echo "Mac CI admission guard is not installed" >&2; exit 69; }
  if ! "$mac_ci_guard" --check-lease >/dev/null 2>&1; then
    exec "$mac_ci_guard" -- /bin/bash "$0" "$@"
  fi
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
dagger_bin="$("$ROOT/scripts/bootstrap-dagger.sh")"

if [[ "$#" -eq 0 ]]; then
  set -- check
fi
temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
if [[ "$temp_root" != /* || ! -d "$temp_root" ]]; then
  echo "The Dagger temporary root must be an existing absolute directory" >&2
  exit 64
fi

umask 077
public_config="$(mktemp -d "$temp_root/dash-public-docker.XXXXXX")"
cleanup() {
  local status="$?"
  trap - EXIT
  chmod 700 "$public_config" 2>/dev/null || true
  unlink "$public_config/config.json" 2>/dev/null || true
  rmdir "$public_config" 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT

printf '%s\n' \
  '{"auths":{"https://index.docker.io/v1/":{},"registry.dagger.io":{}}}' \
  > "$public_config/config.json"
chmod 400 "$public_config/config.json"
chmod 500 "$public_config"
unset DOCKER_AUTH_CONFIG
export DOCKER_CONFIG="$public_config"
export DAGGER_ENGINE="image+docker://registry.dagger.io/engine:v1.0.0-beta.21"

if [[ "$(uname -s)" == "Darwin" ]]; then
  DAGGER_CI_BIN="$dagger_bin" "$mac_ci_guard" -- "$dagger_bin" "$@"
elif [[ "${RUNNER_ENVIRONMENT:-}" == "self-hosted" ]]; then
  host_guard="${DAGGER_CI_HOST_GUARD:-/usr/local/libexec/dagger-ci-host-guard}"
  if [[ ! -x "$host_guard" ]]; then
    echo "Self-hosted Dagger execution requires the admitted host-wide guard" >&2
    exit 69
  fi
  DAGGER_CI_BIN="$dagger_bin" "$host_guard" -- "$dagger_bin" "$@"
else
  "$dagger_bin" "$@"
fi
