#!/usr/bin/env bash
# Install the repository-pinned Dagger CLI without modifying the host toolchain.
set -euo pipefail

readonly DAGGER_VERSION="1.0.0-beta.21"
readonly ROOT="$(cd "$(dirname "$0")/.." && pwd)"
readonly INSTALL_ROOT="${DASH_DAGGER_INSTALL_ROOT:-$ROOT/.tools/dagger}"
readonly TARGET_DIR="$INSTALL_ROOT/v$DAGGER_VERSION"
readonly TARGET="$TARGET_DIR/dagger"

if [[ "$INSTALL_ROOT" != /* || "$INSTALL_ROOT" == "/" ]]; then
  echo "DASH_DAGGER_INSTALL_ROOT must be an absolute, non-root path" >&2
  exit 64
fi

case "$(uname -s)" in
  Darwin) os="darwin" ;;
  Linux) os="linux" ;;
  *) echo "Unsupported operating system for Dagger bootstrap" >&2; exit 69 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "Unsupported processor architecture for Dagger bootstrap" >&2; exit 69 ;;
esac

archive="dagger_v${DAGGER_VERSION}_${os}_${arch}.tar.gz"
case "${os}_${arch}" in
  darwin_amd64)
    checksum="fdbe191c965d240ee9cc90719fa9dca1586805cbb89b0a0087314a84a0937354"
    binary_checksum="0dfc7e18c60e2400d513b08c625e8f8b4ded53515d2dff1486c495be9441a3ea"
    ;;
  darwin_arm64)
    checksum="781f4862c022a19b9a4c498b59e1d9cfda1ee3cdc8ce210e4545bd8842a7416d"
    binary_checksum="0646cb9491a47b5a7abc5dfb74af5bd561f498f74e3cf4b325c53a9b6cd2b7ea"
    ;;
  linux_amd64)
    checksum="c5ac777a5c99089869660943381136e22177b59a46412e310c2fef594760a041"
    binary_checksum="989220a1a61af238e74207f2f59ad0dfd8b00284223d93f243aa20c04cd0748a"
    ;;
  linux_arm64)
    checksum="ba9d55638636918a3404313511bceba5cc0af22f487c1c1b6a5ba60ce70a61bb"
    binary_checksum="068f745b53251693f2614d51378a581cc318a677d3971bceb1e88cd96fa98b68"
    ;;
  *) echo "No admitted Dagger checksum for this platform" >&2; exit 69 ;;
esac

file_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

version_is_exact() {
  [[ -f "$TARGET" && ! -L "$TARGET" && -x "$TARGET" ]] \
    && [[ "$(file_sha256 "$TARGET")" == "$binary_checksum" ]] \
    && "$TARGET" version 2>/dev/null | awk -v wanted="v$DAGGER_VERSION" '
    $1 == "version:" && $2 == wanted && NF == 2 { found++ }
    END { exit found == 1 ? 0 : 1 }
  '
}

if version_is_exact; then
  printf '%s\n' "$TARGET"
  exit 0
fi

for command in curl tar mktemp mkdir mv chmod find rmdir; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Required bootstrap command not found: $command" >&2
    exit 69
  }
done
if command -v shasum >/dev/null 2>&1; then
  checksum_command=(shasum -a 256 --check)
elif command -v sha256sum >/dev/null 2>&1; then
  checksum_command=(sha256sum -c)
else
  echo "A SHA-256 verification command is required" >&2
  exit 69
fi

temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
if [[ "$temp_root" != /* || ! -d "$temp_root" ]]; then
  echo "The temporary root must be an existing absolute directory" >&2
  exit 64
fi
umask 077
download_dir="$(mktemp -d "$temp_root/dash-dagger.XXXXXX")"
cleanup() {
  local status="$?"
  trap - EXIT
  find "$download_dir" -type f -exec chmod 600 {} + 2>/dev/null || true
  find "$download_dir" -depth -type f -delete 2>/dev/null || true
  find "$download_dir" -depth -type d -exec rmdir {} \; 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT

curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  "https://dl.dagger.io/dagger/releases/${DAGGER_VERSION}/${archive}" \
  --output "$download_dir/$archive"
(
  cd "$download_dir"
  printf '%s  %s\n' "$checksum" "$archive" | "${checksum_command[@]}" >&2
  if [[ "$(tar -tzf "$archive")" != $'LICENSE\ndagger' ]]; then
    echo "Dagger archive contains unexpected entries" >&2
    exit 70
  fi
  tar -xzf "$archive" dagger
)
if [[ ! -f "$download_dir/dagger" || -L "$download_dir/dagger" ]] \
  || [[ "$(file_sha256 "$download_dir/dagger")" != "$binary_checksum" ]]; then
  echo "Extracted Dagger binary failed verification" >&2
  exit 70
fi

mkdir -p "$TARGET_DIR"
if [[ -L "$INSTALL_ROOT" || -L "$TARGET_DIR" ]]; then
  echo "Dagger install path may not traverse symbolic links" >&2
  exit 70
fi
chmod 700 "$TARGET_DIR"
candidate="$TARGET_DIR/.dagger.$$"
mv "$download_dir/dagger" "$candidate"
chmod 755 "$candidate"
mv "$candidate" "$TARGET"
version_is_exact || {
  echo "Installed Dagger failed its exact-version verification" >&2
  exit 70
}
printf '%s\n' "$TARGET"
