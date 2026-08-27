#!/usr/bin/env bash
# Install the repository-pinned Dagger CLI without modifying the host toolchain.
set -euo pipefail

readonly DAGGER_VERSION="0.21.8"
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
    checksum="4759befe3fa951fd2ba05551306023df7e8c7fc9eff57bb823481803cb44b215"
    binary_checksum="414f64941f69fc44339e7148b0cfb0309d6757a6e144b06ff6652a71328c8909"
    ;;
  darwin_arm64)
    checksum="f3f37a831afd53d09bf9c9a9df63492c16ad43622e5c197d9815e82f334ef1c4"
    binary_checksum="0a0c1f2610fe60d2abef5eefdb71b6471508390185359de20d557308de83f839"
    ;;
  linux_amd64)
    checksum="53e226c7da8fb75171e58c35759d736d961ce8b3a12db0baa7b7107954fccc5a"
    binary_checksum="c6d08ba2edf34583844eecbf3ae0897127c0cc8377d151da56c66997cb503db2"
    ;;
  linux_arm64)
    checksum="cd0df4885f2050082932b4abc5a6aad9a733f6aa4e7d8474740558517ffec4af"
    binary_checksum="f07bdcc15d75e96aa78b5cc52ccb3762a36a8744eae5c35db4e34920b7b163cd"
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
    $1 == "dagger" && $2 == wanted { found = 1 }
    END { exit found ? 0 : 1 }
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
