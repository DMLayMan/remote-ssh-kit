#!/bin/bash
set -euo pipefail
# Maintainer check only. Installs nothing globally and never prints findings.
repo=$(cd "$(dirname "$0")/.." && pwd)
version=8.30.1
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) platform=darwin_arm64; checksum=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 ;;
  Linux-x86_64) platform=linux_x64; checksum=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
  *) echo 'GITLEAKS_CHECK_UNSUPPORTED_PLATFORM' >&2; exit 2 ;;
esac
umask 077
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
curl --fail --silent --show-error --location --retry 2 --max-time 60 \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_${platform}.tar.gz" -o "$stage/scanner.tar.gz"
if command -v sha256sum >/dev/null; then actual=$(sha256sum "$stage/scanner.tar.gz" | cut -d ' ' -f 1); else actual=$(shasum -a 256 "$stage/scanner.tar.gz" | cut -d ' ' -f 1); fi
[ "$actual" = "$checksum" ] || { echo 'GITLEAKS_CHECK_DOWNLOAD_MISMATCH' >&2; exit 2; }
tar -xzf "$stage/scanner.tar.gz" -C "$stage" gitleaks
: > "$stage/empty-ignore"
unset GITLEAKS_CONFIG GITLEAKS_CONFIG_TOML
common=(--no-banner --no-color --redact=100 --ignore-gitleaks-allow --gitleaks-ignore-path "$stage/empty-ignore" --max-decode-depth 5)
if ! "$stage/gitleaks" git "$repo" --log-opts='--all --full-history' "${common[@]}" > "$stage/history.log" 2>&1; then
  echo 'GITLEAKS_HISTORY_CHECK_FAILED: inspect locally using a private, redacted report.' >&2; exit 1
fi
if [ "${1:-}" != '' ]; then
  [ "$#" = 1 ] && [ -d "$1" ] || { echo 'GITLEAKS_CHECK_INVALID_DIRECTORY' >&2; exit 2; }
  if ! "$stage/gitleaks" dir "$1" --max-archive-depth 2 "${common[@]}" > "$stage/package.log" 2>&1; then
    echo 'GITLEAKS_PACKAGE_CHECK_FAILED: inspect locally using a private, redacted report.' >&2; exit 1
  fi
fi
echo 'GITLEAKS_CHECK_OK'
