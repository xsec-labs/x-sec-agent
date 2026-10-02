#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORDLIST_DIR="$SKILL_DIR/wordlists"
TARGET="$WORDLIST_DIR/rockyou.txt"
URL="${ROCKYOU_URL:-https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz}"
MIN_BYTES="${ROCKYOU_MIN_BYTES:-100000000}"

file_size() {
  wc -c < "$1" | tr -d '[:space:]'
}

if [[ -f "$TARGET" ]]; then
  size="$(file_size "$TARGET")"
  if [[ "$size" -ge "$MIN_BYTES" ]]; then
    echo "[ok] rockyou.txt already exists: $TARGET ($size bytes)"
    exit 0
  fi

  echo "[warn] Existing rockyou.txt is smaller than expected ($size bytes), refreshing it."
fi

mkdir -p "$WORDLIST_DIR"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/xsec-rockyou.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

archive="$tmp_dir/rockyou.txt.tar.gz"

echo "[info] Downloading rockyou.txt from SecLists..."
if command -v curl >/dev/null 2>&1; then
  curl -fL --retry 3 --connect-timeout 20 -o "$archive" "$URL"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$archive" "$URL"
else
  echo "[error] Need curl or wget to download rockyou.txt." >&2
  exit 1
fi

tar -xzf "$archive" -C "$tmp_dir"
extracted="$(find "$tmp_dir" -type f -name 'rockyou.txt' -print -quit)"

if [[ -z "$extracted" ]]; then
  echo "[error] Downloaded archive did not contain rockyou.txt." >&2
  exit 1
fi

mv "$extracted" "$TARGET"
chmod 0644 "$TARGET" 2>/dev/null || true

size="$(file_size "$TARGET")"
if [[ "$size" -lt "$MIN_BYTES" ]]; then
  echo "[error] Downloaded rockyou.txt is unexpectedly small ($size bytes)." >&2
  exit 1
fi

echo "[ok] rockyou.txt ready: $TARGET ($size bytes)"
