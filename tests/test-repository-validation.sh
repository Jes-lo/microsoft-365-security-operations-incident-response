#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="$ROOT/scripts/validate-repository.sh"

"$VALIDATOR" "$ROOT" >/dev/null

TMP_DIR="$(mktemp -d)"
chmod 700 "$TMP_DIR"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TMP_DIR/repo"

tar \
  --exclude='.git' \
  -C "$ROOT" \
  -cf - \
  . \
  | tar \
      -C "$TMP_DIR/repo" \
      -xf -

rm "$TMP_DIR/repo/SECURITY.md"

set +e

"$TMP_DIR/repo/scripts/validate-repository.sh" \
  "$TMP_DIR/repo" \
  >/dev/null 2>&1

MISSING_SECURITY_RC=$?

set -e

[[ "$MISSING_SECURITY_RC" -ne 0 ]] || {
  echo "FAIL: validator accepted repository without SECURITY.md"
  exit 1
}

cp "$ROOT/SECURITY.md" \
  "$TMP_DIR/repo/SECURITY.md"

printf '%s\n' \
  '-----BEGIN '"PRIVATE KEY-----" \
  'adversarial-placeholder-not-a-real-key' \
  '-----END '"PRIVATE KEY-----" \
  > "$TMP_DIR/repo/docs/evidence/adversarial-private-key.txt"

set +e

"$TMP_DIR/repo/scripts/validate-repository.sh" \
  "$TMP_DIR/repo" \
  >/dev/null 2>&1

PRIVATE_KEY_RC=$?

set -e

[[ "$PRIVATE_KEY_RC" -ne 0 ]] || {
  echo "FAIL: validator accepted private-key marker"
  exit 1
}

echo "ADVERSARIAL_REPOSITORY_VALIDATION=PASS"
