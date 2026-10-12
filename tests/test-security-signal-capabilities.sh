#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="$ROOT/scripts/validate-security-signal-capabilities.sh"
SOURCE="$ROOT/configs/security-signal-capabilities.json"

TMP_DIR="$(mktemp -d)"
chmod 700 "$TMP_DIR"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

"$VALIDATOR" "$SOURCE" >/dev/null

jq \
  '.capabilities[0].method = "POST"' \
  "$SOURCE" \
  > "$TMP_DIR/post.json"

set +e
"$VALIDATOR" "$TMP_DIR/post.json" >/dev/null 2>&1
POST_RC=$?
set -e

[[ "$POST_RC" -ne 0 ]] || {
  echo "FAIL: capability validator accepted POST mutation"
  exit 1
}

jq \
  '.capabilities[0].least_privileged_delegated_permission = "Directory.ReadWrite.All"' \
  "$SOURCE" \
  > "$TMP_DIR/write-permission.json"

set +e
"$VALIDATOR" "$TMP_DIR/write-permission.json" >/dev/null 2>&1
WRITE_RC=$?
set -e

[[ "$WRITE_RC" -ne 0 ]] || {
  echo "FAIL: capability validator accepted write permission"
  exit 1
}

jq \
  '.tenant_write_allowed = true' \
  "$SOURCE" \
  > "$TMP_DIR/write-enabled.json"

set +e
"$VALIDATOR" "$TMP_DIR/write-enabled.json" >/dev/null 2>&1
WRITE_ENABLED_RC=$?
set -e

[[ "$WRITE_ENABLED_RC" -ne 0 ]] || {
  echo "FAIL: capability validator accepted tenant writes"
  exit 1
}

echo "ADVERSARIAL_SECURITY_SIGNAL_CAPABILITY_VALIDATION=PASS"
