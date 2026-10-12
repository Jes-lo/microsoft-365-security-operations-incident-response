#!/usr/bin/env bash
set -euo pipefail

FILE="${1:-configs/security-signal-capabilities.json}"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

[[ -f "$FILE" ]] || fail "capability configuration file missing"

jq -e . "$FILE" >/dev/null \
  || fail "capability configuration is invalid JSON"

[[ "$(jq -r '.schema_version' "$FILE")" == "1" ]] \
  || fail "unexpected capability schema version"

[[ "$(jq -r '.discovery_mode' "$FILE")" == "read-only" ]] \
  || fail "discovery mode must be read-only"

[[ "$(jq -r '.live_validation_state' "$FILE")" == "NOT_RUN" ]] \
  || fail "initial live validation state must be NOT_RUN"

[[ "$(jq -r '.tenant_write_allowed' "$FILE")" == "false" ]] \
  || fail "tenant writes must be prohibited"

CAPABILITY_COUNT="$(jq '.capabilities | length' "$FILE")"

[[ "$CAPABILITY_COUNT" -eq 6 ]] \
  || fail "expected exactly six initial signal capabilities"

DUPLICATE_ID_COUNT="$(
  jq \
    '[.capabilities[].id] |
     group_by(.) |
     map(select(length > 1)) |
     length' \
    "$FILE"
)"

[[ "$DUPLICATE_ID_COUNT" -eq 0 ]] \
  || fail "duplicate capability IDs detected"

NON_GET_COUNT="$(
  jq \
    '[.capabilities[] |
      select(.method != "GET")
    ] |
    length' \
    "$FILE"
)"

[[ "$NON_GET_COUNT" -eq 0 ]] \
  || fail "non-GET capability detected"

WRITE_ALLOWED_COUNT="$(
  jq \
    '[.capabilities[] |
      select(.tenant_write_allowed != false)
    ] |
    length' \
    "$FILE"
)"

[[ "$WRITE_ALLOWED_COUNT" -eq 0 ]] \
  || fail "write-enabled capability detected"

NON_V1_ENDPOINT_COUNT="$(
  jq \
    '[.capabilities[] |
      select(
        (.endpoint | type) != "string"
        or
        (.endpoint | startswith("/v1.0/") | not)
      )
    ] |
    length' \
    "$FILE"
)"

[[ "$NON_V1_ENDPOINT_COUNT" -eq 0 ]] \
  || fail "all capability endpoints must use Microsoft Graph v1.0"

READWRITE_PERMISSION_COUNT="$(
  jq \
    '[.capabilities[] |
      select(
        .least_privileged_delegated_permission |
        test("ReadWrite|Write"; "i")
      )
    ] |
    length' \
    "$FILE"
)"

[[ "$READWRITE_PERMISSION_COUNT" -eq 0 ]] \
  || fail "write-capable Microsoft Graph permission detected"

REQUIRED_IDS=(
  "entra-directory-audit"
  "entra-sign-ins"
  "defender-alerts"
  "defender-incidents"
  "entra-risky-users"
  "entra-risk-detections"
)

for ID in "${REQUIRED_IDS[@]}"; do
  COUNT="$(
    jq \
      --arg id "$ID" \
      '[.capabilities[] |
        select(.id == $id)
      ] |
      length' \
      "$FILE"
  )"

  [[ "$COUNT" -eq 1 ]] \
    || fail "missing or duplicate required capability: $ID"
done

declare -A EXPECTED_PERMISSIONS=(
  ["entra-directory-audit"]="AuditLog.Read.All"
  ["entra-sign-ins"]="AuditLog.Read.All"
  ["defender-alerts"]="SecurityAlert.Read.All"
  ["defender-incidents"]="SecurityIncident.Read.All"
  ["entra-risky-users"]="IdentityRiskyUser.Read.All"
  ["entra-risk-detections"]="IdentityRiskEvent.Read.All"
)

for ID in "${!EXPECTED_PERMISSIONS[@]}"; do
  ACTUAL="$(
    jq -r \
      --arg id "$ID" \
      '.capabilities[] |
       select(.id == $id) |
       .least_privileged_delegated_permission' \
      "$FILE"
  )"

  [[ "$ACTUAL" == "${EXPECTED_PERMISSIONS[$ID]}" ]] \
    || fail "unexpected least-privileged permission for $ID"
done

printf 'SECURITY_SIGNAL_CAPABILITY_VALIDATION=PASS\n'
