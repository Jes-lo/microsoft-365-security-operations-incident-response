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

LIVE_VALIDATION_STATE="$(
  jq -r '.live_validation_state' "$FILE"
)"

case "$LIVE_VALIDATION_STATE" in
  NOT_RUN|AUDITLOG_READ_VALIDATED|AUDITLOG_READ_PARTIAL|SECURITY_SIGNAL_DISCOVERY_COMPLETE)
    ;;
  *)
    fail "unexpected live validation state"
    ;;
esac

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

LIVE_RESULT_COUNT="$(
  jq \
    '[.capabilities[] |
      select(has("live_validation"))
    ] |
    length' \
    "$FILE"
)"

case "$LIVE_VALIDATION_STATE" in
  NOT_RUN)
    EXPECTED_LIVE_COUNT=0
    ;;
  AUDITLOG_READ_VALIDATED|AUDITLOG_READ_PARTIAL)
    EXPECTED_LIVE_COUNT=2
    ;;
  SECURITY_SIGNAL_DISCOVERY_COMPLETE)
    EXPECTED_LIVE_COUNT=6
    ;;
esac

[[ "$LIVE_RESULT_COUNT" -eq "$EXPECTED_LIVE_COUNT" ]] \
  || fail "unexpected live validation result count"

if [[ "$LIVE_VALIDATION_STATE" != "NOT_RUN" ]]; then

  REQUIRED_LIVE_IDS=(
    "entra-directory-audit"
    "entra-sign-ins"
  )

  if [[ "$LIVE_VALIDATION_STATE" == "SECURITY_SIGNAL_DISCOVERY_COMPLETE" ]]; then
    REQUIRED_LIVE_IDS+=(
      "defender-alerts"
      "defender-incidents"
      "entra-risky-users"
      "entra-risk-detections"
    )
  fi

  for ID in "${REQUIRED_LIVE_IDS[@]}"; do

    RESULT_COUNT="$(
      jq \
        --arg id "$ID" \
        '[.capabilities[] |
          select(
            .id == $id
            and
            has("live_validation")
          )
        ] |
        length' \
        "$FILE"
    )"

    [[ "$RESULT_COUNT" -eq 1 ]] \
      || fail "missing live validation result for $ID"

  done

  INVALID_CLASSIFICATION_COUNT="$(
    jq \
      '[.capabilities[] |
        select(has("live_validation")) |
        select(
          .live_validation.classification != "AVAILABLE"
          and
          .live_validation.classification != "ACCESS_OR_LICENSE_DENIED"
          and
          .live_validation.classification != "ENDPOINT_OR_PRODUCT_UNAVAILABLE"
        )
      ] |
      length' \
      "$FILE"
  )"

  [[ "$INVALID_CLASSIFICATION_COUNT" -eq 0 ]] \
    || fail "unexpected live capability classification"

  INVALID_HTTP_MAPPING_COUNT="$(
    jq \
      '[.capabilities[] |
        select(has("live_validation")) |
        select(
          (
            .live_validation.classification == "AVAILABLE"
            and
            .live_validation.http_status != 200
          )
          or
          (
            .live_validation.classification == "ACCESS_OR_LICENSE_DENIED"
            and
            .live_validation.http_status != 403
          )
          or
          (
            .live_validation.classification == "ENDPOINT_OR_PRODUCT_UNAVAILABLE"
            and
            .live_validation.http_status != 404
          )
        )
      ] |
      length' \
      "$FILE"
  )"

  [[ "$INVALID_HTTP_MAPPING_COUNT" -eq 0 ]] \
    || fail "invalid live HTTP/classification mapping"

  LIVE_WRITE_SCOPE_COUNT="$(
    jq \
      '[.capabilities[] |
        select(has("live_validation")) |
        select(.live_validation.write_scope_count != 0)
      ] |
      length' \
      "$FILE"
  )"

  [[ "$LIVE_WRITE_SCOPE_COUNT" -eq 0 ]] \
    || fail "live discovery contains write-capable scope"

  LIVE_UNEXPECTED_SCOPE_COUNT="$(
    jq \
      '[.capabilities[] |
        select(has("live_validation")) |
        select(.live_validation.unexpected_scope_count != 0)
      ] |
      length' \
      "$FILE"
  )"

  [[ "$LIVE_UNEXPECTED_SCOPE_COUNT" -eq 0 ]] \
    || fail "live discovery contains unexpected scope"

  PROBE_WRITE_COUNT="$(
    jq \
      '[.capabilities[] |
        select(has("live_validation")) |
        select(
          .live_validation.tenant_write_performed_by_probe != false
        )
      ] |
      length' \
      "$FILE"
  )"

  [[ "$PROBE_WRITE_COUNT" -eq 0 ]] \
    || fail "live discovery records investigation-time tenant write"

  RAW_EVIDENCE_COUNT="$(
    jq \
      '[.capabilities[] |
        select(has("live_validation")) |
        select(
          .live_validation.raw_evidence_retained != false
        )
      ] |
      length' \
      "$FILE"
  )"

  [[ "$RAW_EVIDENCE_COUNT" -eq 0 ]] \
    || fail "live discovery retained raw evidence"

  NON_DEDICATED_APP_COUNT="$(
    jq \
      '[.capabilities[] |
        select(has("live_validation")) |
        select(
          .live_validation.authentication_application != "DEDICATED_PROJECT_APP"
        )
      ] |
      length' \
      "$FILE"
  )"

  [[ "$NON_DEDICATED_APP_COUNT" -eq 0 ]] \
    || fail "live discovery did not use dedicated project application"

  SHARED_GRAPH_APP_COUNT="$(
    jq \
      '[.capabilities[] |
        select(has("live_validation")) |
        select(
          .live_validation.default_graph_powershell_application_used != false
        )
      ] |
      length' \
      "$FILE"
  )"

  [[ "$SHARED_GRAPH_APP_COUNT" -eq 0 ]] \
    || fail "shared Microsoft Graph PowerShell application was used"

fi

printf 'SECURITY_SIGNAL_CAPABILITY_VALIDATION=PASS\n'
