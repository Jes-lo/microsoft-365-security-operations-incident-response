#!/usr/bin/env bash

set -euo pipefail

fail() {
  printf 'IDENTITY_INVESTIGATION_VALIDATION=FAIL: %s\n' "$1" >&2
  exit 1
}

ROOT="$(
  cd \
    "$(dirname "${BASH_SOURCE[0]}")/.." \
    >/dev/null 2>&1 &&
  pwd
)"

CONTRACT="$ROOT/configs/identity-incident-investigation-contract.json"
CONVERTER="$ROOT/automation/powershell/Convert-IdentitySecuritySignals.ps1"
EVIDENCE="$ROOT/docs/evidence/IDENTITY-SECURITY-INCIDENT-INVESTIGATION-LIVE-VALIDATION.md"

[[ -f "$CONTRACT" ]] \
  || fail "identity investigation contract missing"

[[ -f "$CONVERTER" ]] \
  || fail "identity signal converter missing"

[[ -f "$EVIDENCE" ]] \
  || fail "sanitized live validation evidence missing"

jq -e . "$CONTRACT" >/dev/null \
  || fail "identity investigation contract invalid"

[[ "$(jq -r '.schema_version' "$CONTRACT")" == "1" ]] \
  || fail "unexpected schema version"

[[ "$(jq -r '.feature' "$CONTRACT")" == "4" ]] \
  || fail "unexpected feature number"

[[ "$(jq -r '.phase' "$CONTRACT")" == "LIVE_VALIDATION_COMPLETE" ]] \
  || fail "unexpected Feature 4 phase"

[[ "$(jq -r '.live_validation_state' "$CONTRACT")" == "IDENTITY_SECURITY_INCIDENT_INVESTIGATION_COMPLETE" ]] \
  || fail "unexpected Feature 4 live validation state"

SURFACE_COUNT="$(
  jq '.investigation_surfaces | length' \
    "$CONTRACT"
)"

[[ "$SURFACE_COUNT" -eq 3 ]] \
  || fail "unexpected investigation surface count"

INVALID_METHOD_COUNT="$(
  jq \
    '[.investigation_surfaces[] |
      select(.method != "GET")
    ] |
    length' \
    "$CONTRACT"
)"

[[ "$INVALID_METHOD_COUNT" -eq 0 ]] \
  || fail "non-GET investigation method detected"

INVALID_FEATURE2_STATE_COUNT="$(
  jq \
    '[.investigation_surfaces[] |
      select(.feature_2_classification != "AVAILABLE")
    ] |
    length' \
    "$CONTRACT"
)"

[[ "$INVALID_FEATURE2_STATE_COUNT" -eq 0 ]] \
  || fail "Feature 4 uses a surface not AVAILABLE in Feature 2"

[[ "$(
  jq -r \
    '.live_query_boundary.tenant_write_allowed' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "tenant writes allowed"

[[ "$(
  jq -r \
    '.live_query_boundary.new_permission_grant_allowed' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "new permission grants allowed"

[[ "$(
  jq -r \
    '.live_query_boundary.automatic_role_assignment_allowed' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "automatic role assignment allowed"

[[ "$(
  jq -r \
    '.live_query_boundary.trial_activation_allowed' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "trial activation allowed"

[[ "$(
  jq -r \
    '.privacy_boundary.raw_user_principal_name_persisted' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "raw UPN persistence allowed"

[[ "$(
  jq -r \
    '.privacy_boundary.raw_user_id_persisted' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "raw user ID persistence allowed"

[[ "$(
  jq -r \
    '.privacy_boundary.raw_ip_address_persisted' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "raw IP persistence allowed"

[[ "$(
  jq -r \
    '.privacy_boundary.raw_graph_payload_persisted' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "raw Graph payload persistence allowed"

REQUIRED_SURFACES=(
  "entra-sign-ins"
  "entra-directory-audit"
  "entra-risk-detections"
)

for ID in "${REQUIRED_SURFACES[@]}"; do
  COUNT="$(
    jq \
      --arg id "$ID" \
      '[.investigation_surfaces[] |
        select(.id == $id)
      ] |
      length' \
      "$CONTRACT"
  )"

  [[ "$COUNT" -eq 1 ]] \
    || fail "required investigation surface missing: $ID"
done

[[ "$(
  jq \
    '[.excluded_surfaces[] |
      select(
        .id == "entra-risky-users"
        and
        .feature_2_classification == "ACCESS_OR_LICENSE_DENIED"
      )
    ] |
    length' \
    "$CONTRACT"
)" -eq 1 ]] \
  || fail "risky-users Feature 2 boundary not preserved"

if grep -nEI \
  -- \
  'Connect-MgGraph|Invoke-MgGraphRequest|New-Mg|Update-Mg|Remove-Mg|ReadWrite' \
  "$CONVERTER"
then
  fail "Feature 4A local converter contains Graph access/write patterns"
fi

grep -Fq \
  'SUBJECT-{0:D3}' \
  "$CONVERTER" \
  || fail "subject aliasing missing"

grep -Fq \
  'raw_identifiers_retained = $false' \
  "$CONVERTER" \
  || fail "raw identifier non-retention assertion missing"

grep -Fq \
  'raw_graph_payload_retained = $false' \
  "$CONVERTER" \
  || fail "raw Graph payload non-retention assertion missing"

[[ "$(
  jq -r '.live_validation.authentication_mode' "$CONTRACT"
)" == "DELEGATED_READ_ONLY" ]] \
  || fail "unexpected live authentication mode"

[[ "$(
  jq -r '.live_validation.missing_required_scope_count' "$CONTRACT"
)" == "0" ]] \
  || fail "missing required live scopes"

[[ "$(
  jq -r '.live_validation.unexpected_scope_count' "$CONTRACT"
)" == "0" ]] \
  || fail "unexpected live scopes recorded"

[[ "$(
  jq -r '.live_validation.write_capable_scope_count' "$CONTRACT"
)" == "0" ]] \
  || fail "write-capable live scopes recorded"

[[ "$(
  jq -r '.live_validation.graph_get_count' "$CONTRACT"
)" == "3" ]] \
  || fail "unexpected Graph GET count"

[[ "$(
  jq -r '.live_validation.tenant_write_count' "$CONTRACT"
)" == "0" ]] \
  || fail "tenant writes recorded"

[[ "$(
  jq -r '.live_validation.risky_users_queried' "$CONTRACT"
)" == "false" ]] \
  || fail "risky-users query unexpectedly recorded"

[[ "$(
  jq -r '.live_validation.raw_identifiers_retained' "$CONTRACT"
)" == "false" ]] \
  || fail "raw identifier retention recorded"

[[ "$(
  jq -r '.live_validation.raw_graph_responses_retained' "$CONTRACT"
)" == "false" ]] \
  || fail "raw Graph response retention recorded"

[[ "$(
  jq -r '.live_validation.live_activity_counts_committed_to_git' "$CONTRACT"
)" == "false" ]] \
  || fail "live activity count retention recorded"

AVAILABLE_LIVE_SURFACE_COUNT="$(
  jq \
    '[.live_validation.surfaces[] |
      select(
        .classification == "AVAILABLE"
        and
        .method == "GET"
      )
    ] |
    length' \
    "$CONTRACT"
)"

[[ "$AVAILABLE_LIVE_SURFACE_COUNT" -eq 3 ]] \
  || fail "unexpected live investigation surface result"

EXPECTED_EVIDENCE_PATH="$(
  jq -r \
    '.live_validation.sanitized_evidence_path' \
    "$CONTRACT"
)"

[[ "$EXPECTED_EVIDENCE_PATH" == "docs/evidence/IDENTITY-SECURITY-INCIDENT-INVESTIGATION-LIVE-VALIDATION.md" ]] \
  || fail "unexpected sanitized evidence path"

EXPECTED_EVIDENCE_SHA="$(
  jq -r \
    '.live_validation.sanitized_evidence_sha256' \
    "$CONTRACT"
)"

[[ "$EXPECTED_EVIDENCE_SHA" =~ ^[0-9a-f]{64}$ ]] \
  || fail "invalid sanitized evidence SHA-256"

ACTUAL_EVIDENCE_SHA="$(
  sha256sum "$EVIDENCE" |
  awk '{print $1}'
)"

[[ "$ACTUAL_EVIDENCE_SHA" == "$EXPECTED_EVIDENCE_SHA" ]] \
  || fail "sanitized live evidence SHA-256 mismatch"

if grep -nEI \
  -- \
  '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
  "$EVIDENCE"
then
  fail "raw identifier pattern detected in live evidence"
fi

printf 'IDENTITY_INVESTIGATION_VALIDATION=PASS\n'
