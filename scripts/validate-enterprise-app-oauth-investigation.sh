#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/enterprise-app-oauth-investigation-contract.json"
CONVERTER="$ROOT/automation/powershell/Convert-EnterpriseAppOAuthSignals.ps1"
EVIDENCE="$ROOT/docs/evidence/ENTERPRISE-APPLICATION-OAUTH-INCIDENT-INVESTIGATION-LIVE-VALIDATION.md"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

[[ -f "$CONTRACT" ]] \
  || fail "enterprise app/OAuth investigation contract missing"

[[ -f "$CONVERTER" ]] \
  || fail "enterprise app/OAuth signal converter missing"

[[ -f "$EVIDENCE" ]] \
  || fail "sanitized Feature 5 live validation evidence missing"

jq -e . "$CONTRACT" >/dev/null \
  || fail "enterprise app/OAuth contract JSON invalid"

[[ "$(jq -r '.feature' "$CONTRACT")" == "5" ]] \
  || fail "unexpected Feature number"

[[ "$(jq -r '.phase' "$CONTRACT")" == "LIVE_VALIDATION_COMPLETE" ]] \
  || fail "unexpected Feature 5 phase"

[[ "$(jq -r '.live_validation_state' "$CONTRACT")" == "ENTERPRISE_APPLICATION_OAUTH_INCIDENT_INVESTIGATION_COMPLETE" ]] \
  || fail "unexpected Feature 5 live validation state"

SURFACE_COUNT="$(
  jq '.investigation_surfaces | length' "$CONTRACT"
)"

[[ "$SURFACE_COUNT" -eq 2 ]] \
  || fail "unexpected investigation surface count"

AVAILABLE_GET_COUNT="$(
  jq \
    '[.investigation_surfaces[] |
      select(
        .feature_2_classification == "AVAILABLE"
        and
        .method == "GET"
      )
    ] |
    length' \
    "$CONTRACT"
)"

[[ "$AVAILABLE_GET_COUNT" -eq 2 ]] \
  || fail "investigation surfaces must remain read-only and previously available"

AUDIT_SCOPE_COUNT="$(
  jq \
    '[.investigation_surfaces[] |
      select(
        .delegated_permission == "AuditLog.Read.All"
      )
    ] |
    length' \
    "$CONTRACT"
)"

[[ "$AUDIT_SCOPE_COUNT" -eq 2 ]] \
  || fail "Feature 5A must use existing AuditLog.Read.All only"

[[ "$(
  jq -r \
    '.permission_boundary.foundation_requires_new_permissions' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "Feature 5A unexpectedly requires new permissions"

[[ "$(
  jq -r \
    '.permission_boundary.current_permission_grant_inventory_query_in_scope' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "current permission grant inventory must remain outside Feature 5A"

[[ "$(
  jq -r \
    '.permission_boundary.additional_directory_or_application_permissions_automatically_authorized' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "additional Graph permissions cannot be automatically authorized"

[[ "$(
  jq -r '.live_query_boundary.tenant_write_allowed' "$CONTRACT"
)" == "false" ]] \
  || fail "tenant writes unexpectedly allowed"

[[ "$(
  jq -r '.live_query_boundary.new_permission_grant_allowed' "$CONTRACT"
)" == "false" ]] \
  || fail "new permission grants unexpectedly allowed"

[[ "$(
  jq -r '.live_query_boundary.automatic_role_assignment_allowed' "$CONTRACT"
)" == "false" ]] \
  || fail "automatic role assignment unexpectedly allowed"

[[ "$(
  jq -r '.live_query_boundary.trial_activation_allowed' "$CONTRACT"
)" == "false" ]] \
  || fail "trial activation unexpectedly allowed"

for FIELD in \
  raw_application_client_ids_retained \
  raw_service_principal_ids_retained \
  raw_user_ids_retained \
  raw_user_principal_names_retained \
  raw_ip_addresses_retained \
  raw_event_ids_retained \
  raw_correlation_ids_retained \
  raw_oauth_grant_values_retained \
  raw_graph_payloads_retained
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.privacy_boundary[$field]' \
      "$CONTRACT"
  )" == "false" ]] \
    || fail "privacy boundary violated: $FIELD"
done

[[ "$(
  jq -r '.privacy_boundary.application_alias_format' "$CONTRACT"
)" == "APP-NNN" ]] \
  || fail "unexpected application alias format"

[[ "$(
  jq -r '.privacy_boundary.subject_alias_format' "$CONTRACT"
)" == "SUBJECT-NNN" ]] \
  || fail "unexpected subject alias format"

if grep -nEI \
  -- \
  'Connect-MgGraph|Invoke-MgGraphRequest|Disconnect-MgGraph|New-Mg|Update-Mg|Remove-Mg|ReadWrite' \
  "$CONVERTER"
then
  fail "converter contains Microsoft Graph access or write-capable pattern"
fi

grep -Fq \
  "application_alias_mode = 'IN_MEMORY_ONLY'" \
  "$CONVERTER" \
  || fail "application alias privacy mode missing"

grep -Fq \
  "subject_alias_mode = 'IN_MEMORY_ONLY'" \
  "$CONVERTER" \
  || fail "subject alias privacy mode missing"

grep -Fq \
  'raw_grant_values_retained = $false' \
  "$CONVERTER" \
  || fail "raw grant non-retention control missing"

grep -Fq \
  'permission_change_observed' \
  "$CONVERTER" \
  || fail "permission-change presence classification missing"

[[ "$(
  jq -r '.live_validation.authentication_mode' "$CONTRACT"
)" == "DELEGATED_READ_ONLY" ]] \
  || fail "unexpected live authentication mode"

[[ "$(
  jq -r '.live_validation.required_functional_scopes | length' "$CONTRACT"
)" == "1" ]] \
  || fail "unexpected required live scope count"

[[ "$(
  jq -r '.live_validation.required_functional_scopes[0]' "$CONTRACT"
)" == "AuditLog.Read.All" ]] \
  || fail "unexpected required live permission"

[[ "$(
  jq -r '.live_validation.missing_required_scope_count' "$CONTRACT"
)" == "0" ]] \
  || fail "missing required live scopes recorded"

[[ "$(
  jq -r '.live_validation.unexpected_scope_count' "$CONTRACT"
)" == "0" ]] \
  || fail "unexpected live scopes recorded"

[[ "$(
  jq -r '.live_validation.write_capable_scope_count' "$CONTRACT"
)" == "0" ]] \
  || fail "write-capable live scopes recorded"

[[ "$(
  jq -r '.live_validation.lookback_hours' "$CONTRACT"
)" == "24" ]] \
  || fail "unexpected live lookback"

[[ "$(
  jq -r '.live_validation.maximum_records_per_surface' "$CONTRACT"
)" == "25" ]] \
  || fail "unexpected live record boundary"

[[ "$(
  jq -r '.live_validation.graph_get_count' "$CONTRACT"
)" == "2" ]] \
  || fail "unexpected live Graph GET count"

[[ "$(
  jq -r '.live_validation.tenant_write_count' "$CONTRACT"
)" == "0" ]] \
  || fail "tenant writes recorded"

[[ "$(
  jq -r '.live_validation.application_management_filter_mode' "$CONTRACT"
)" == "LOCAL_POST_READ" ]] \
  || fail "unexpected ApplicationManagement filter mode"

[[ "$(
  jq -r '.live_validation.current_permission_grant_inventory_query_count' "$CONTRACT"
)" == "0" ]] \
  || fail "permission-grant inventory query unexpectedly recorded"

[[ "$(
  jq -r '.live_validation.new_permission_grant_count' "$CONTRACT"
)" == "0" ]] \
  || fail "new permission grant unexpectedly recorded"

[[ "$(
  jq -r '.live_validation.new_role_assignment_count' "$CONTRACT"
)" == "0" ]] \
  || fail "new role assignment unexpectedly recorded"

for FIELD in \
  raw_identifiers_printed \
  raw_identifiers_retained \
  raw_oauth_grant_values_retained \
  raw_graph_responses_printed \
  raw_graph_responses_retained \
  live_activity_counts_committed_to_git \
  temporary_live_inputs_committed_to_git
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.live_validation[$field]' \
      "$CONTRACT"
  )" == "false" ]] \
    || fail "live privacy boundary violated: $FIELD"
done

[[ "$(
  jq -r '.live_validation.sanitized_live_transformation_validated' "$CONTRACT"
)" == "true" ]] \
  || fail "sanitized live transformation not validated"

[[ "$(
  jq -r '.live_validation.feature_3_evidence_registration_validated' "$CONTRACT"
)" == "true" ]] \
  || fail "Feature 3 evidence integration not validated"

[[ "$(
  jq -r '.live_validation.feature_3_custody_integrity_validated' "$CONTRACT"
)" == "true" ]] \
  || fail "Feature 3 custody integration not validated"

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

[[ "$AVAILABLE_LIVE_SURFACE_COUNT" -eq 2 ]] \
  || fail "unexpected validated Feature 5 surface count"

EXPECTED_EVIDENCE_PATH="$(
  jq -r \
    '.live_validation.sanitized_evidence_path' \
    "$CONTRACT"
)"

[[ "$EXPECTED_EVIDENCE_PATH" == "docs/evidence/ENTERPRISE-APPLICATION-OAUTH-INCIDENT-INVESTIGATION-LIVE-VALIDATION.md" ]] \
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
  || fail "sanitized Feature 5 evidence SHA-256 mismatch"

if grep -nEI \
  -- \
  '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
  "$EVIDENCE"
then
  fail "raw identifier pattern detected in Feature 5 live evidence"
fi

printf 'ENTERPRISE_APP_OAUTH_INVESTIGATION_VALIDATION=PASS\n'
