#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/enterprise-app-oauth-investigation-contract.json"
CONVERTER="$ROOT/automation/powershell/Convert-EnterpriseAppOAuthSignals.ps1"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

[[ -f "$CONTRACT" ]] \
  || fail "enterprise app/OAuth investigation contract missing"

[[ -f "$CONVERTER" ]] \
  || fail "enterprise app/OAuth signal converter missing"

jq -e . "$CONTRACT" >/dev/null \
  || fail "enterprise app/OAuth contract JSON invalid"

[[ "$(jq -r '.feature' "$CONTRACT")" == "5" ]] \
  || fail "unexpected Feature number"

[[ "$(jq -r '.phase' "$CONTRACT")" == "FOUNDATION_READY_FOR_LIVE_VALIDATION" ]] \
  || fail "unexpected Feature 5 phase"

[[ "$(jq -r '.live_validation_state' "$CONTRACT")" == "NOT_RUN" ]] \
  || fail "Feature 5 live validation must remain NOT_RUN"

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

printf 'ENTERPRISE_APP_OAUTH_INVESTIGATION_VALIDATION=PASS\n'
