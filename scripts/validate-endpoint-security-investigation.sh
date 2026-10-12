#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/endpoint-security-investigation-contract.json"
CONVERTER="$ROOT/automation/powershell/Convert-EndpointSecuritySignals.ps1"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

[[ -f "$CONTRACT" ]] \
  || fail "endpoint security investigation contract missing"

[[ -f "$CONVERTER" ]] \
  || fail "endpoint security signal converter missing"

jq -e . "$CONTRACT" >/dev/null \
  || fail "endpoint security contract JSON invalid"

[[ "$(jq -r '.feature' "$CONTRACT")" == "6" ]] \
  || fail "unexpected Feature number"

[[ "$(jq -r '.phase' "$CONTRACT")" == "FOUNDATION_READY_FOR_LIVE_VALIDATION" ]] \
  || fail "unexpected Feature 6 phase"

[[ "$(jq -r '.live_validation_state' "$CONTRACT")" == "NOT_RUN" ]] \
  || fail "Feature 6 live validation must remain NOT_RUN"

SURFACE_COUNT="$(
  jq '.investigation_surfaces | length' "$CONTRACT"
)"

[[ "$SURFACE_COUNT" -eq 2 ]] \
  || fail "unexpected Feature 6 surface count"

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
  || fail "Feature 6 surfaces must remain previously available GET surfaces"

ALERT_SCOPE_COUNT="$(
  jq \
    '[.investigation_surfaces[] |
      select(
        .id == "defender-security-alerts-v2"
        and
        .delegated_permission == "SecurityAlert.Read.All"
      )
    ] |
    length' \
    "$CONTRACT"
)"

INCIDENT_SCOPE_COUNT="$(
  jq \
    '[.investigation_surfaces[] |
      select(
        .id == "defender-security-incidents"
        and
        .delegated_permission == "SecurityIncident.Read.All"
      )
    ] |
    length' \
    "$CONTRACT"
)"

[[ "$ALERT_SCOPE_COUNT" -eq 1 ]] \
  || fail "unexpected SecurityAlert permission boundary"

[[ "$INCIDENT_SCOPE_COUNT" -eq 1 ]] \
  || fail "unexpected SecurityIncident permission boundary"

for FIELD in \
  tenant_write_allowed \
  endpoint_write_allowed \
  destructive_endpoint_action_allowed \
  new_permission_grant_allowed \
  automatic_role_assignment_allowed \
  trial_activation_allowed
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.live_query_boundary[$field]' \
      "$CONTRACT"
  )" == "false" ]] \
    || fail "unsafe Feature 6 live boundary: $FIELD"
done

for FIELD in \
  direct_endpoint_inventory_query_in_scope \
  direct_endpoint_response_action_in_scope \
  device_isolation_in_scope \
  device_offboarding_in_scope \
  file_quarantine_or_submission_in_scope \
  remediation_execution_in_scope
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.product_boundary[$field]' \
      "$CONTRACT"
  )" == "false" ]] \
    || fail "unsafe endpoint product boundary: $FIELD"
done

for FIELD in \
  raw_alert_ids_retained \
  raw_incident_ids_retained \
  raw_device_ids_retained \
  raw_device_names_retained \
  raw_user_ids_retained \
  raw_user_principal_names_retained \
  raw_ip_addresses_retained \
  raw_mac_addresses_retained \
  raw_file_names_retained \
  raw_file_paths_retained \
  raw_file_hashes_retained \
  raw_urls_retained \
  raw_titles_or_descriptions_retained \
  raw_graph_payloads_retained
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.privacy_boundary[$field]' \
      "$CONTRACT"
  )" == "false" ]] \
    || fail "Feature 6 privacy boundary violated: $FIELD"
done

[[ "$(
  jq -r '.privacy_boundary.incident_alias_format' "$CONTRACT"
)" == "INCIDENT-NNN" ]] \
  || fail "unexpected incident alias format"

[[ "$(
  jq -r '.privacy_boundary.alert_alias_format' "$CONTRACT"
)" == "ALERT-NNN" ]] \
  || fail "unexpected alert alias format"

[[ "$(
  jq -r '.privacy_boundary.device_alias_format' "$CONTRACT"
)" == "DEVICE-NNN" ]] \
  || fail "unexpected device alias format"

[[ "$(
  jq -r '.privacy_boundary.subject_alias_format' "$CONTRACT"
)" == "SUBJECT-NNN" ]] \
  || fail "unexpected subject alias format"

if grep -nEI \
  -- \
  'Connect-MgGraph|Invoke-MgGraphRequest|Disconnect-MgGraph|New-Mg[A-Za-z]|Update-Mg[A-Za-z]|Remove-Mg[A-Za-z]' \
  "$CONVERTER"
then
  fail "converter contains Microsoft Graph access"
fi

if grep -nEI \
  -- \
  'SecurityAlert\.ReadWrite\.All|SecurityIncident\.ReadWrite\.All|Directory\.AccessAsUser\.All' \
  "$CONVERTER"
then
  fail "converter contains write-capable Graph permission pattern"
fi

grep -Fq \
  "incident_alias_mode = 'IN_MEMORY_ONLY'" \
  "$CONVERTER" \
  || fail "incident alias privacy mode missing"

grep -Fq \
  "device_alias_mode = 'IN_MEMORY_ONLY'" \
  "$CONVERTER" \
  || fail "device alias privacy mode missing"

grep -Fq \
  'raw_file_hashes_retained = $false' \
  "$CONVERTER" \
  || fail "raw file hash non-retention control missing"

grep -Fq \
  'endpoint_response_action = $false' \
  "$CONVERTER" \
  || fail "endpoint response action boundary missing"

printf 'ENDPOINT_SECURITY_INVESTIGATION_VALIDATION=PASS\n'
