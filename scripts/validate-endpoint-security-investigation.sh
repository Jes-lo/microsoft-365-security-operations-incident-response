#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/endpoint-security-investigation-contract.json"
EVIDENCE="$ROOT/docs/evidence/ENDPOINT-SECURITY-INCIDENT-INVESTIGATION-LIVE-VALIDATION.md"
CONVERTER="$ROOT/automation/powershell/Convert-EndpointSecuritySignals.ps1"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

[[ -f "$CONTRACT" ]] \
  || fail "endpoint security investigation contract missing"

[[ -f "$EVIDENCE" ]] \
  || fail "sanitized Feature 6 live validation evidence missing"

[[ -f "$CONVERTER" ]] \
  || fail "endpoint security signal converter missing"

jq -e . "$CONTRACT" >/dev/null \
  || fail "endpoint security contract JSON invalid"

[[ "$(jq -r '.feature' "$CONTRACT")" == "6" ]] \
  || fail "unexpected Feature number"

[[ "$(jq -r '.phase' "$CONTRACT")" == "LIVE_VALIDATION_COMPLETE" ]] \
  || fail "unexpected Feature 6 phase"

[[ "$(jq -r '.live_validation_state' "$CONTRACT")" == "ENDPOINT_SECURITY_INCIDENT_INVESTIGATION_COMPLETE" ]] \
  || fail "unexpected Feature 6 live validation state"

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

[[ "$(jq -r '.live_validation.status' "$CONTRACT")" == "PASS" ]] \
  || fail "Feature 6 live validation status is not PASS"

[[ "$(jq -r '.live_validation.result' "$CONTRACT")" == "AVAILABLE_SURFACES_ZERO_SIGNALS_IN_24H" ]] \
  || fail "unexpected Feature 6 live validation result"

[[ "$(jq -r '.live_validation.authentication' "$CONTRACT")" == "DELEGATED_READ_ONLY" ]] \
  || fail "unexpected Feature 6 authentication classification"

[[ "$(jq -r '.live_validation.lookback_hours' "$CONTRACT")" == "24" ]] \
  || fail "unexpected Feature 6 live lookback"

[[ "$(jq -r '.live_validation.maximum_records_per_surface' "$CONTRACT")" == "25" ]] \
  || fail "unexpected Feature 6 live record boundary"

[[ "$(jq -r '.live_validation.graph_get_request_count' "$CONTRACT")" == "2" ]] \
  || fail "unexpected Feature 6 Graph GET count"

[[ "$(jq -r '.live_validation.successful_get_count' "$CONTRACT")" == "2" ]] \
  || fail "unexpected Feature 6 successful GET count"

[[ "$(jq -r '.live_validation.alerts_v2_records_observed' "$CONTRACT")" == "0" ]] \
  || fail "unexpected live alerts count"

[[ "$(jq -r '.live_validation.incidents_records_observed' "$CONTRACT")" == "0" ]] \
  || fail "unexpected live incidents count"

for FIELD in \
  missing_scope_count \
  unexpected_scope_count \
  write_capable_scope_count \
  tenant_writes \
  endpoint_writes \
  endpoint_actions \
  alert_mutations \
  incident_mutations \
  new_permission_grants \
  role_assignments \
  trial_activations
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.live_validation[$field]' \
      "$CONTRACT"
  )" == "0" ]] \
    || fail "unsafe Feature 6 live validation value: $FIELD"
done

for FIELD in \
  pagination_used \
  raw_graph_payloads_retained \
  synthetic_signal_fabrication
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.live_validation[$field]' \
      "$CONTRACT"
  )" == "false" ]] \
    || fail "unsafe Feature 6 live validation Boolean: $FIELD"
done

for FIELD in \
  zero_signal_converter_path_validated \
  feature_3_sha256_validated \
  feature_3_custody_validated
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.live_validation[$field]' \
      "$CONTRACT"
  )" == "true" ]] \
    || fail "required Feature 6 live validation control missing: $FIELD"
done

EVIDENCE_RELATIVE="$(
  jq -r \
    '.live_validation.sanitized_evidence_path' \
    "$CONTRACT"
)"

[[ "$EVIDENCE_RELATIVE" == "docs/evidence/ENDPOINT-SECURITY-INCIDENT-INVESTIGATION-LIVE-VALIDATION.md" ]] \
  || fail "unexpected Feature 6 evidence path"

EXPECTED_EVIDENCE_SHA="$(
  jq -r \
    '.live_validation.sanitized_evidence_sha256' \
    "$CONTRACT"
)"

[[ "$EXPECTED_EVIDENCE_SHA" =~ ^[0-9a-f]{64}$ ]] \
  || fail "invalid Feature 6 evidence SHA-256"

ACTUAL_EVIDENCE_SHA="$(
  sha256sum "$EVIDENCE" |
  awk '{print $1}'
)"

[[ "$ACTUAL_EVIDENCE_SHA" == "$EXPECTED_EVIDENCE_SHA" ]] \
  || fail "sanitized Feature 6 evidence SHA-256 mismatch"

grep -Fq \
  'available zero-signal condition' \
  "$EVIDENCE" \
  || fail "Feature 6 evidence must document zero-signal availability"

grep -Fq \
  'No security telemetry was fabricated' \
  "$EVIDENCE" \
  || fail "Feature 6 evidence must prohibit fabricated live telemetry"

grep -Fq \
  'tenant writes: `0`' \
  "$EVIDENCE" \
  || fail "Feature 6 evidence must document zero tenant writes"

grep -Fq \
  'endpoint response actions: `0`' \
  "$EVIDENCE" \
  || fail "Feature 6 evidence must document zero endpoint actions"

if grep -Eq \
  '\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b' \
  "$EVIDENCE"
then
  fail "GUID-like raw identifier detected in Feature 6 live evidence"
fi

if grep -Eiq \
  '\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b' \
  "$EVIDENCE"
then
  fail "UPN/email-like identifier detected in Feature 6 live evidence"
fi

if grep -Eiq \
  -- \
  '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|Bearer[[:space:]]+[A-Za-z0-9._~-]+' \
  "$EVIDENCE"
then
  fail "secret-like value detected in Feature 6 live evidence"
fi

printf 'FEATURE_6_LIVE_VALIDATION_EVIDENCE=PASS\n'
printf 'FEATURE_6_LIVE_EVIDENCE_SHA256=PASS\n'
printf 'FEATURE_6_ZERO_SIGNAL_TRUTHFULNESS=PASS\n'

printf 'ENDPOINT_SECURITY_INVESTIGATION_VALIDATION=PASS\n'
