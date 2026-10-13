#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONVERTER="$ROOT/automation/powershell/Convert-CrossSignalCorrelation.ps1"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

command -v pwsh >/dev/null \
  || fail "pwsh is required"

WORK="$(
  mktemp -d
)"

cleanup() {
  rm -rf -- "$WORK"
}

trap cleanup EXIT

CASE_ROOT="$WORK/cases"
CASE_ID="IR-20990101-CROSS7A"
CASE_PATH="$CASE_ROOT/$CASE_ID"

IDENTITY="$WORK/identity.json"
APPLICATION="$WORK/application.json"
ENDPOINT="$WORK/endpoint.json"
BINDINGS="$WORK/bindings.json"

SUMMARY_ONE="$WORK/cross-signal-one.json"
SUMMARY_TWO="$WORK/cross-signal-two.json"

mkdir -p "$CASE_ROOT"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/New-IncidentCase.ps1" \
  -CaseId "$CASE_ID" \
  -Severity "SEV2" \
  -TitleSanitized "Synthetic cross signal correlation" \
  -RootPath "$CASE_ROOT" \
  >/dev/null

cat > "$IDENTITY" <<JSON
{
  "schema_version": 1,
  "case_id": "$CASE_ID",
  "investigation_type": "IDENTITY_SECURITY",
  "privacy_mode": "SUBJECT_ALIAS_ONLY",
  "raw_identifiers_retained": false,
  "raw_graph_payload_retained": false,
  "source_counts": {
    "sign_ins": 1,
    "directory_audits": 1,
    "risk_detections": 1
  },
  "finding_counts": {
    "failed_sign_ins": 1,
    "risky_sign_ins": 1,
    "risk_detections": 1,
    "unique_subjects": 2
  },
  "sign_ins": [
    {
      "subject_alias": "SUBJECT-001",
      "timestamp_utc": "2099-01-01T01:00:00.0000000Z",
      "outcome": "FAILURE",
      "risk_level": "medium"
    }
  ],
  "directory_audits": [
    {
      "actor_alias": "SUBJECT-002",
      "target_alias": "SUBJECT-UNKNOWN",
      "timestamp_utc": "2099-01-01T01:04:00.0000000Z",
      "category": "UserManagement",
      "result": "success"
    }
  ],
  "risk_detections": [
    {
      "subject_alias": "SUBJECT-001",
      "timestamp_utc": "2099-01-01T01:06:00.0000000Z",
      "risk_event_type": "anonymizedIPAddress",
      "risk_level": "medium",
      "risk_state": "atRisk"
    }
  ]
}
JSON

cat > "$APPLICATION" <<JSON
{
  "schema_version": 1,
  "feature": 5,
  "case_id": "$CASE_ID",
  "investigation_type": "ENTERPRISE_APPLICATION_OAUTH",
  "privacy": {
    "application_alias_mode": "IN_MEMORY_ONLY",
    "subject_alias_mode": "IN_MEMORY_ONLY",
    "raw_application_ids_retained": false,
    "raw_service_principal_ids_retained": false,
    "raw_user_ids_retained": false,
    "raw_upns_retained": false,
    "raw_ip_addresses_retained": false,
    "raw_grant_values_retained": false,
    "raw_graph_payloads_retained": false
  },
  "counts": {
    "sign_in_records": 2,
    "directory_audit_records": 1,
    "application_alias_count": 1,
    "subject_alias_count": 2,
    "failed_sign_ins": 1,
    "risky_sign_ins": 1,
    "consent_events": 1,
    "permission_change_events": 1
  },
  "sign_ins": [
    {
      "app_alias": "APP-001",
      "subject_alias": "SUBJECT-001",
      "timestamp_utc": "2099-01-01T01:01:00.0000000Z",
      "outcome": "SUCCESS",
      "risk_level": "none"
    },
    {
      "app_alias": "APP-001",
      "subject_alias": "SUBJECT-002",
      "timestamp_utc": "2099-01-01T01:02:00.0000000Z",
      "outcome": "FAILURE",
      "risk_level": "medium"
    }
  ],
  "directory_audits": [
    {
      "app_alias": "APP-001",
      "actor_alias": "SUBJECT-002",
      "timestamp_utc": "2099-01-01T01:03:00.0000000Z",
      "operation": "CONSENT",
      "result": "success",
      "permission_change_observed": true
    }
  ]
}
JSON

cat > "$ENDPOINT" <<JSON
{
  "schema_version": 1,
  "feature": 6,
  "case_id": "$CASE_ID",
  "investigation_type": "ENDPOINT_SECURITY",
  "investigation_boundary": {
    "unified_security_alert_and_incident_analysis": true,
    "direct_endpoint_inventory_query": false,
    "endpoint_response_action": false,
    "tenant_remediation_execution": false
  },
  "privacy": {
    "incident_alias_mode": "IN_MEMORY_ONLY",
    "alert_alias_mode": "IN_MEMORY_ONLY",
    "device_alias_mode": "IN_MEMORY_ONLY",
    "subject_alias_mode": "IN_MEMORY_ONLY",
    "raw_alert_ids_retained": false,
    "raw_incident_ids_retained": false,
    "raw_device_ids_retained": false,
    "raw_device_names_retained": false,
    "raw_user_ids_retained": false,
    "raw_upns_retained": false,
    "raw_ip_addresses_retained": false,
    "raw_mac_addresses_retained": false,
    "raw_file_names_retained": false,
    "raw_file_paths_retained": false,
    "raw_file_hashes_retained": false,
    "raw_urls_retained": false,
    "raw_titles_or_descriptions_retained": false,
    "raw_graph_payloads_retained": false
  },
  "counts": {
    "incident_records": 1,
    "alert_records": 1,
    "incident_alias_count": 1,
    "alert_alias_count": 1,
    "device_alias_count": 1,
    "subject_alias_count": 1,
    "evidence_records": 2,
    "device_evidence_records": 1,
    "user_evidence_records": 1,
    "malicious_evidence_records": 0,
    "suspicious_evidence_records": 1,
    "endpoint_associated_alerts": 1
  },
  "incidents": [
    {
      "incident_alias": "INCIDENT-001",
      "created_at_utc": "2099-01-01T01:07:00.0000000Z",
      "last_update_at_utc": "2099-01-01T01:08:00.0000000Z",
      "severity": "medium",
      "status": "active",
      "classification": "unknown",
      "determination": "unknown",
      "correlated_alert_count": 1
    }
  ],
  "alerts": [
    {
      "alert_alias": "ALERT-001",
      "incident_alias": "INCIDENT-001",
      "created_at_utc": "2099-01-01T01:05:00.0000000Z",
      "last_update_at_utc": "2099-01-01T01:05:30.0000000Z",
      "severity": "medium",
      "status": "new",
      "classification": "unknown",
      "determination": "unknown",
      "investigation_state": "unsupported",
      "service_source_category": "MDE",
      "endpoint_associated": true,
      "mitre_technique_count": 1,
      "evidence": [
        {
          "evidence_type": "USER",
          "verdict": "suspicious",
          "remediation_status": "none",
          "roles": [
            "loggedOn"
          ],
          "subject_alias": "SUBJECT-003"
        },
        {
          "evidence_type": "DEVICE",
          "verdict": "unknown",
          "remediation_status": "none",
          "roles": [
            "impacted"
          ],
          "device_alias": "DEVICE-001",
          "os_family": "WINDOWS"
        }
      ]
    }
  ]
}
JSON

cat > "$BINDINGS" <<JSON
{
  "schema_version": 1,
  "case_id": "$CASE_ID",
  "bindings": [
    {
      "binding_alias": "CORR-SUBJECT-001",
      "relationship_type": "SAME_SUBJECT",
      "members": [
        {
          "domain": "IDENTITY",
          "alias": "SUBJECT-001"
        },
        {
          "domain": "APPLICATION",
          "alias": "SUBJECT-002"
        },
        {
          "domain": "ENDPOINT",
          "alias": "SUBJECT-003"
        }
      ]
    }
  ]
}
JSON

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$CONVERTER" \
  -CasePath "$CASE_PATH" \
  -IdentitySummaryPath "$IDENTITY" \
  -ApplicationSummaryPath "$APPLICATION" \
  -EndpointSummaryPath "$ENDPOINT" \
  -BindingsPath "$BINDINGS" \
  -OutputPath "$SUMMARY_ONE" \
  >/dev/null

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$CONVERTER" \
  -CasePath "$CASE_PATH" \
  -IdentitySummaryPath "$IDENTITY" \
  -ApplicationSummaryPath "$APPLICATION" \
  -EndpointSummaryPath "$ENDPOINT" \
  -BindingsPath "$BINDINGS" \
  -OutputPath "$SUMMARY_TWO" \
  >/dev/null

jq -e . "$SUMMARY_ONE" >/dev/null
jq -e . "$SUMMARY_TWO" >/dev/null

cmp -s \
  "$SUMMARY_ONE" \
  "$SUMMARY_TWO" \
  || fail "cross-signal output is not deterministic"

[[ "$(jq -r '.feature' "$SUMMARY_ONE")" == "7" ]]
[[ "$(jq -r '.correlation_type' "$SUMMARY_ONE")" == "CROSS_SIGNAL" ]]
[[ "$(jq -r '.deterministic_output' "$SUMMARY_ONE")" == "true" ]]

[[ "$(jq -r '.counts.total_events' "$SUMMARY_ONE")" == "8" ]]
[[ "$(jq -r '.counts.identity_events' "$SUMMARY_ONE")" == "3" ]]
[[ "$(jq -r '.counts.application_events' "$SUMMARY_ONE")" == "3" ]]
[[ "$(jq -r '.counts.endpoint_events' "$SUMMARY_ONE")" == "2" ]]
[[ "$(jq -r '.counts.explicit_subject_bindings' "$SUMMARY_ONE")" == "1" ]]
[[ "$(jq -r '.counts.bound_events' "$SUMMARY_ONE")" == "5" ]]
[[ "$(jq -r '.counts.unbound_events' "$SUMMARY_ONE")" == "3" ]]

EXPECTED_ORDER="$(
  cat <<'ORDER'
IDENTITY_SIGN_IN
APPLICATION_SIGN_IN
APPLICATION_SIGN_IN
APPLICATION_DIRECTORY_AUDIT
IDENTITY_DIRECTORY_AUDIT
ENDPOINT_ALERT
IDENTITY_RISK_DETECTION
ENDPOINT_INCIDENT
ORDER
)"

ACTUAL_ORDER="$(
  jq -r \
    '.timeline[].event_type' \
    "$SUMMARY_ONE"
)"

[[ "$ACTUAL_ORDER" == "$EXPECTED_ORDER" ]] \
  || fail "deterministic cross-signal timeline order is incorrect"

jq -e '
  [
    .timeline[].sequence
  ] == [
    1,2,3,4,5,6,7,8
  ]
' \
  "$SUMMARY_ONE" \
  >/dev/null \
  || fail "timeline sequence is not deterministic"

jq -e '
  .timeline[]
  |
  select(
    .domain == "APPLICATION"
    and
    .event_type == "APPLICATION_SIGN_IN"
    and
    .source_index == 0
  )
  |
  .local_references.subject_alias == "SUBJECT-001"
  and
  (.subject_bindings | length) == 0
' \
  "$SUMMARY_ONE" \
  >/dev/null \
  || fail "cross-domain alias equality incorrectly created a join"

jq -e '
  .timeline[]
  |
  select(
    .domain == "APPLICATION"
    and
    .event_type == "APPLICATION_SIGN_IN"
    and
    .source_index == 1
  )
  |
  .local_references.subject_alias == "SUBJECT-002"
  and
  (.subject_bindings | length) == 1
  and
  .subject_bindings[0].binding_alias == "CORR-SUBJECT-001"
' \
  "$SUMMARY_ONE" \
  >/dev/null \
  || fail "explicit application subject binding missing"

jq -e '
  .timeline[]
  |
  select(
    .domain == "ENDPOINT"
    and
    .event_type == "ENDPOINT_ALERT"
  )
  |
  (.subject_bindings | length) == 1
  and
  .subject_bindings[0].binding_alias == "CORR-SUBJECT-001"
' \
  "$SUMMARY_ONE" \
  >/dev/null \
  || fail "explicit endpoint subject binding missing"

for FIELD in \
  raw_identifiers_retained \
  raw_graph_payloads_retained \
  cross_domain_alias_equality_join
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.privacy[$field]' \
      "$SUMMARY_ONE"
  )" == "false" ]] \
    || fail "unsafe output privacy field: $FIELD"
done

for FIELD in \
  graph_requests \
  tenant_reads \
  tenant_writes \
  endpoint_actions \
  response_actions
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.safety_boundary[$field]' \
      "$SUMMARY_ONE"
  )" == "0" ]] \
    || fail "unsafe output safety field: $FIELD"
done

if grep -Eiq \
  -- \
  '\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b|https?://|Bearer[[:space:]]+' \
  "$SUMMARY_ONE"
then
  fail "raw identifier or secret-like material detected in cross-signal output"
fi

SENSITIVE_IDENTITY="$WORK/sensitive-identity.json"
SENSITIVE_APPLICATION="$WORK/sensitive-application.json"
SENSITIVE_ENDPOINT="$WORK/sensitive-endpoint.json"
SENSITIVE_SUMMARY="$WORK/sensitive-summary.json"

SENSITIVE_EMAIL="$(
  printf '%s%s%s' \
    'analyst' \
    '@' \
    'example.invalid'
)"

SENSITIVE_IP="198.51.100.7"

SENSITIVE_URL="$(
  printf '%s%s' \
    'https://' \
    'private.example.invalid/path'
)"

SENSITIVE_GUID="$(
  printf '%s-%s-%s-%s-%s' \
    '11111111' \
    '2222' \
    '3333' \
    '4444' \
    '555555555555'
)"

SENSITIVE_HASH="$(
  printf 'a%.0s' {1..64}
)"

SENSITIVE_PATH='C:\Users\private\secret.txt'

jq \
  --arg email "$SENSITIVE_EMAIL" \
  --arg ip "$SENSITIVE_IP" \
  '
    .sign_ins[0].outcome = $email
    |
    .risk_detections[0].risk_event_type = $ip
  ' \
  "$IDENTITY" \
  > "$SENSITIVE_IDENTITY"

jq \
  --arg url "$SENSITIVE_URL" \
  --arg path "$SENSITIVE_PATH" \
  '
    .sign_ins[0].risk_level = $url
    |
    .directory_audits[0].operation = $path
  ' \
  "$APPLICATION" \
  > "$SENSITIVE_APPLICATION"

jq \
  --arg guid "$SENSITIVE_GUID" \
  --arg hash "$SENSITIVE_HASH" \
  '
    .incidents[0].determination = $guid
    |
    .alerts[0].classification = $hash
  ' \
  "$ENDPOINT" \
  > "$SENSITIVE_ENDPOINT"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$CONVERTER" \
  -CasePath "$CASE_PATH" \
  -IdentitySummaryPath "$SENSITIVE_IDENTITY" \
  -ApplicationSummaryPath "$SENSITIVE_APPLICATION" \
  -EndpointSummaryPath "$SENSITIVE_ENDPOINT" \
  -BindingsPath "$BINDINGS" \
  -OutputPath "$SENSITIVE_SUMMARY" \
  >/dev/null

jq -e . "$SENSITIVE_SUMMARY" >/dev/null

REDACTED_CATEGORY_COUNT="$(
  jq \
    '[
      .timeline[].attributes[]?
      |
      select(. == "REDACTED_CATEGORY")
    ]
    |
    length' \
    "$SENSITIVE_SUMMARY"
)"

[[ "$REDACTED_CATEGORY_COUNT" -eq 6 ]] \
  || fail "expected six identifier-like category values to be redacted"

for RAW_VALUE in \
  "$SENSITIVE_EMAIL" \
  "$SENSITIVE_IP" \
  "$SENSITIVE_URL" \
  "$SENSITIVE_GUID" \
  "$SENSITIVE_HASH" \
  "$SENSITIVE_PATH"
do
  if grep -Fq \
    -- \
    "$RAW_VALUE" \
    "$SENSITIVE_SUMMARY"
  then
    fail "identifier-like category value leaked into correlation output"
  fi
done

jq -e '
  .privacy.raw_identifiers_retained == false
  and
  .privacy.raw_graph_payloads_retained == false
' \
  "$SENSITIVE_SUMMARY" \
  >/dev/null \
  || fail "privacy state changed during category redaction test"

printf 'SENSITIVE_CATEGORY_REDACTION=PASS\n'

SUMMARY_SHA="$(
  sha256sum "$SUMMARY_ONE" |
  awk '{print $1}'
)"

[[ "$SUMMARY_SHA" =~ ^[0-9a-f]{64}$ ]]

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/Add-IncidentEvidenceRecord.ps1" \
  -CasePath "$CASE_PATH" \
  -EvidenceId "EVID-CROSSSIG01" \
  -SourceType "OTHER_SANITIZED" \
  -SanitizedLabel "Sanitized cross signal correlation timeline" \
  -SourceFile "$SUMMARY_ONE" \
  >/dev/null

INTEGRITY="$WORK/integrity.txt"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/Test-IncidentCaseIntegrity.ps1" \
  -CasePath "$CASE_PATH" \
  > "$INTEGRITY"

grep -Fxq \
  'INCIDENT_CASE_INTEGRITY=PASS' \
  "$INTEGRITY"

grep -Fxq \
  'CUSTODY_HASH_CHAIN=PASS' \
  "$INTEGRITY"

grep -Fxq \
  'RAW_EVIDENCE_RETENTION=NO' \
  "$INTEGRITY"

REGISTERED_SHA="$(
  jq -r \
    '.evidence[] |
     select(.evidence_id == "EVID-CROSSSIG01") |
     .sha256' \
    "$CASE_PATH/evidence-index.json"
)"

[[ "$REGISTERED_SHA" == "$SUMMARY_SHA" ]] \
  || fail "Feature 3 SHA binding failed"

DUPLICATE_BINDINGS="$WORK/duplicate-bindings.json"

jq '
  .bindings += [
    {
      "binding_alias": "CORR-SUBJECT-002",
      "relationship_type": "SAME_SUBJECT",
      "members": [
        {
          "domain": "IDENTITY",
          "alias": "SUBJECT-001"
        },
        {
          "domain": "APPLICATION",
          "alias": "SUBJECT-001"
        }
      ]
    }
  ]
' \
  "$BINDINGS" \
  > "$DUPLICATE_BINDINGS"

set +e

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$CONVERTER" \
  -CasePath "$CASE_PATH" \
  -IdentitySummaryPath "$IDENTITY" \
  -ApplicationSummaryPath "$APPLICATION" \
  -EndpointSummaryPath "$ENDPOINT" \
  -BindingsPath "$DUPLICATE_BINDINGS" \
  -OutputPath "$WORK/duplicate-output.json" \
  >/dev/null 2>&1

DUPLICATE_EXIT=$?

set -e

[[ "$DUPLICATE_EXIT" -ne 0 ]] \
  || fail "duplicate binding member assignment was accepted"

PHANTOM_BINDINGS="$WORK/phantom-bindings.json"

jq '
  .bindings[0].members[2].alias = "SUBJECT-099"
' \
  "$BINDINGS" \
  > "$PHANTOM_BINDINGS"

set +e

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$CONVERTER" \
  -CasePath "$CASE_PATH" \
  -IdentitySummaryPath "$IDENTITY" \
  -ApplicationSummaryPath "$APPLICATION" \
  -EndpointSummaryPath "$ENDPOINT" \
  -BindingsPath "$PHANTOM_BINDINGS" \
  -OutputPath "$WORK/phantom-output.json" \
  >/dev/null 2>&1

PHANTOM_EXIT=$?

set -e

[[ "$PHANTOM_EXIT" -ne 0 ]] \
  || fail "phantom binding alias was accepted"

ZERO_IDENTITY="$WORK/zero-identity.json"
ZERO_APPLICATION="$WORK/zero-application.json"
ZERO_ENDPOINT="$WORK/zero-endpoint.json"
ZERO_SUMMARY_ONE="$WORK/zero-summary-one.json"
ZERO_SUMMARY_TWO="$WORK/zero-summary-two.json"

jq '
  .sign_ins = []
  |
  .directory_audits = []
  |
  .risk_detections = []
  |
  .source_counts |= with_entries(.value = 0)
  |
  .finding_counts |= with_entries(.value = 0)
' \
  "$IDENTITY" \
  > "$ZERO_IDENTITY"

jq '
  .sign_ins = []
  |
  .directory_audits = []
  |
  .counts |= with_entries(.value = 0)
' \
  "$APPLICATION" \
  > "$ZERO_APPLICATION"

jq '
  .incidents = []
  |
  .alerts = []
  |
  .counts |= with_entries(.value = 0)
' \
  "$ENDPOINT" \
  > "$ZERO_ENDPOINT"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$CONVERTER" \
  -CasePath "$CASE_PATH" \
  -IdentitySummaryPath "$ZERO_IDENTITY" \
  -ApplicationSummaryPath "$ZERO_APPLICATION" \
  -EndpointSummaryPath "$ZERO_ENDPOINT" \
  -OutputPath "$ZERO_SUMMARY_ONE" \
  >/dev/null

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$CONVERTER" \
  -CasePath "$CASE_PATH" \
  -IdentitySummaryPath "$ZERO_IDENTITY" \
  -ApplicationSummaryPath "$ZERO_APPLICATION" \
  -EndpointSummaryPath "$ZERO_ENDPOINT" \
  -OutputPath "$ZERO_SUMMARY_TWO" \
  >/dev/null

jq -e . "$ZERO_SUMMARY_ONE" >/dev/null
jq -e . "$ZERO_SUMMARY_TWO" >/dev/null

cmp -s \
  "$ZERO_SUMMARY_ONE" \
  "$ZERO_SUMMARY_TWO" \
  || fail "zero-signal correlation output is not deterministic"

jq -e '
  .feature == 7
  and
  .correlation_type == "CROSS_SIGNAL"
  and
  .deterministic_output == true
  and
  .counts.total_events == 0
  and
  .counts.identity_events == 0
  and
  .counts.application_events == 0
  and
  .counts.endpoint_events == 0
  and
  .counts.explicit_subject_bindings == 0
  and
  .counts.bound_events == 0
  and
  .counts.unbound_events == 0
  and
  (.timeline | length) == 0
  and
  (.bindings | length) == 0
  and
  .privacy.raw_identifiers_retained == false
  and
  .privacy.raw_graph_payloads_retained == false
  and
  .safety_boundary.tenant_writes == 0
  and
  .safety_boundary.endpoint_actions == 0
' \
  "$ZERO_SUMMARY_ONE" \
  >/dev/null \
  || fail "zero-signal empty-array correlation contract failed"

printf 'ZERO_SIGNAL_EMPTY_ARRAY_CORRELATION=PASS\n'

UNSAFE_IDENTITY="$WORK/unsafe-identity.json"

jq \
  '.raw_identifiers_retained = true' \
  "$IDENTITY" \
  > "$UNSAFE_IDENTITY"

set +e

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$CONVERTER" \
  -CasePath "$CASE_PATH" \
  -IdentitySummaryPath "$UNSAFE_IDENTITY" \
  -ApplicationSummaryPath "$APPLICATION" \
  -EndpointSummaryPath "$ENDPOINT" \
  -BindingsPath "$BINDINGS" \
  -OutputPath "$WORK/unsafe-output.json" \
  >/dev/null 2>&1

UNSAFE_EXIT=$?

set -e

[[ "$UNSAFE_EXIT" -ne 0 ]] \
  || fail "unsafe source privacy state was accepted"

printf 'CROSS_SIGNAL_CORRELATION_TEST=PASS\n'
printf 'DETERMINISTIC_TIMELINE_TEST=PASS\n'
printf 'CROSS_DOMAIN_ALIAS_EQUALITY_JOIN_REJECTION=PASS\n'
printf 'EXPLICIT_SUBJECT_BINDING=PASS\n'
printf 'PHANTOM_BINDING_REJECTION=PASS\n'
printf 'DUPLICATE_BINDING_MEMBER_REJECTION=PASS\n'
printf 'UNSAFE_SOURCE_REJECTION=PASS\n'
printf 'RAW_IDENTIFIER_NON_RETENTION=PASS\n'
printf 'ZERO_SIGNAL_EMPTY_ARRAY_REGRESSION=PASS\n'
printf 'SENSITIVE_CATEGORY_REDACTION_TEST=PASS\n'
printf 'FEATURE_3_EVIDENCE_INTEGRATION=PASS\n'
