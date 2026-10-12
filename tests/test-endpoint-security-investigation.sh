#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

TMP_DIR="$(mktemp -d)"
chmod 700 "$TMP_DIR"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

CASE_ROOT="$TMP_DIR/cases"
CASE_ID="IR-20990101-ENDPOINT"
CASE_PATH="$CASE_ROOT/$CASE_ID"

ALERTS="$TMP_DIR/alerts.json"
INCIDENTS="$TMP_DIR/incidents.json"
SUMMARY="$TMP_DIR/summary.json"
INTEGRITY="$TMP_DIR/integrity.txt"

RAW_INCIDENT_ONE="private-incident-internal-alpha"
RAW_INCIDENT_TWO="private-incident-internal-beta"

RAW_ALERT_ONE="private-alert-internal-one"
RAW_ALERT_TWO="private-alert-internal-two"
RAW_ALERT_THREE="private-alert-internal-three"

RAW_DEVICE_ID="private-mde-device-internal"
RAW_DEVICE_NAME="private-hostname-internal"
RAW_SUBJECT_ID="private-subject-internal"
RAW_ACCOUNT_NAME="private-account-internal"
RAW_FILE_NAME="private-file-artifact"
RAW_FILE_PATH="private-file-path-internal"
RAW_FILE_HASH="private-file-hash-internal"
RAW_PROCESS_COMMAND="private-process-command-internal"
RAW_NETWORK_VALUE="private-network-artifact-internal"
RAW_ALERT_TITLE="private-alert-title-internal"
RAW_INCIDENT_DESCRIPTION="private-incident-description-internal"

mkdir -p "$CASE_ROOT"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/New-IncidentCase.ps1" \
  -CaseId "$CASE_ID" \
  -Severity "SEV2" \
  -TitleSanitized "Endpoint security investigation synthetic test" \
  -RootPath "$CASE_ROOT" \
  >/dev/null

jq -n \
  --arg incident1 "$RAW_INCIDENT_ONE" \
  --arg incident2 "$RAW_INCIDENT_TWO" \
  --arg description "$RAW_INCIDENT_DESCRIPTION" \
  '{
    value: [
      {
        id: $incident1,
        displayName: "private-incident-display-one",
        description: $description,
        assignedTo: "private-assignee-one",
        createdDateTime: "2099-01-01T00:00:00Z",
        lastUpdateDateTime: "2099-01-01T01:00:00Z",
        severity: "high",
        status: "active",
        classification: "truePositive",
        determination: "malware"
      },
      {
        id: $incident2,
        displayName: "private-incident-display-two",
        description: $description,
        assignedTo: "private-assignee-two",
        createdDateTime: "2099-01-01T02:00:00Z",
        lastUpdateDateTime: "2099-01-01T03:00:00Z",
        severity: "medium",
        status: "resolved",
        classification: "falsePositive",
        determination: "notMalicious"
      }
    ]
  }' \
  > "$INCIDENTS"

jq -n \
  --arg incident1 "$RAW_INCIDENT_ONE" \
  --arg incident2 "$RAW_INCIDENT_TWO" \
  --arg alert1 "$RAW_ALERT_ONE" \
  --arg alert2 "$RAW_ALERT_TWO" \
  --arg alert3 "$RAW_ALERT_THREE" \
  --arg deviceId "$RAW_DEVICE_ID" \
  --arg deviceName "$RAW_DEVICE_NAME" \
  --arg subjectId "$RAW_SUBJECT_ID" \
  --arg accountName "$RAW_ACCOUNT_NAME" \
  --arg fileName "$RAW_FILE_NAME" \
  --arg filePath "$RAW_FILE_PATH" \
  --arg fileHash "$RAW_FILE_HASH" \
  --arg processCommand "$RAW_PROCESS_COMMAND" \
  --arg networkValue "$RAW_NETWORK_VALUE" \
  --arg title "$RAW_ALERT_TITLE" \
  '{
    value: [
      {
        id: $alert1,
        incidentId: $incident1,
        title: $title,
        description: "private-description-one",
        createdDateTime: "2099-01-01T00:05:00Z",
        lastUpdateDateTime: "2099-01-01T00:10:00Z",
        severity: "high",
        status: "new",
        classification: "truePositive",
        determination: "malware",
        investigationState: "running",
        serviceSource: "microsoftDefenderForEndpoint",
        mitreTechniques: [
          "T1001",
          "T1002"
        ],
        evidence: [
          {
            "@odata.type": "#microsoft.graph.security.deviceEvidence",
            verdict: "malicious",
            remediationStatus: "active",
            roles: [
              "compromised"
            ],
            mdeDeviceId: $deviceId,
            deviceDnsName: $deviceName,
            hostName: $deviceName,
            osPlatform: "Windows11",
            lastIpAddress: $networkValue
          },
          {
            "@odata.type": "#microsoft.graph.security.userEvidence",
            verdict: "suspicious",
            remediationStatus: "none",
            roles: [
              "compromised"
            ],
            userAccount: {
              userSid: $subjectId,
              accountName: $accountName,
              userPrincipalName: null
            }
          }
        ]
      },
      {
        id: $alert2,
        incidentId: $incident1,
        title: $title,
        description: "private-description-two",
        createdDateTime: "2099-01-01T00:20:00Z",
        lastUpdateDateTime: "2099-01-01T00:30:00Z",
        severity: "medium",
        status: "inProgress",
        classification: "truePositive",
        determination: "malware",
        investigationState: "partiallyRemediated",
        serviceSource: "microsoftDefenderForEndpoint",
        mitreTechniques: [],
        evidence: [
          {
            "@odata.type": "#microsoft.graph.security.fileEvidence",
            verdict: "malicious",
            remediationStatus: "remediated",
            roles: [
              "related"
            ],
            fileName: $fileName,
            filePath: $filePath,
            fileHash: {
              algorithm: "sha256",
              hashValue: $fileHash
            }
          },
          {
            "@odata.type": "#microsoft.graph.security.processEvidence",
            verdict: "suspicious",
            remediationStatus: "none",
            roles: [
              "related"
            ],
            processCommandLine: $processCommand
          }
        ]
      },
      {
        id: $alert3,
        incidentId: $incident2,
        title: $title,
        description: "private-description-three",
        createdDateTime: "2099-01-01T02:05:00Z",
        lastUpdateDateTime: "2099-01-01T02:10:00Z",
        severity: "low",
        status: "resolved",
        classification: "falsePositive",
        determination: "notMalicious",
        investigationState: "benign",
        serviceSource: "microsoftDefenderForIdentity",
        mitreTechniques: [],
        evidence: [
          {
            "@odata.type": "#microsoft.graph.security.userEvidence",
            verdict: "unknown",
            remediationStatus: "none",
            roles: [
              "related"
            ],
            userAccount: {
              userSid: $subjectId,
              accountName: $accountName,
              userPrincipalName: null
            }
          }
        ]
      }
    ]
  }' \
  > "$ALERTS"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/Convert-EndpointSecuritySignals.ps1" \
  -CasePath "$CASE_PATH" \
  -AlertsPath "$ALERTS" \
  -IncidentsPath "$INCIDENTS" \
  -OutputPath "$SUMMARY" \
  >/dev/null

jq -e . \
  "$SUMMARY" \
  >/dev/null

[[ "$(jq -r '.feature' "$SUMMARY")" == "6" ]]
[[ "$(jq -r '.investigation_type' "$SUMMARY")" == "ENDPOINT_SECURITY" ]]

[[ "$(jq -r '.investigation_boundary.unified_security_alert_and_incident_analysis' "$SUMMARY")" == "true" ]]
[[ "$(jq -r '.investigation_boundary.direct_endpoint_inventory_query' "$SUMMARY")" == "false" ]]
[[ "$(jq -r '.investigation_boundary.endpoint_response_action' "$SUMMARY")" == "false" ]]
[[ "$(jq -r '.investigation_boundary.tenant_remediation_execution' "$SUMMARY")" == "false" ]]

[[ "$(jq -r '.counts.incident_records' "$SUMMARY")" == "2" ]]
[[ "$(jq -r '.counts.alert_records' "$SUMMARY")" == "3" ]]
[[ "$(jq -r '.counts.incident_alias_count' "$SUMMARY")" == "2" ]]
[[ "$(jq -r '.counts.alert_alias_count' "$SUMMARY")" == "3" ]]
[[ "$(jq -r '.counts.device_alias_count' "$SUMMARY")" == "1" ]]
[[ "$(jq -r '.counts.subject_alias_count' "$SUMMARY")" == "1" ]]
[[ "$(jq -r '.counts.evidence_records' "$SUMMARY")" == "5" ]]
[[ "$(jq -r '.counts.device_evidence_records' "$SUMMARY")" == "1" ]]
[[ "$(jq -r '.counts.user_evidence_records' "$SUMMARY")" == "2" ]]
[[ "$(jq -r '.counts.malicious_evidence_records' "$SUMMARY")" == "2" ]]
[[ "$(jq -r '.counts.suspicious_evidence_records' "$SUMMARY")" == "2" ]]
[[ "$(jq -r '.counts.endpoint_associated_alerts' "$SUMMARY")" == "2" ]]

INCIDENT_ALIAS_COUNT="$(
  jq \
    '[
      .incidents[].incident_alias,
      .alerts[].incident_alias
    ] |
    map(
      select(
        test("^INCIDENT-[0-9]{3}$")
        and
        . != "INCIDENT-000"
      )
    ) |
    unique |
    length' \
    "$SUMMARY"
)"

ALERT_ALIAS_COUNT="$(
  jq \
    '[
      .alerts[].alert_alias
    ] |
    map(
      select(
        test("^ALERT-[0-9]{3}$")
        and
        . != "ALERT-000"
      )
    ) |
    unique |
    length' \
    "$SUMMARY"
)"

DEVICE_ALIAS_COUNT="$(
  jq \
    '[
      .alerts[].evidence[]? |
      .device_alias?
    ] |
    map(
      select(
        type == "string"
        and
        test("^DEVICE-[0-9]{3}$")
        and
        . != "DEVICE-000"
      )
    ) |
    unique |
    length' \
    "$SUMMARY"
)"

SUBJECT_ALIAS_COUNT="$(
  jq \
    '[
      .alerts[].evidence[]? |
      .subject_alias?
    ] |
    map(
      select(
        type == "string"
        and
        test("^SUBJECT-[0-9]{3}$")
        and
        . != "SUBJECT-000"
      )
    ) |
    unique |
    length' \
    "$SUMMARY"
)"

[[ "$INCIDENT_ALIAS_COUNT" -eq 2 ]]
[[ "$ALERT_ALIAS_COUNT" -eq 3 ]]
[[ "$DEVICE_ALIAS_COUNT" -eq 1 ]]
[[ "$SUBJECT_ALIAS_COUNT" -eq 1 ]]

[[ "$(
  jq -r '
    .incidents[] |
    select(.incident_alias == "INCIDENT-001") |
    .correlated_alert_count
  ' \
    "$SUMMARY"
)" == "2" ]]

[[ "$(
  jq -r '
    .incidents[] |
    select(.incident_alias == "INCIDENT-002") |
    .correlated_alert_count
  ' \
    "$SUMMARY"
)" == "1" ]]

for RAW_VALUE in \
  "$RAW_INCIDENT_ONE" \
  "$RAW_INCIDENT_TWO" \
  "$RAW_ALERT_ONE" \
  "$RAW_ALERT_TWO" \
  "$RAW_ALERT_THREE" \
  "$RAW_DEVICE_ID" \
  "$RAW_DEVICE_NAME" \
  "$RAW_SUBJECT_ID" \
  "$RAW_ACCOUNT_NAME" \
  "$RAW_FILE_NAME" \
  "$RAW_FILE_PATH" \
  "$RAW_FILE_HASH" \
  "$RAW_PROCESS_COMMAND" \
  "$RAW_NETWORK_VALUE" \
  "$RAW_ALERT_TITLE" \
  "$RAW_INCIDENT_DESCRIPTION"
do
  if grep -Fq \
    -- "$RAW_VALUE" \
    "$SUMMARY"
  then
    echo "FAIL: raw endpoint or security artifact leaked into summary." >&2
    exit 1
  fi
done

for FIELD in \
  raw_alert_ids_retained \
  raw_incident_ids_retained \
  raw_device_ids_retained \
  raw_device_names_retained \
  raw_user_ids_retained \
  raw_upns_retained \
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
      '.privacy[$field]' \
      "$SUMMARY"
  )" == "false" ]]
done

SUMMARY_SHA="$(
  sha256sum "$SUMMARY" |
  awk '{print $1}'
)"

[[ "$SUMMARY_SHA" =~ ^[0-9a-f]{64}$ ]]

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/Add-IncidentEvidenceRecord.ps1" \
  -CasePath "$CASE_PATH" \
  -EvidenceId "EVID-ENDPOINT01" \
  -SourceType "OTHER_SANITIZED" \
  -SanitizedLabel "Endpoint security sanitized investigation summary" \
  -SourceFile "$SUMMARY" \
  >/dev/null

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
     select(.evidence_id == "EVID-ENDPOINT01") |
     .sha256' \
    "$CASE_PATH/evidence-index.json"
)"

[[ "$REGISTERED_SHA" == "$SUMMARY_SHA" ]]

printf 'ENDPOINT_SECURITY_INVESTIGATION_TEST=PASS\n'
printf 'INCIDENT_ALERT_CORRELATION=PASS\n'
printf 'DEVICE_ALIAS_CORRELATION=PASS\n'
printf 'SUBJECT_ALIAS_CORRELATION=PASS\n'
printf 'RAW_ENDPOINT_IDENTIFIER_NON_RETENTION=PASS\n'
printf 'RAW_FILE_NETWORK_ARTIFACT_NON_RETENTION=PASS\n'
printf 'ENDPOINT_RESPONSE_ACTION_BOUNDARY=PASS\n'
printf 'FEATURE_3_EVIDENCE_INTEGRATION=PASS\n'
