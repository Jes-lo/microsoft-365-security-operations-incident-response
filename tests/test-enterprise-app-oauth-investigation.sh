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
CASE_ID="IR-20990101-APPOAUTH"
CASE_PATH="$CASE_ROOT/$CASE_ID"

SIGNINS="$TMP_DIR/signins.json"
AUDITS="$TMP_DIR/audits.json"
SUMMARY="$TMP_DIR/summary.json"
INTEGRITY="$TMP_DIR/integrity.txt"

RAW_USER_ONE="private-user-internal-one"
RAW_USER_TWO="private-user-internal-two"
RAW_APP_ONE="private-application-internal-alpha"
RAW_APP_TWO="private-application-internal-beta"
RAW_GRANT_VALUE="private-oauth-grant-value-do-not-retain"

mkdir -p "$CASE_ROOT"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/New-IncidentCase.ps1" \
  -CaseId "$CASE_ID" \
  -Severity "SEV2" \
  -TitleSanitized "Enterprise application OAuth investigation synthetic test" \
  -RootPath "$CASE_ROOT" \
  >/dev/null

jq -n \
  --arg user1 "$RAW_USER_ONE" \
  --arg user2 "$RAW_USER_TWO" \
  --arg app1 "$RAW_APP_ONE" \
  --arg app2 "$RAW_APP_TWO" \
  '{
    value: [
      {
        createdDateTime: "2099-01-01T00:00:00Z",
        userId: $user1,
        appId: $app1,
        status: {
          errorCode: 0
        },
        riskLevelAggregated: "none"
      },
      {
        createdDateTime: "2099-01-01T00:05:00Z",
        userId: $user2,
        appId: $app1,
        status: {
          errorCode: 50058
        },
        riskLevelAggregated: "none"
      },
      {
        createdDateTime: "2099-01-01T00:10:00Z",
        userId: $user1,
        appId: $app2,
        status: {
          errorCode: 0
        },
        riskLevelAggregated: "medium"
      }
    ]
  }' \
  > "$SIGNINS"

jq -n \
  --arg user1 "$RAW_USER_ONE" \
  --arg app1 "$RAW_APP_ONE" \
  --arg app2 "$RAW_APP_TWO" \
  --arg grant "$RAW_GRANT_VALUE" \
  '{
    value: [
      {
        activityDateTime: "2099-01-01T00:15:00Z",
        category: "ApplicationManagement",
        activityDisplayName: "Consent to application",
        result: "success",
        initiatedBy: {
          user: {
            id: $user1
          }
        },
        targetResources: [
          {
            id: $app1,
            type: "ServicePrincipal",
            displayName: "Private Synthetic Application Alpha",
            modifiedProperties: [
              {
                displayName: "ConsentAction.Permissions",
                oldValue: null,
                newValue: $grant
              }
            ]
          }
        ]
      },
      {
        activityDateTime: "2099-01-01T00:20:00Z",
        category: "ApplicationManagement",
        activityDisplayName: "Update application",
        result: "success",
        initiatedBy: {
          user: {
            id: $user1
          }
        },
        targetResources: [
          {
            id: $app2,
            type: "Application",
            displayName: "Private Synthetic Application Beta",
            modifiedProperties: []
          }
        ]
      }
    ]
  }' \
  > "$AUDITS"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/Convert-EnterpriseAppOAuthSignals.ps1" \
  -CasePath "$CASE_PATH" \
  -SignInsPath "$SIGNINS" \
  -DirectoryAuditsPath "$AUDITS" \
  -OutputPath "$SUMMARY" \
  >/dev/null

jq -e . "$SUMMARY" >/dev/null

[[ "$(jq -r '.feature' "$SUMMARY")" == "5" ]]
[[ "$(jq -r '.investigation_type' "$SUMMARY")" == "ENTERPRISE_APPLICATION_OAUTH" ]]

[[ "$(jq -r '.counts.sign_in_records' "$SUMMARY")" == "3" ]]
[[ "$(jq -r '.counts.directory_audit_records' "$SUMMARY")" == "2" ]]
[[ "$(jq -r '.counts.application_alias_count' "$SUMMARY")" == "2" ]]
[[ "$(jq -r '.counts.subject_alias_count' "$SUMMARY")" == "2" ]]
[[ "$(jq -r '.counts.failed_sign_ins' "$SUMMARY")" == "1" ]]
[[ "$(jq -r '.counts.risky_sign_ins' "$SUMMARY")" == "1" ]]
[[ "$(jq -r '.counts.consent_events' "$SUMMARY")" == "1" ]]
[[ "$(jq -r '.counts.permission_change_events' "$SUMMARY")" == "1" ]]

APP_ALIAS_COUNT="$(
  jq \
    '[
      .sign_ins[].app_alias,
      .directory_audits[].app_alias
    ] |
    map(
      select(
        test("^APP-[0-9]{3}$")
        and
        . != "APP-000"
      )
    ) |
    unique |
    length' \
    "$SUMMARY"
)"

SUBJECT_ALIAS_COUNT="$(
  jq \
    '[
      .sign_ins[].subject_alias,
      .directory_audits[].actor_alias
    ] |
    map(
      select(
        test("^SUBJECT-[0-9]{3}$")
        and
        . != "SUBJECT-000"
      )
    ) |
    unique |
    length' \
    "$SUMMARY"
)"

[[ "$APP_ALIAS_COUNT" -eq 2 ]]
[[ "$SUBJECT_ALIAS_COUNT" -eq 2 ]]

for RAW_VALUE in \
  "$RAW_USER_ONE" \
  "$RAW_USER_TWO" \
  "$RAW_APP_ONE" \
  "$RAW_APP_TWO" \
  "$RAW_GRANT_VALUE"
do
  if grep -Fq \
    "$RAW_VALUE" \
    "$SUMMARY"
  then
    echo "FAIL: raw synthetic identifier or grant leaked into summary." >&2
    exit 1
  fi
done

[[ "$(
  jq -r '.privacy.raw_application_ids_retained' "$SUMMARY"
)" == "false" ]]

[[ "$(
  jq -r '.privacy.raw_service_principal_ids_retained' "$SUMMARY"
)" == "false" ]]

[[ "$(
  jq -r '.privacy.raw_user_ids_retained' "$SUMMARY"
)" == "false" ]]

[[ "$(
  jq -r '.privacy.raw_upns_retained' "$SUMMARY"
)" == "false" ]]

[[ "$(
  jq -r '.privacy.raw_ip_addresses_retained' "$SUMMARY"
)" == "false" ]]

[[ "$(
  jq -r '.privacy.raw_grant_values_retained' "$SUMMARY"
)" == "false" ]]

[[ "$(
  jq -r '.privacy.raw_graph_payloads_retained' "$SUMMARY"
)" == "false" ]]

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
  -EvidenceId "EVID-APPOAUTH01" \
  -SourceType "OTHER_SANITIZED" \
  -SanitizedLabel "Enterprise app OAuth sanitized investigation summary" \
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
     select(.evidence_id == "EVID-APPOAUTH01") |
     .sha256' \
    "$CASE_PATH/evidence-index.json"
)"

[[ "$REGISTERED_SHA" == "$SUMMARY_SHA" ]]

printf 'ENTERPRISE_APP_OAUTH_INVESTIGATION_TEST=PASS\n'
printf 'APPLICATION_ALIAS_CORRELATION=PASS\n'
printf 'SUBJECT_ALIAS_CORRELATION=PASS\n'
printf 'RAW_APPLICATION_IDENTIFIER_NON_RETENTION=PASS\n'
printf 'RAW_OAUTH_GRANT_VALUE_NON_RETENTION=PASS\n'
printf 'FEATURE_3_EVIDENCE_INTEGRATION=PASS\n'
