#!/usr/bin/env bash

set -euo pipefail
umask 077

fail() {
  printf 'IDENTITY_INVESTIGATION_TEST=FAIL: %s\n' "$1" >&2
  exit 1
}

ROOT="$(
  cd \
    "$(dirname "${BASH_SOURCE[0]}")/.." \
    >/dev/null 2>&1 &&
  pwd
)"

WORK="$(mktemp -d)"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

command -v pwsh >/dev/null \
  || fail "PowerShell 7 unavailable"

CASE_ROOT="$WORK/cases"
CASE_ID="IR-20990101-IDTEST"
CASE_PATH="$CASE_ROOT/$CASE_ID"

SIGN_INS="$WORK/sign-ins.json"
AUDITS="$WORK/directory-audits.json"
RISKS="$WORK/risk-detections.json"
SUMMARY="$WORK/identity-summary.json"

USER_ONE_GUID='11111111''-''1111''-''1111''-''1111''-''111111111111'
USER_TWO_GUID='22222222''-''2222''-''2222''-''2222''-''222222222222'
EVENT_GUID='33333333''-''3333''-''3333''-''3333''-''333333333333'

USER_ONE_UPN='identity.one''@''example.test'
USER_TWO_UPN='identity.two''@''example.test'

IP_ONE='198.51.100.10'
IP_TWO='203.0.113.20'

mkdir -p "$CASE_ROOT"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/New-IncidentCase.ps1" \
  -CaseId "$CASE_ID" \
  -Severity "SEV2" \
  -TitleSanitized "Synthetic identity investigation" \
  -RootPath "$CASE_ROOT" \
  >/dev/null

jq -n \
  --arg u1 "$USER_ONE_GUID" \
  --arg u2 "$USER_TWO_GUID" \
  --arg p1 "$USER_ONE_UPN" \
  --arg p2 "$USER_TWO_UPN" \
  --arg e "$EVENT_GUID" \
  --arg ip1 "$IP_ONE" \
  --arg ip2 "$IP_TWO" \
  '{
    value: [
      {
        id: $e,
        createdDateTime: "2099-01-01T01:00:00Z",
        userId: $u1,
        userPrincipalName: $p1,
        ipAddress: $ip1,
        status: {
          errorCode: 0
        },
        riskLevelAggregated: "none"
      },
      {
        id: ($e + "-not-a-real-guid"),
        createdDateTime: "2099-01-01T01:05:00Z",
        userId: $u1,
        userPrincipalName: $p1,
        ipAddress: $ip2,
        status: {
          errorCode: 50053
        },
        riskLevelAggregated: "medium"
      },
      {
        id: "synthetic-event-three",
        createdDateTime: "2099-01-01T01:10:00Z",
        userId: $u2,
        userPrincipalName: $p2,
        ipAddress: $ip2,
        status: {
          errorCode: 0
        },
        riskLevelAggregated: "none"
      }
    ]
  }' \
  > "$SIGN_INS"

jq -n \
  --arg u1 "$USER_ONE_GUID" \
  --arg p1 "$USER_ONE_UPN" \
  --arg u2 "$USER_TWO_GUID" \
  --arg p2 "$USER_TWO_UPN" \
  --arg e "$EVENT_GUID" \
  '{
    value: [
      {
        id: $e,
        activityDateTime: "2099-01-01T01:07:00Z",
        category: "UserManagement",
        result: "success",
        initiatedBy: {
          user: {
            id: $u1,
            userPrincipalName: $p1
          }
        },
        targetResources: [
          {
            id: $u2,
            type: "User",
            userPrincipalName: $p2
          }
        ]
      }
    ]
  }' \
  > "$AUDITS"

jq -n \
  --arg u1 "$USER_ONE_GUID" \
  --arg p1 "$USER_ONE_UPN" \
  --arg e "$EVENT_GUID" \
  --arg ip "$IP_ONE" \
  '{
    value: [
      {
        id: $e,
        detectedDateTime: "2099-01-01T01:04:00Z",
        userId: $u1,
        userPrincipalName: $p1,
        ipAddress: $ip,
        riskEventType: "unfamiliarFeatures",
        riskLevel: "medium",
        riskState: "atRisk"
      }
    ]
  }' \
  > "$RISKS"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/Convert-IdentitySecuritySignals.ps1" \
  -CasePath "$CASE_PATH" \
  -SignInsPath "$SIGN_INS" \
  -DirectoryAuditsPath "$AUDITS" \
  -RiskDetectionsPath "$RISKS" \
  -OutputPath "$SUMMARY" \
  >/dev/null

[[ -f "$SUMMARY" ]] \
  || fail "sanitized identity summary not created"

jq -e \
  '
    .schema_version == 1
    and
    .case_id == "IR-20990101-IDTEST"
    and
    .investigation_type == "IDENTITY_SECURITY"
    and
    .privacy_mode == "SUBJECT_ALIAS_ONLY"
    and
    .raw_identifiers_retained == false
    and
    .raw_graph_payload_retained == false
    and
    .source_counts.sign_ins == 3
    and
    .source_counts.directory_audits == 1
    and
    .source_counts.risk_detections == 1
    and
    .finding_counts.failed_sign_ins == 1
    and
    .finding_counts.risky_sign_ins == 1
    and
    .finding_counts.risk_detections == 1
    and
    .finding_counts.unique_subjects == 2
    and
    (.sign_ins | length) == 3
    and
    (.directory_audits | length) == 1
    and
    (.risk_detections | length) == 1
  ' \
  "$SUMMARY" \
  >/dev/null \
  || fail "sanitized investigation summary contract failed"

for SECRET_VALUE in \
  "$USER_ONE_GUID" \
  "$USER_TWO_GUID" \
  "$EVENT_GUID" \
  "$USER_ONE_UPN" \
  "$USER_TWO_UPN" \
  "$IP_ONE" \
  "$IP_TWO"
do
  if grep -Fq \
    "$SECRET_VALUE" \
    "$SUMMARY"
  then
    fail "raw synthetic identifier leaked into sanitized summary"
  fi
done

ALIAS_COUNT="$(
  jq \
    '[
      .sign_ins[].subject_alias,
      .directory_audits[].actor_alias,
      .directory_audits[].target_alias,
      .risk_detections[].subject_alias
    ] |
    map(
      select(
        test("^SUBJECT-[0-9]{3}$")
      )
    ) |
    unique |
    length' \
    "$SUMMARY"
)"

[[ "$ALIAS_COUNT" -eq 2 ]] \
  || fail "expected two correlated subject aliases"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/Add-IncidentEvidenceRecord.ps1" \
  -CasePath "$CASE_PATH" \
  -EvidenceId "EVID-IDINV01" \
  -SourceType "OTHER_SANITIZED" \
  -SanitizedLabel "Sanitized identity investigation summary" \
  -SourceFile "$SUMMARY" \
  >/dev/null

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/Test-IncidentCaseIntegrity.ps1" \
  -CasePath "$CASE_PATH" \
  >/dev/null

jq -e \
  '
    .evidence_count == 1
    and
    .custody_event_count == 1
    and
    .raw_tenant_data_retained == false
  ' \
  "$CASE_PATH/case.json" \
  >/dev/null \
  || fail "Feature 3 case integration failed"

jq -e \
  '
    (.evidence | length) == 1
    and
    .evidence[0].evidence_id == "EVID-IDINV01"
    and
    .evidence[0].raw_content_retained == false
    and
    (.evidence[0].sha256 | test("^[0-9a-f]{64}$"))
  ' \
  "$CASE_PATH/evidence-index.json" \
  >/dev/null \
  || fail "Feature 3 evidence registration failed"

printf 'IDENTITY_INVESTIGATION_TEST=PASS\n'
printf 'SUBJECT_ALIAS_CORRELATION=PASS\n'
printf 'RAW_IDENTITY_IDENTIFIER_NON_RETENTION=PASS\n'
printf 'FEATURE_3_EVIDENCE_INTEGRATION=PASS\n'
