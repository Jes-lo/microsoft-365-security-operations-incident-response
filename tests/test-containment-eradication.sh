#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

PLANNER="$ROOT/automation/powershell/New-ContainmentEradicationPlan.ps1"

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
CASE_ID="IR-20990101-RESP8A"
CASE_PATH="$CASE_ROOT/$CASE_ID"

REQUEST="$WORK/request.json"
PLAN_ONE="$WORK/plan-one.json"
PLAN_TWO="$WORK/plan-two.json"

mkdir -p "$CASE_ROOT"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/New-IncidentCase.ps1" \
  -CaseId "$CASE_ID" \
  -Severity "SEV2" \
  -TitleSanitized "Synthetic containment and eradication simulation" \
  -RootPath "$CASE_ROOT" \
  >/dev/null

cat > "$REQUEST" <<JSON
{
  "schema_version": 1,
  "feature": 8,
  "case_id": "$CASE_ID",
  "execution_mode": "SIMULATION_ONLY",
  "live_execution_authorized": false,
  "actions": [
    {
      "sequence": 1,
      "action_type": "SUBJECT_REVOKE_SESSIONS",
      "target_alias": "SUBJECT-001",
      "reason_category": "SUSPECTED_ACCOUNT_COMPROMISE"
    },
    {
      "sequence": 2,
      "action_type": "APPLICATION_DISABLE_ACCESS",
      "target_alias": "APP-001",
      "reason_category": "MALICIOUS_APPLICATION_ACTIVITY"
    },
    {
      "sequence": 3,
      "action_type": "DEVICE_ISOLATE",
      "target_alias": "DEVICE-001",
      "reason_category": "ENDPOINT_COMPROMISE"
    },
    {
      "sequence": 4,
      "action_type": "OAUTH_GRANT_REMOVE",
      "target_alias": "APP-001",
      "reason_category": "OAUTH_ABUSE"
    },
    {
      "sequence": 5,
      "action_type": "SUBJECT_CREDENTIAL_RESET",
      "target_alias": "SUBJECT-001",
      "reason_category": "CREDENTIAL_EXPOSURE"
    },
    {
      "sequence": 6,
      "action_type": "FILE_QUARANTINE",
      "target_alias": "FILE-001",
      "reason_category": "MALICIOUS_FILE_ACTIVITY"
    }
  ]
}
JSON

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$PLANNER" \
  -CasePath "$CASE_PATH" \
  -RequestPath "$REQUEST" \
  -OutputPath "$PLAN_ONE" \
  >/dev/null

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$PLANNER" \
  -CasePath "$CASE_PATH" \
  -RequestPath "$REQUEST" \
  -OutputPath "$PLAN_TWO" \
  >/dev/null

jq -e . "$PLAN_ONE" >/dev/null
jq -e . "$PLAN_TWO" >/dev/null

cmp -s \
  "$PLAN_ONE" \
  "$PLAN_TWO" \
  || fail "Feature 8 plan output is not deterministic"

jq -e '
  .schema_version == 1
  and
  .feature == 8
  and
  .case_id == "IR-20990101-RESP8A"
  and
  .plan_type == "CONTAINMENT_ERADICATION_SIMULATION"
  and
  .execution_mode == "SIMULATION_ONLY"
  and
  .live_execution_authorized == false
  and
  .deterministic_output == true
  and
  .counts.planned_actions == 6
  and
  .counts.containment_actions == 3
  and
  .counts.eradication_actions == 3
  and
  .counts.executed_actions == 0
  and
  .counts.tenant_writes == 0
  and
  .counts.endpoint_actions == 0
  and
  .counts.response_actions == 0
  and
  .counts.graph_requests == 0
  and
  .action_gate.status == "NOT_PASSED"
  and
  .action_gate.explicit_operator_authorization == false
  and
  .action_gate.current_permission_resolution == "NOT_PERFORMED"
  and
  .action_gate.live_execution_available == false
  and
  .safety_boundary.graph_authentication_required == false
  and
  .safety_boundary.graph_requests == 0
  and
  .safety_boundary.tenant_reads == 0
  and
  .safety_boundary.tenant_writes == 0
  and
  .safety_boundary.endpoint_actions == 0
  and
  .safety_boundary.response_actions == 0
  and
  .safety_boundary.new_permission_grants == 0
  and
  .safety_boundary.role_assignments == 0
  and
  .safety_boundary.trial_activations == 0
  and
  .safety_boundary.destructive_action_default == "DENY"
  and
  .safety_boundary.live_response_action_default == "DENY"
  and
  .privacy.controlled_aliases_only == true
  and
  .privacy.controlled_reason_categories_only == true
  and
  .privacy.raw_tenant_identifiers_retained == false
  and
  .privacy.raw_user_identifiers_retained == false
  and
  .privacy.raw_application_identifiers_retained == false
  and
  .privacy.raw_device_identifiers_retained == false
  and
  .privacy.raw_file_identifiers_retained == false
  and
  .privacy.raw_network_indicators_retained == false
  and
  .privacy.raw_credentials_retained == false
  and
  .privacy.raw_tokens_retained == false
  and
  all(
    .actions[];
    .execution_status == "NOT_EXECUTED"
    and
    .approval_status == "NOT_REQUESTED"
    and
    .permission_resolution == "DEFERRED_TO_EXPLICIT_ACTION_GATE"
    and
    .verification_requirement == "REQUIRED_BEFORE_ANY_LIVE_ACTION"
    and
    .rollback_requirement == "REQUIRED_BEFORE_ANY_LIVE_ACTION"
  )
' \
  "$PLAN_ONE" \
  >/dev/null \
  || fail "Feature 8 simulation contract failed"

expect_failure() {
  local LABEL="$1"
  local INPUT="$2"
  local OUTPUT="$WORK/${LABEL}-rejected-output.json"
  local LOG="$WORK/${LABEL}.log"

  [[ "$OUTPUT" != "$INPUT" ]] \
    || fail "test harness input/output collision: $LABEL"

  rm -f -- "$OUTPUT"

  set +e

  pwsh \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -File "$PLANNER" \
    -CasePath "$CASE_PATH" \
    -RequestPath "$INPUT" \
    -OutputPath "$OUTPUT" \
    >"$LOG" \
    2>&1

  local RC=$?

  set -e

  [[ "$RC" -ne 0 ]] \
    || fail "expected rejection did not occur: $LABEL"

  [[ ! -e "$OUTPUT" ]] \
    || fail "rejected request produced output: $LABEL"
}

LIVE_MODE="$WORK/live-mode.json"

jq '
  .execution_mode = "LIVE"
' \
  "$REQUEST" \
  > "$LIVE_MODE"

expect_failure \
  "live-mode" \
  "$LIVE_MODE"

printf 'LIVE_EXECUTION_REJECTION=PASS\n'

LIVE_AUTH="$WORK/live-auth.json"

jq '
  .live_execution_authorized = true
' \
  "$REQUEST" \
  > "$LIVE_AUTH"

expect_failure \
  "live-auth" \
  "$LIVE_AUTH"

printf 'LIVE_AUTHORIZATION_REJECTION=PASS\n'

RAW_GUID="$(
  printf '%s-%s-%s-%s-%s\n' \
    '11111111' \
    '2222' \
    '3333' \
    '4444' \
    '555555555555'
)"

RAW_TARGET="$WORK/raw-target.json"

jq \
  --arg raw "$RAW_GUID" \
  '
    .actions[0].target_alias = $raw
  ' \
  "$REQUEST" \
  > "$RAW_TARGET"

expect_failure \
  "raw-target" \
  "$RAW_TARGET"

printf 'RAW_IDENTIFIER_INPUT_REJECTION=PASS\n'

UNKNOWN_ACTION="$WORK/unknown-action.json"

jq '
  .actions[0].action_type = "UNSUPPORTED_RESPONSE_ACTION"
' \
  "$REQUEST" \
  > "$UNKNOWN_ACTION"

expect_failure \
  "unknown-action" \
  "$UNKNOWN_ACTION"

printf 'UNKNOWN_ACTION_REJECTION=PASS\n'

DUPLICATE_SEQUENCE="$WORK/duplicate-sequence.json"

jq '
  .actions[1].sequence = 1
' \
  "$REQUEST" \
  > "$DUPLICATE_SEQUENCE"

expect_failure \
  "duplicate-sequence" \
  "$DUPLICATE_SEQUENCE"

printf 'DUPLICATE_SEQUENCE_REJECTION=PASS\n'

NONCONTIGUOUS="$WORK/noncontiguous.json"

jq '
  .actions[5].sequence = 7
' \
  "$REQUEST" \
  > "$NONCONTIGUOUS"

expect_failure \
  "noncontiguous" \
  "$NONCONTIGUOUS"

printf 'NONCONTIGUOUS_SEQUENCE_REJECTION=PASS\n'

UNEXPECTED_PROPERTY="$WORK/unexpected-property.json"

jq '
  .actions[0].raw_user_id = "PRIVATE-VALUE"
' \
  "$REQUEST" \
  > "$UNEXPECTED_PROPERTY"

expect_failure \
  "unexpected-property" \
  "$UNEXPECTED_PROPERTY"

printf 'UNEXPECTED_PROPERTY_REJECTION=PASS\n'

WRONG_CASE="$WORK/wrong-case.json"

jq '
  .case_id = "IR-20990101-OTHER8"
' \
  "$REQUEST" \
  > "$WRONG_CASE"

expect_failure \
  "wrong-case" \
  "$WRONG_CASE"

printf 'CASE_BINDING_REJECTION=PASS\n'

FREEFORM_REASON="$WORK/freeform-reason.json"

jq '
  .actions[0].reason_category = "free form incident details"
' \
  "$REQUEST" \
  > "$FREEFORM_REASON"

expect_failure \
  "freeform-reason" \
  "$FREEFORM_REASON"

printf 'FREE_FORM_REASON_REJECTION=PASS\n'

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/Add-IncidentEvidenceRecord.ps1" \
  -CasePath "$CASE_PATH" \
  -EvidenceId "EVID-F8PLAN01" \
  -SourceType "LOCAL_FILE" \
  -SanitizedLabel "Synthetic containment eradication response plan" \
  -SourceFile "$PLAN_ONE" \
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
  "$INTEGRITY" \
  || fail "Feature 3 incident integrity failed"

grep -Fxq \
  'CUSTODY_HASH_CHAIN=PASS' \
  "$INTEGRITY" \
  || fail "Feature 3 custody chain failed"

grep -Fxq \
  'RAW_EVIDENCE_RETENTION=NO' \
  "$INTEGRITY" \
  || fail "Feature 3 raw-evidence boundary failed"

PLAN_SHA="$(
  sha256sum "$PLAN_ONE" |
  awk '{print $1}'
)"

REGISTERED_SHA="$(
  jq -r \
    '.evidence[] |
     select(.evidence_id == "EVID-F8PLAN01") |
     .sha256' \
    "$CASE_PATH/evidence-index.json"
)"

[[ "$PLAN_SHA" == "$REGISTERED_SHA" ]] \
  || fail "Feature 3 evidence SHA mismatch"

printf 'CONTAINMENT_ERADICATION_SIMULATION_TEST=PASS\n'
printf 'DETERMINISTIC_RESPONSE_PLAN=PASS\n'
printf 'NO_LIVE_ACTION_EXECUTION=PASS\n'
printf 'FEATURE_3_EVIDENCE_INTEGRATION=PASS\n'
