#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

PLANNER="$ROOT/automation/powershell/New-ContainmentEradicationPlan.ps1"
GATE="$ROOT/automation/powershell/Test-ContainmentEradicationActionGate.ps1"

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
CASE_ID="IR-20990102-GATE8B"
CASE_PATH="$CASE_ROOT/$CASE_ID"

PLAN_REQUEST="$WORK/plan-request.json"
PLAN="$WORK/plan.json"

GATE_REQUEST="$WORK/gate-request.json"
GATE_ONE="$WORK/gate-one.json"
GATE_TWO="$WORK/gate-two.json"

mkdir -p "$CASE_ROOT"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/New-IncidentCase.ps1" \
  -CaseId "$CASE_ID" \
  -Severity "SEV2" \
  -TitleSanitized "Synthetic explicit response gate model" \
  -RootPath "$CASE_ROOT" \
  >/dev/null

cat > "$PLAN_REQUEST" <<JSON
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
      "action_type": "DEVICE_ISOLATE",
      "target_alias": "DEVICE-001",
      "reason_category": "ENDPOINT_COMPROMISE"
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
  -RequestPath "$PLAN_REQUEST" \
  -OutputPath "$PLAN" \
  >/dev/null

cat > "$GATE_REQUEST" <<JSON
{
  "schema_version": 1,
  "feature": 8,
  "case_id": "$CASE_ID",
  "gate_scope": "LOCAL_MODEL_REVIEW_ONLY",
  "live_execution_requested": false,
  "operator_authorization": "AUTHORIZED_FOR_SEPARATE_LIVE_GATE_REVIEW",
  "concrete_permission_resolution": "DEFERRED_TO_SEPARATE_LIVE_GATE",
  "action_reviews": [
    {
      "sequence": 1,
      "exact_action_confirmed": true,
      "target_class_confirmed": true,
      "impact_acknowledged": true,
      "reversibility_acknowledged": true,
      "prerequisites_confirmed": true,
      "symbolic_capability_confirmed": true,
      "verification_plan_confirmed": true,
      "rollback_plan_confirmed": true,
      "evidence_handling_confirmed": true
    },
    {
      "sequence": 2,
      "exact_action_confirmed": true,
      "target_class_confirmed": true,
      "impact_acknowledged": true,
      "reversibility_acknowledged": true,
      "prerequisites_confirmed": true,
      "symbolic_capability_confirmed": true,
      "verification_plan_confirmed": true,
      "rollback_plan_confirmed": true,
      "evidence_handling_confirmed": true
    }
  ]
}
JSON

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$GATE" \
  -PlanPath "$PLAN" \
  -GateRequestPath "$GATE_REQUEST" \
  -OutputPath "$GATE_ONE" \
  >/dev/null

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$GATE" \
  -PlanPath "$PLAN" \
  -GateRequestPath "$GATE_REQUEST" \
  -OutputPath "$GATE_TWO" \
  >/dev/null

cmp -s \
  "$GATE_ONE" \
  "$GATE_TWO" \
  || fail "Feature 8B gate output is not deterministic"

jq -e '
  .schema_version == 1
  and
  .feature == 8
  and
  .case_id == "IR-20990102-GATE8B"
  and
  .gate_type == "EXPLICIT_RESPONSE_ACTION_GATE_MODEL"
  and
  .gate_scope == "LOCAL_MODEL_REVIEW_ONLY"
  and
  .deterministic_output == true
  and
  .operator_authorization.decision
    == "AUTHORIZED_FOR_SEPARATE_LIVE_GATE_REVIEW"
  and
  .operator_authorization.scope
    == "SEPARATE_LIVE_GATE_REVIEW_ONLY"
  and
  .operator_authorization.authorizes_live_execution == false
  and
  .operator_authorization.authorizes_permission_grant == false
  and
  .operator_authorization.authorizes_role_assignment == false
  and
  .operator_authorization.authorizes_tenant_write == false
  and
  .operator_authorization.authorizes_endpoint_action == false
  and
  .decision.gate_status
    == "READY_FOR_SEPARATE_LIVE_GATE_REVIEW"
  and
  .decision.execution_release == "NOT_RELEASED"
  and
  .decision.live_execution_available == false
  and
  .decision.concrete_permission_resolution
    == "DEFERRED_TO_SEPARATE_LIVE_GATE"
  and
  .counts.reviewed_actions == 2
  and
  .counts.ready_for_separate_live_gate_review == 2
  and
  .counts.blocked_actions == 0
  and
  .counts.executed_actions == 0
  and
  .counts.graph_requests == 0
  and
  .counts.tenant_reads == 0
  and
  .counts.tenant_writes == 0
  and
  .counts.endpoint_actions == 0
  and
  .counts.response_actions == 0
  and
  .counts.new_permission_grants == 0
  and
  .counts.role_assignments == 0
  and
  .counts.trial_activations == 0
  and
  .safety_boundary.live_execution_release == false
  and
  .safety_boundary.destructive_action_default == "DENY"
  and
  all(
    .actions[];
    .gate_status
      == "READY_FOR_SEPARATE_LIVE_GATE_REVIEW"
    and
    .concrete_permission_resolution
      == "DEFERRED_TO_SEPARATE_LIVE_GATE"
    and
    .execution_release == "NOT_RELEASED"
    and
    .execution_status == "NOT_EXECUTED"
  )
' \
  "$GATE_ONE" \
  >/dev/null \
  || fail "Feature 8B ready-gate contract failed"

printf 'READY_GATE_REVIEW_MODEL=PASS\n'
printf 'READY_GATE_DOES_NOT_RELEASE_EXECUTION=PASS\n'
printf 'DETERMINISTIC_ACTION_GATE=PASS\n'

BLOCKED_REQUEST="$WORK/blocked-request.json"
BLOCKED_OUTPUT="$WORK/blocked-output.json"

jq '
  .action_reviews[1].rollback_plan_confirmed = false
' \
  "$GATE_REQUEST" \
  > "$BLOCKED_REQUEST"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$GATE" \
  -PlanPath "$PLAN" \
  -GateRequestPath "$BLOCKED_REQUEST" \
  -OutputPath "$BLOCKED_OUTPUT" \
  >/dev/null

jq -e '
  .decision.gate_status == "BLOCKED"
  and
  .decision.execution_release == "NOT_RELEASED"
  and
  .decision.live_execution_available == false
  and
  .counts.ready_for_separate_live_gate_review == 1
  and
  .counts.blocked_actions == 1
  and
  .counts.executed_actions == 0
  and
  any(
    .actions[];
    .gate_status == "BLOCKED"
  )
' \
  "$BLOCKED_OUTPUT" \
  >/dev/null \
  || fail "incomplete review did not fail closed"

printf 'INCOMPLETE_REVIEW_FAIL_CLOSED=PASS\n'

expect_failure() {
  local LABEL="$1"
  local INPUT="$2"
  local OUTPUT="$WORK/${LABEL}-rejected-output.json"
  local LOG="$WORK/${LABEL}.log"

  [[ "$OUTPUT" != "$INPUT" ]] \
    || fail "gate test input/output collision: $LABEL"

  rm -f -- "$OUTPUT"

  set +e

  pwsh \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -File "$GATE" \
    -PlanPath "$PLAN" \
    -GateRequestPath "$INPUT" \
    -OutputPath "$OUTPUT" \
    >"$LOG" \
    2>&1

  local RC=$?

  set -e

  [[ "$RC" -ne 0 ]] \
    || fail "expected gate rejection did not occur: $LABEL"

  [[ ! -e "$OUTPUT" ]] \
    || fail "rejected gate request produced output: $LABEL"
}

LIVE_REQUEST="$WORK/live-request.json"

jq '
  .live_execution_requested = true
' \
  "$GATE_REQUEST" \
  > "$LIVE_REQUEST"

expect_failure \
  "live-request" \
  "$LIVE_REQUEST"

printf 'LIVE_EXECUTION_REQUEST_REJECTION=PASS\n'

EXECUTE_AUTH="$WORK/execute-auth.json"

jq '
  .operator_authorization = "AUTHORIZED_TO_EXECUTE"
' \
  "$GATE_REQUEST" \
  > "$EXECUTE_AUTH"

expect_failure \
  "execute-auth" \
  "$EXECUTE_AUTH"

printf 'EXECUTION_AUTHORIZATION_VALUE_REJECTION=PASS\n'

WRITE_MARKER="$(
  printf '%s%s%s\n' \
    'User.' \
    'ReadWrite' \
    '.All'
)"

CONCRETE_PERMISSION="$WORK/concrete-permission.json"

jq \
  --arg marker "$WRITE_MARKER" \
  '
    .concrete_permission_resolution = $marker
  ' \
  "$GATE_REQUEST" \
  > "$CONCRETE_PERMISSION"

expect_failure \
  "concrete-permission" \
  "$CONCRETE_PERMISSION"

printf 'CONCRETE_PERMISSION_RESOLUTION_REJECTION=PASS\n'

WRONG_CASE="$WORK/wrong-case.json"

jq '
  .case_id = "IR-20990102-OTHER8B"
' \
  "$GATE_REQUEST" \
  > "$WRONG_CASE"

expect_failure \
  "wrong-case" \
  "$WRONG_CASE"

printf 'ACTION_GATE_CASE_BINDING_REJECTION=PASS\n'

DUPLICATE_REVIEW="$WORK/duplicate-review.json"

jq '
  .action_reviews[1].sequence = 1
' \
  "$GATE_REQUEST" \
  > "$DUPLICATE_REVIEW"

expect_failure \
  "duplicate-review" \
  "$DUPLICATE_REVIEW"

printf 'DUPLICATE_ACTION_REVIEW_REJECTION=PASS\n'

MISSING_REVIEW="$WORK/missing-review.json"

jq '
  del(.action_reviews[1])
' \
  "$GATE_REQUEST" \
  > "$MISSING_REVIEW"

expect_failure \
  "missing-review" \
  "$MISSING_REVIEW"

printf 'MISSING_ACTION_REVIEW_REJECTION=PASS\n'

UNEXPECTED_PROPERTY="$WORK/unexpected-property.json"

jq '
  .action_reviews[0].raw_object_identifier = "PRIVATE-VALUE"
' \
  "$GATE_REQUEST" \
  > "$UNEXPECTED_PROPERTY"

expect_failure \
  "unexpected-property" \
  "$UNEXPECTED_PROPERTY"

printf 'ACTION_GATE_UNEXPECTED_PROPERTY_REJECTION=PASS\n'

INVALID_BOOLEAN="$WORK/invalid-boolean.json"

jq '
  .action_reviews[0].impact_acknowledged = "yes"
' \
  "$GATE_REQUEST" \
  > "$INVALID_BOOLEAN"

expect_failure \
  "invalid-boolean" \
  "$INVALID_BOOLEAN"

printf 'ACTION_GATE_BOOLEAN_TYPE_REJECTION=PASS\n'

TAMPERED_PLAN="$WORK/tampered-plan.json"
TAMPERED_REQUEST="$WORK/tampered-request.json"

jq '
  .actions[0].execution_status = "EXECUTED"
' \
  "$PLAN" \
  > "$TAMPERED_PLAN"

cp \
  "$GATE_REQUEST" \
  "$TAMPERED_REQUEST"

set +e

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$GATE" \
  -PlanPath "$TAMPERED_PLAN" \
  -GateRequestPath "$TAMPERED_REQUEST" \
  -OutputPath "$WORK/tampered-output.json" \
  >"$WORK/tampered-plan.log" \
  2>&1

TAMPERED_RC=$?

set -e

[[ "$TAMPERED_RC" -ne 0 ]] \
  || fail "executed-plan tamper was not rejected"

[[ ! -e "$WORK/tampered-output.json" ]] \
  || fail "executed-plan tamper produced output"

printf 'EXECUTED_PLAN_TAMPER_REJECTION=PASS\n'

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$ROOT/automation/powershell/Add-IncidentEvidenceRecord.ps1" \
  -CasePath "$CASE_PATH" \
  -EvidenceId "EVID-F8GATE01" \
  -SourceType "LOCAL_FILE" \
  -SanitizedLabel "Synthetic explicit action gate result" \
  -SourceFile "$GATE_ONE" \
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

GATE_SHA="$(
  sha256sum "$GATE_ONE" |
  awk '{print $1}'
)"

REGISTERED_SHA="$(
  jq -r \
    '.evidence[] |
     select(.evidence_id == "EVID-F8GATE01") |
     .sha256' \
    "$CASE_PATH/evidence-index.json"
)"

[[ "$GATE_SHA" == "$REGISTERED_SHA" ]] \
  || fail "Feature 8B evidence SHA mismatch"

printf 'CONTAINMENT_ERADICATION_ACTION_GATE_TEST=PASS\n'
printf 'NO_LIVE_EXECUTION_RELEASE=PASS\n'
printf 'NO_CONCRETE_PERMISSION_RESOLUTION=PASS\n'
printf 'FEATURE_3_ACTION_GATE_EVIDENCE_INTEGRATION=PASS\n'
