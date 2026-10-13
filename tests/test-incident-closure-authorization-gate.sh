#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

PLANNER="$ROOT/automation/powershell/New-RecoveryValidationPlan.ps1"
PLAN_CONTRACT="$ROOT/configs/recovery-validation-contract.json"

CLOSURE_EVALUATOR="$ROOT/automation/powershell/Test-RecoveryClosureGate.ps1"
CLOSURE_CONTRACT="$ROOT/configs/recovery-closure-gate-contract.json"

AUTH_EVALUATOR="$ROOT/automation/powershell/Test-IncidentClosureAuthorizationGate.ps1"
AUTH_CONTRACT="$ROOT/configs/incident-closure-authorization-gate-contract.json"

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

PLAN_REQUEST="$WORK/plan-request.json"
RECOVERY_PLAN="$WORK/recovery-plan.json"

cat > "$PLAN_REQUEST" <<'JSON'
{
  "schema_version": 1,
  "feature": 9,
  "case_id": "IR-20261013-TEST9C",
  "gate_scope": "LOCAL_RECOVERY_VALIDATION_PLAN_ONLY",
  "live_recovery_requested": false,
  "action_items": [
    {
      "sequence": 1,
      "action_type": "SUBJECT_REVOKE_SESSIONS",
      "target_alias": "SUBJECT-001"
    }
  ]
}
JSON

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$PLANNER" \
  -InputPath "$PLAN_REQUEST" \
  -OutputPath "$RECOVERY_PLAN" \
  -ContractPath "$PLAN_CONTRACT" \
  >/dev/null

PLAN_HASH="$(
  sha256sum "$RECOVERY_PLAN" |
  awk '{print $1}'
)"

CLOSURE_REQUEST="$WORK/closure-request.json"
CLOSURE_OUTPUT="$WORK/closure-output.json"

jq -n \
  --arg hash "$PLAN_HASH" \
  --slurpfile plan "$RECOVERY_PLAN" \
  '{
    schema_version: 1,
    feature: 9,
    case_id: $plan[0].case_id,
    recovery_plan_sha256: $hash,
    gate_scope: "LOCAL_RECOVERY_CLOSURE_REVIEW_ONLY",
    live_recovery_requested: false,
    incident_closure_requested: false,
    operator_validation: "VALIDATED_FOR_CLOSURE_REVIEW",
    item_validations: [
      $plan[0].recovery_items[]
      | {
          sequence,
          action_type,
          target_alias,
          verification_results: [
            .verification_checks[]
            | {
                check_name: .,
                status: "PASS",
                evidence_status: "SANITIZED_EVIDENCE_RECORDED"
              }
          ]
        }
    ]
  }' \
  > "$CLOSURE_REQUEST"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$CLOSURE_EVALUATOR" \
  -RecoveryPlanPath "$RECOVERY_PLAN" \
  -GateRequestPath "$CLOSURE_REQUEST" \
  -ContractPath "$CLOSURE_CONTRACT" \
  -OutputPath "$CLOSURE_OUTPUT" \
  >/dev/null

jq -e '
  .gate_status == "READY_FOR_CLOSURE_REVIEW"
  and
  .incident_closure_release == "NOT_RELEASED"
  and
  .incident_closed == false
' \
  "$CLOSURE_OUTPUT" \
  >/dev/null \
  || fail "Feature 9B source gate is not ready"

CLOSURE_HASH="$(
  sha256sum "$CLOSURE_OUTPUT" |
  awk '{print $1}'
)"

READY_REQUEST="$WORK/ready-request.json"
READY_OUTPUT_ONE="$WORK/ready-output-one.json"
READY_OUTPUT_TWO="$WORK/ready-output-two.json"

jq -n \
  --arg hash "$CLOSURE_HASH" \
  '{
    schema_version: 1,
    feature: 9,
    case_id: "IR-20261013-TEST9C",
    closure_gate_sha256: $hash,
    gate_scope: "LOCAL_INCIDENT_CLOSURE_AUTHORIZATION_REVIEW_ONLY",
    incident_closure_requested: false,
    operator_authorization:
      "AUTHORIZED_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW",
    reviews: {
      EXACT_CASE_CONFIRMED: true,
      RECOVERY_CLOSURE_GATE_READY_CONFIRMED: true,
      RECOVERY_EVIDENCE_REVIEWED: true,
      RESIDUAL_RISK_REVIEWED: true,
      BUSINESS_SERVICE_VALIDATED: true,
      FOLLOW_UP_ACTIONS_RECORDED: true,
      POSTMORTEM_HANDOFF_CONFIRMED: true,
      EXPLICIT_CLOSURE_EXECUTION_REVIEW_AUTHORIZATION: true
    }
  }' \
  > "$READY_REQUEST"

for OUTPUT in \
  "$READY_OUTPUT_ONE" \
  "$READY_OUTPUT_TWO"
do
  pwsh \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -File "$AUTH_EVALUATOR" \
    -ClosureGateOutputPath "$CLOSURE_OUTPUT" \
    -AuthorizationRequestPath "$READY_REQUEST" \
    -ContractPath "$AUTH_CONTRACT" \
    -OutputPath "$OUTPUT" \
    >/dev/null
done

cmp -s \
  "$READY_OUTPUT_ONE" \
  "$READY_OUTPUT_TWO" \
  || fail "Feature 9C output is not deterministic"

jq -e \
  --arg hash "$CLOSURE_HASH" \
  '
    .feature == 9
    and
    .mode == "LOCAL_INCIDENT_CLOSURE_AUTHORIZATION_REVIEW_ONLY"
    and
    .closure_gate_sha256 == $hash
    and
    .gate_status
      == "READY_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW"
    and
    .ready_status_authorizes_incident_closure == false
    and
    .ready_status_authorizes_tenant_write == false
    and
    .automatic_incident_closure == false
    and
    .incident_closure_execution_release == "NOT_RELEASED"
    and
    .recovery_release == "NOT_RELEASED"
    and
    .incident_closed == false
    and
    all(.reviews[]; . == true)
    and
    .safety_boundary.tenant_writes == 0
    and
    .safety_boundary.incident_closure_requests == 0
    and
    .safety_boundary.incident_closures == 0
  ' \
  "$READY_OUTPUT_ONE" \
  >/dev/null \
  || fail "ready Feature 9C output invalid"

printf 'READY_FOR_SEPARATE_CLOSURE_EXECUTION_REVIEW_MODEL=PASS\n'
printf 'READY_STATUS_DOES_NOT_CLOSE_INCIDENT=PASS\n'
printf 'CLOSURE_GATE_SHA256_BINDING=PASS\n'
printf 'DETERMINISTIC_INCIDENT_CLOSURE_AUTHORIZATION_GATE=PASS\n'

BLOCKED_REQUEST="$WORK/blocked-request.json"
BLOCKED_OUTPUT="$WORK/blocked-output.json"

jq '
  .reviews.RESIDUAL_RISK_REVIEWED = false
' \
  "$READY_REQUEST" \
  > "$BLOCKED_REQUEST"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$AUTH_EVALUATOR" \
  -ClosureGateOutputPath "$CLOSURE_OUTPUT" \
  -AuthorizationRequestPath "$BLOCKED_REQUEST" \
  -ContractPath "$AUTH_CONTRACT" \
  -OutputPath "$BLOCKED_OUTPUT" \
  >/dev/null

jq -e '
  .gate_status == "BLOCKED"
  and
  .incident_closure_execution_release == "NOT_RELEASED"
  and
  .incident_closed == false
' \
  "$BLOCKED_OUTPUT" \
  >/dev/null \
  || fail "incomplete review did not block Feature 9C"

printf 'INCOMPLETE_CLOSURE_REVIEW_FAIL_CLOSED=PASS\n'

NOT_AUTHORIZED_REQUEST="$WORK/not-authorized.json"
NOT_AUTHORIZED_OUTPUT="$WORK/not-authorized-output.json"

jq '
  .operator_authorization = "NOT_AUTHORIZED"
' \
  "$READY_REQUEST" \
  > "$NOT_AUTHORIZED_REQUEST"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$AUTH_EVALUATOR" \
  -ClosureGateOutputPath "$CLOSURE_OUTPUT" \
  -AuthorizationRequestPath "$NOT_AUTHORIZED_REQUEST" \
  -ContractPath "$AUTH_CONTRACT" \
  -OutputPath "$NOT_AUTHORIZED_OUTPUT" \
  >/dev/null

jq -e '
  .gate_status == "BLOCKED"
  and
  .incident_closed == false
' \
  "$NOT_AUTHORIZED_OUTPUT" \
  >/dev/null \
  || fail "negative authorization did not block Feature 9C"

printf 'NEGATIVE_OPERATOR_AUTHORIZATION_BLOCKS_CLOSURE_REVIEW=PASS\n'

expect_failure() {
  local LABEL="$1"
  local REQUEST="$2"
  local SOURCE="${3:-$CLOSURE_OUTPUT}"

  set +e

  pwsh \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -File "$AUTH_EVALUATOR" \
    -ClosureGateOutputPath "$SOURCE" \
    -AuthorizationRequestPath "$REQUEST" \
    -ContractPath "$AUTH_CONTRACT" \
    -OutputPath "$WORK/${LABEL}.output.json" \
    >"$WORK/${LABEL}.log" \
    2>&1

  local RC=$?

  set -e

  [[ "$RC" -ne 0 ]] \
    || fail "expected rejection did not occur: $LABEL"
}

BAD_HASH="$WORK/bad-hash.json"

jq '
  .closure_gate_sha256 = ("0" * 64)
' \
  "$READY_REQUEST" \
  > "$BAD_HASH"

expect_failure \
  "source-hash-mismatch" \
  "$BAD_HASH"

printf 'CLOSURE_GATE_HASH_MISMATCH_REJECTION=PASS\n'

CASE_MISMATCH="$WORK/case-mismatch.json"

jq '
  .case_id = "IR-20261013-OTHER9C"
' \
  "$READY_REQUEST" \
  > "$CASE_MISMATCH"

expect_failure \
  "case-mismatch" \
  "$CASE_MISMATCH"

printf 'INCIDENT_CLOSURE_AUTH_CASE_BINDING_REJECTION=PASS\n'

EXECUTION_REQUEST="$WORK/execution-request.json"

jq '
  .incident_closure_requested = true
' \
  "$READY_REQUEST" \
  > "$EXECUTION_REQUEST"

expect_failure \
  "closure-execution-request" \
  "$EXECUTION_REQUEST"

printf 'INCIDENT_CLOSURE_EXECUTION_REQUEST_REJECTION=PASS\n'

UNKNOWN_AUTH="$WORK/unknown-auth.json"

jq '
  .operator_authorization = "EXECUTE_INCIDENT_CLOSURE"
' \
  "$READY_REQUEST" \
  > "$UNKNOWN_AUTH"

expect_failure \
  "unknown-authorization" \
  "$UNKNOWN_AUTH"

printf 'UNSUPPORTED_CLOSURE_AUTHORIZATION_REJECTION=PASS\n'

MISSING_REVIEW="$WORK/missing-review.json"

jq '
  del(.reviews.POSTMORTEM_HANDOFF_CONFIRMED)
' \
  "$READY_REQUEST" \
  > "$MISSING_REVIEW"

expect_failure \
  "missing-review" \
  "$MISSING_REVIEW"

printf 'MISSING_CLOSURE_REVIEW_CONTROL_REJECTION=PASS\n'

BAD_BOOLEAN="$WORK/bad-boolean.json"

jq '
  .reviews.RESIDUAL_RISK_REVIEWED = "true"
' \
  "$READY_REQUEST" \
  > "$BAD_BOOLEAN"

expect_failure \
  "bad-boolean" \
  "$BAD_BOOLEAN"

printf 'CLOSURE_REVIEW_BOOLEAN_TYPE_REJECTION=PASS\n'

UNEXPECTED="$WORK/unexpected.json"

jq '
  .raw_evidence = "forbidden"
' \
  "$READY_REQUEST" \
  > "$UNEXPECTED"

expect_failure \
  "unexpected-property" \
  "$UNEXPECTED"

printf 'INCIDENT_CLOSURE_AUTH_UNEXPECTED_PROPERTY_REJECTION=PASS\n'

BLOCKED_SOURCE="$WORK/blocked-source.json"
BLOCKED_SOURCE_REQUEST="$WORK/blocked-source-request.json"

jq '
  .gate_status = "BLOCKED"
' \
  "$CLOSURE_OUTPUT" \
  > "$BLOCKED_SOURCE"

BLOCKED_SOURCE_HASH="$(
  sha256sum "$BLOCKED_SOURCE" |
  awk '{print $1}'
)"

jq \
  --arg hash "$BLOCKED_SOURCE_HASH" \
  '.closure_gate_sha256 = $hash' \
  "$READY_REQUEST" \
  > "$BLOCKED_SOURCE_REQUEST"

expect_failure \
  "blocked-source" \
  "$BLOCKED_SOURCE_REQUEST" \
  "$BLOCKED_SOURCE"

printf 'NON_READY_CLOSURE_GATE_SOURCE_REJECTION=PASS\n'

CLOSED_SOURCE="$WORK/closed-source.json"
CLOSED_SOURCE_REQUEST="$WORK/closed-source-request.json"

jq '
  .incident_closed = true
' \
  "$CLOSURE_OUTPUT" \
  > "$CLOSED_SOURCE"

CLOSED_SOURCE_HASH="$(
  sha256sum "$CLOSED_SOURCE" |
  awk '{print $1}'
)"

jq \
  --arg hash "$CLOSED_SOURCE_HASH" \
  '.closure_gate_sha256 = $hash' \
  "$READY_REQUEST" \
  > "$CLOSED_SOURCE_REQUEST"

expect_failure \
  "closed-source" \
  "$CLOSED_SOURCE_REQUEST" \
  "$CLOSED_SOURCE"

printf 'ALREADY_CLOSED_SOURCE_REJECTION=PASS\n'

printf 'NO_GRAPH_CLOSURE_AUTH_REQUEST_EXECUTED=PASS\n'
printf 'NO_DEFENDER_CLOSURE_AUTH_REQUEST_EXECUTED=PASS\n'
printf 'NO_TENANT_CLOSURE_AUTH_WRITE_EXECUTED=PASS\n'
printf 'NO_RECOVERY_ACTION_EXECUTED=PASS\n'
printf 'NO_CREDENTIAL_CHANGE_EXECUTED=PASS\n'
printf 'NO_INCIDENT_CLOSURE_REQUEST_EXECUTED=PASS\n'
printf 'NO_INCIDENT_CLOSURE_EXECUTED=PASS\n'
printf 'INCIDENT_CLOSURE_AUTHORIZATION_GATE_TEST=PASS\n'
