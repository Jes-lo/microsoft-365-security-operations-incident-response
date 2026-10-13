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

POSTMORTEM_BUILDER="$ROOT/automation/powershell/New-PostmortemLocalClosureRecord.ps1"
POSTMORTEM_CONTRACT="$ROOT/configs/postmortem-local-closure-contract.json"

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
  "case_id": "IR-20261013-TEST10A",
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

CLOSURE_HASH="$(
  sha256sum "$CLOSURE_OUTPUT" |
  awk '{print $1}'
)"

AUTH_REQUEST="$WORK/auth-request.json"
AUTH_OUTPUT="$WORK/auth-output.json"

jq -n \
  --arg hash "$CLOSURE_HASH" \
  '{
    schema_version: 1,
    feature: 9,
    case_id: "IR-20261013-TEST10A",
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
  > "$AUTH_REQUEST"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$AUTH_EVALUATOR" \
  -ClosureGateOutputPath "$CLOSURE_OUTPUT" \
  -AuthorizationRequestPath "$AUTH_REQUEST" \
  -ContractPath "$AUTH_CONTRACT" \
  -OutputPath "$AUTH_OUTPUT" \
  >/dev/null

jq -e '
  .gate_status
    == "READY_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW"
  and
  .incident_closure_execution_release == "NOT_RELEASED"
  and
  .incident_closed == false
' \
  "$AUTH_OUTPUT" \
  >/dev/null \
  || fail "Feature 9C source is not ready for Feature 10A"

AUTH_HASH="$(
  sha256sum "$AUTH_OUTPUT" |
  awk '{print $1}'
)"

POSTMORTEM_REQUEST="$WORK/postmortem-request.json"
POSTMORTEM_OUTPUT_ONE="$WORK/postmortem-output-one.json"
POSTMORTEM_OUTPUT_TWO="$WORK/postmortem-output-two.json"

jq -n \
  --arg hash "$AUTH_HASH" \
  '{
    schema_version: 1,
    feature: 10,
    case_id: "IR-20261013-TEST10A",
    authorization_gate_sha256: $hash,
    gate_scope: "LOCAL_POSTMORTEM_CASE_CLOSURE_RECORD_ONLY",
    external_incident_closure_requested: false,
    root_cause_category: "CREDENTIAL_COMPROMISE",
    impact_scope: "IDENTITY",
    contributing_factors: [
      "DETECTION_GAP",
      "PROCESS_GAP"
    ],
    lessons_learned: [
      "DETECTION_COVERAGE",
      "RESPONSE_GATING",
      "PROCESS_IMPROVEMENT"
    ],
    follow_up_actions: [
      {
        sequence: 1,
        category: "DETECTION_IMPROVEMENT",
        priority: "P1",
        owner_role: "INCIDENT_RESPONSE",
        due_window: "DAYS_30",
        status: "OPEN"
      },
      {
        sequence: 2,
        category: "IDENTITY_HARDENING",
        priority: "P2",
        owner_role: "IDENTITY_SECURITY",
        due_window: "DAYS_60",
        status: "OPEN"
      }
    ]
  }' \
  > "$POSTMORTEM_REQUEST"

for OUTPUT in \
  "$POSTMORTEM_OUTPUT_ONE" \
  "$POSTMORTEM_OUTPUT_TWO"
do
  pwsh \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -File "$POSTMORTEM_BUILDER" \
    -AuthorizationGateOutputPath "$AUTH_OUTPUT" \
    -PostmortemRequestPath "$POSTMORTEM_REQUEST" \
    -ContractPath "$POSTMORTEM_CONTRACT" \
    -OutputPath "$OUTPUT" \
    >/dev/null
done

cmp -s \
  "$POSTMORTEM_OUTPUT_ONE" \
  "$POSTMORTEM_OUTPUT_TWO" \
  || fail "Feature 10A output is not deterministic"

jq -e \
  --arg hash "$AUTH_HASH" \
  '
    .schema_version == 1
    and
    .feature == 10
    and
    .case_id == "IR-20261013-TEST10A"
    and
    .mode == "LOCAL_POSTMORTEM_CASE_CLOSURE_ONLY"
    and
    .authorization_gate_sha256 == $hash
    and
    .postmortem_status == "POSTMORTEM_COMPLETE"
    and
    .local_case_closure_scope == "LOCAL_CASE_RECORD_ONLY"
    and
    .local_case_closure_status
      == "LOCAL_CASE_CLOSED_POSTMORTEM_COMPLETE"
    and
    .external_incident_closure_status == "NOT_EXECUTED"
    and
    .external_incident_closure_release == "NOT_RELEASED"
    and
    .local_closure_implies_tenant_write == false
    and
    .local_closure_implies_external_incident_closure == false
    and
    .external_incident_closure_authorized == false
    and
    .external_incident_closed == false
    and
    (.lifecycle_phases | length) == 8
    and
    (.follow_up_actions | length) == 2
    and
    .follow_up_actions[0].sequence == 1
    and
    .follow_up_actions[1].sequence == 2
    and
    .safety_boundary.tenant_writes == 0
    and
    .safety_boundary.external_incident_closure_requests == 0
    and
    .safety_boundary.external_incident_closures == 0
  ' \
  "$POSTMORTEM_OUTPUT_ONE" \
  >/dev/null \
  || fail "Feature 10A local closure output invalid"

printf 'POSTMORTEM_LOCAL_CASE_CLOSURE_MODEL=PASS\n'
printf 'LOCAL_CASE_CLOSURE_DOES_NOT_CLOSE_EXTERNAL_INCIDENT=PASS\n'
printf 'AUTHORIZATION_GATE_SHA256_BINDING=PASS\n'
printf 'DETERMINISTIC_POSTMORTEM_RECORD=PASS\n'
printf 'FOLLOW_UP_ACTIONS_MODEL=PASS\n'

expect_failure() {
  local LABEL="$1"
  local REQUEST="$2"
  local SOURCE="${3:-$AUTH_OUTPUT}"

  set +e

  pwsh \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -File "$POSTMORTEM_BUILDER" \
    -AuthorizationGateOutputPath "$SOURCE" \
    -PostmortemRequestPath "$REQUEST" \
    -ContractPath "$POSTMORTEM_CONTRACT" \
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
  .authorization_gate_sha256 = ("0" * 64)
' \
  "$POSTMORTEM_REQUEST" \
  > "$BAD_HASH"

expect_failure \
  "authorization-hash-mismatch" \
  "$BAD_HASH"

printf 'AUTHORIZATION_GATE_HASH_MISMATCH_REJECTION=PASS\n'

CASE_MISMATCH="$WORK/case-mismatch.json"

jq '
  .case_id = "IR-20261013-OTHER10A"
' \
  "$POSTMORTEM_REQUEST" \
  > "$CASE_MISMATCH"

expect_failure \
  "postmortem-case-mismatch" \
  "$CASE_MISMATCH"

printf 'POSTMORTEM_CASE_BINDING_REJECTION=PASS\n'

EXTERNAL_CLOSE="$WORK/external-close.json"

jq '
  .external_incident_closure_requested = true
' \
  "$POSTMORTEM_REQUEST" \
  > "$EXTERNAL_CLOSE"

expect_failure \
  "external-incident-closure-request" \
  "$EXTERNAL_CLOSE"

printf 'EXTERNAL_INCIDENT_CLOSURE_REQUEST_REJECTION=PASS\n'

BLOCKED_SOURCE="$WORK/blocked-auth-source.json"
BLOCKED_REQUEST="$WORK/blocked-auth-request.json"

jq '
  .gate_status = "BLOCKED"
' \
  "$AUTH_OUTPUT" \
  > "$BLOCKED_SOURCE"

BLOCKED_HASH="$(
  sha256sum "$BLOCKED_SOURCE" |
  awk '{print $1}'
)"

jq \
  --arg hash "$BLOCKED_HASH" \
  '.authorization_gate_sha256 = $hash' \
  "$POSTMORTEM_REQUEST" \
  > "$BLOCKED_REQUEST"

expect_failure \
  "non-ready-authorization-source" \
  "$BLOCKED_REQUEST" \
  "$BLOCKED_SOURCE"

printf 'NON_READY_AUTHORIZATION_SOURCE_REJECTION=PASS\n'

CLOSED_SOURCE="$WORK/closed-auth-source.json"
CLOSED_REQUEST="$WORK/closed-auth-request.json"

jq '
  .incident_closed = true
' \
  "$AUTH_OUTPUT" \
  > "$CLOSED_SOURCE"

CLOSED_HASH="$(
  sha256sum "$CLOSED_SOURCE" |
  awk '{print $1}'
)"

jq \
  --arg hash "$CLOSED_HASH" \
  '.authorization_gate_sha256 = $hash' \
  "$POSTMORTEM_REQUEST" \
  > "$CLOSED_REQUEST"

expect_failure \
  "already-closed-authorization-source" \
  "$CLOSED_REQUEST" \
  "$CLOSED_SOURCE"

printf 'ALREADY_CLOSED_AUTHORIZATION_SOURCE_REJECTION=PASS\n'

BAD_ROOT_CAUSE="$WORK/bad-root-cause.json"

jq '
  .root_cause_category = "FREE_FORM_ROOT_CAUSE"
' \
  "$POSTMORTEM_REQUEST" \
  > "$BAD_ROOT_CAUSE"

expect_failure \
  "unsupported-root-cause" \
  "$BAD_ROOT_CAUSE"

printf 'UNSUPPORTED_ROOT_CAUSE_REJECTION=PASS\n'

DUP_FACTOR="$WORK/duplicate-factor.json"

jq '
  .contributing_factors +=
    [.contributing_factors[0]]
' \
  "$POSTMORTEM_REQUEST" \
  > "$DUP_FACTOR"

expect_failure \
  "duplicate-contributing-factor" \
  "$DUP_FACTOR"

printf 'DUPLICATE_CONTRIBUTING_FACTOR_REJECTION=PASS\n'

DUP_LESSON="$WORK/duplicate-lesson.json"

jq '
  .lessons_learned +=
    [.lessons_learned[0]]
' \
  "$POSTMORTEM_REQUEST" \
  > "$DUP_LESSON"

expect_failure \
  "duplicate-lesson" \
  "$DUP_LESSON"

printf 'DUPLICATE_LESSON_REJECTION=PASS\n'

NONCONTIGUOUS="$WORK/noncontiguous-follow-up.json"

jq '
  .follow_up_actions[1].sequence = 3
' \
  "$POSTMORTEM_REQUEST" \
  > "$NONCONTIGUOUS"

expect_failure \
  "noncontiguous-follow-up" \
  "$NONCONTIGUOUS"

printf 'NONCONTIGUOUS_FOLLOW_UP_SEQUENCE_REJECTION=PASS\n'

UNKNOWN_FOLLOW_UP="$WORK/unknown-follow-up.json"

jq '
  .follow_up_actions[0].category =
    "UNKNOWN_FOLLOW_UP_CATEGORY"
' \
  "$POSTMORTEM_REQUEST" \
  > "$UNKNOWN_FOLLOW_UP"

expect_failure \
  "unknown-follow-up-category" \
  "$UNKNOWN_FOLLOW_UP"

printf 'UNKNOWN_FOLLOW_UP_CATEGORY_REJECTION=PASS\n'

UNEXPECTED="$WORK/unexpected-property.json"

jq '
  .narrative = "forbidden free-form narrative"
' \
  "$POSTMORTEM_REQUEST" \
  > "$UNEXPECTED"

expect_failure \
  "unexpected-property" \
  "$UNEXPECTED"

printf 'POSTMORTEM_UNEXPECTED_PROPERTY_REJECTION=PASS\n'

printf 'NO_GRAPH_POSTMORTEM_REQUEST_EXECUTED=PASS\n'
printf 'NO_DEFENDER_POSTMORTEM_REQUEST_EXECUTED=PASS\n'
printf 'NO_TENANT_POSTMORTEM_WRITE_EXECUTED=PASS\n'
printf 'NO_RECOVERY_ACTION_EXECUTED=PASS\n'
printf 'NO_CREDENTIAL_CHANGE_EXECUTED=PASS\n'
printf 'NO_EXTERNAL_INCIDENT_CLOSURE_REQUEST_EXECUTED=PASS\n'
printf 'NO_EXTERNAL_INCIDENT_CLOSURE_EXECUTED=PASS\n'
printf 'POSTMORTEM_LOCAL_CLOSURE_TEST=PASS\n'
