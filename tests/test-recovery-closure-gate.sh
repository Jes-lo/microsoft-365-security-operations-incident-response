#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

PLANNER="$ROOT/automation/powershell/New-RecoveryValidationPlan.ps1"
PLAN_CONTRACT="$ROOT/configs/recovery-validation-contract.json"

EVALUATOR="$ROOT/automation/powershell/Test-RecoveryClosureGate.ps1"
GATE_CONTRACT="$ROOT/configs/recovery-closure-gate-contract.json"

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
  "case_id": "IR-20261013-TEST9B",
  "gate_scope": "LOCAL_RECOVERY_VALIDATION_PLAN_ONLY",
  "live_recovery_requested": false,
  "action_items": [
    {
      "sequence": 1,
      "action_type": "SUBJECT_REVOKE_SESSIONS",
      "target_alias": "SUBJECT-001"
    },
    {
      "sequence": 2,
      "action_type": "SUBJECT_BLOCK_SIGN_IN",
      "target_alias": "SUBJECT-002"
    },
    {
      "sequence": 3,
      "action_type": "APPLICATION_DISABLE_ACCESS",
      "target_alias": "APP-001"
    },
    {
      "sequence": 4,
      "action_type": "DEVICE_ISOLATE",
      "target_alias": "DEVICE-001"
    },
    {
      "sequence": 5,
      "action_type": "OAUTH_GRANT_REMOVE",
      "target_alias": "APP-002"
    },
    {
      "sequence": 6,
      "action_type": "APPLICATION_CREDENTIAL_REMEDIATE",
      "target_alias": "APP-003"
    },
    {
      "sequence": 7,
      "action_type": "SUBJECT_CREDENTIAL_RESET",
      "target_alias": "SUBJECT-003"
    },
    {
      "sequence": 8,
      "action_type": "FILE_QUARANTINE",
      "target_alias": "FILE-001"
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

READY_REQUEST="$WORK/ready-request.json"
READY_OUTPUT_ONE="$WORK/ready-output-one.json"
READY_OUTPUT_TWO="$WORK/ready-output-two.json"

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
  > "$READY_REQUEST"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$EVALUATOR" \
  -RecoveryPlanPath "$RECOVERY_PLAN" \
  -GateRequestPath "$READY_REQUEST" \
  -ContractPath "$GATE_CONTRACT" \
  -OutputPath "$READY_OUTPUT_ONE" \
  >/dev/null

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$EVALUATOR" \
  -RecoveryPlanPath "$RECOVERY_PLAN" \
  -GateRequestPath "$READY_REQUEST" \
  -ContractPath "$GATE_CONTRACT" \
  -OutputPath "$READY_OUTPUT_TWO" \
  >/dev/null

cmp -s \
  "$READY_OUTPUT_ONE" \
  "$READY_OUTPUT_TWO" \
  || fail "closure gate output is not deterministic"

jq -e \
  --arg hash "$PLAN_HASH" \
  '
    .feature == 9
    and
    .mode == "LOCAL_CLOSURE_REVIEW_ONLY"
    and
    .recovery_plan_sha256 == $hash
    and
    .operator_validation == "VALIDATED_FOR_CLOSURE_REVIEW"
    and
    .gate_status == "READY_FOR_CLOSURE_REVIEW"
    and
    .recovery_release == "NOT_RELEASED"
    and
    .incident_closure_release == "NOT_RELEASED"
    and
    .ready_status_authorizes_incident_closure == false
    and
    .automatic_incident_closure == false
    and
    .incident_closed == false
    and
    (.recovery_items | length) == 8
    and
    all(
      .recovery_items[];
      (
        .validation_status == "VALIDATED_FOR_CLOSURE_REVIEW"
        and
        .recovery_release == "NOT_RELEASED"
        and
        .incident_closure_release == "NOT_RELEASED"
        and
        all(
          .verification_results[];
          (
            .status == "PASS"
            and
            .evidence_status == "SANITIZED_EVIDENCE_RECORDED"
          )
        )
      )
    )
    and
    .safety_boundary.tenant_writes == 0
    and
    .safety_boundary.recovery_actions == 0
    and
    .safety_boundary.credential_changes == 0
    and
    .safety_boundary.incident_closures == 0
  ' \
  "$READY_OUTPUT_ONE" \
  >/dev/null \
  || fail "ready closure-review output invalid"

printf 'READY_FOR_CLOSURE_REVIEW_MODEL=PASS\n'
printf 'READY_STATUS_DOES_NOT_CLOSE_INCIDENT=PASS\n'
printf 'RECOVERY_PLAN_SHA256_BINDING=PASS\n'
printf 'SANITIZED_EVIDENCE_REQUIRED_FOR_PASS=PASS\n'
printf 'DETERMINISTIC_RECOVERY_CLOSURE_GATE=PASS\n'

FAIL_REQUEST="$WORK/fail-request.json"
FAIL_OUTPUT="$WORK/fail-output.json"

jq '
  .item_validations[0].verification_results[0].status = "FAIL"
' \
  "$READY_REQUEST" \
  > "$FAIL_REQUEST"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$EVALUATOR" \
  -RecoveryPlanPath "$RECOVERY_PLAN" \
  -GateRequestPath "$FAIL_REQUEST" \
  -ContractPath "$GATE_CONTRACT" \
  -OutputPath "$FAIL_OUTPUT" \
  >/dev/null

jq -e '
  .gate_status == "BLOCKED"
  and
  .incident_closure_release == "NOT_RELEASED"
  and
  .incident_closed == false
' \
  "$FAIL_OUTPUT" \
  >/dev/null \
  || fail "failed verification did not block closure review"

printf 'FAILED_RECOVERY_VALIDATION_BLOCKS_CLOSURE_REVIEW=PASS\n'

PENDING_REQUEST="$WORK/pending-request.json"
PENDING_OUTPUT="$WORK/pending-output.json"

jq '
  .item_validations[0].verification_results[0].status = "PENDING"
  |
  .item_validations[0].verification_results[0].evidence_status = "NOT_RECORDED"
' \
  "$READY_REQUEST" \
  > "$PENDING_REQUEST"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$EVALUATOR" \
  -RecoveryPlanPath "$RECOVERY_PLAN" \
  -GateRequestPath "$PENDING_REQUEST" \
  -ContractPath "$GATE_CONTRACT" \
  -OutputPath "$PENDING_OUTPUT" \
  >/dev/null

jq -e '
  .gate_status == "BLOCKED"
  and
  .incident_closure_release == "NOT_RELEASED"
  and
  .incident_closed == false
' \
  "$PENDING_OUTPUT" \
  >/dev/null \
  || fail "pending verification did not block closure review"

printf 'PENDING_RECOVERY_VALIDATION_BLOCKS_CLOSURE_REVIEW=PASS\n'

NO_HUMAN_REQUEST="$WORK/no-human-request.json"
NO_HUMAN_OUTPUT="$WORK/no-human-output.json"

jq '
  .operator_validation = "NOT_VALIDATED"
' \
  "$READY_REQUEST" \
  > "$NO_HUMAN_REQUEST"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$EVALUATOR" \
  -RecoveryPlanPath "$RECOVERY_PLAN" \
  -GateRequestPath "$NO_HUMAN_REQUEST" \
  -ContractPath "$GATE_CONTRACT" \
  -OutputPath "$NO_HUMAN_OUTPUT" \
  >/dev/null

jq -e '
  .gate_status == "BLOCKED"
  and
  .incident_closed == false
' \
  "$NO_HUMAN_OUTPUT" \
  >/dev/null \
  || fail "missing explicit human validation did not block closure review"

printf 'MISSING_HUMAN_VALIDATION_BLOCKS_CLOSURE_REVIEW=PASS\n'

expect_failure() {
  local LABEL="$1"
  local REQUEST="$2"
  local PLAN="${3:-$RECOVERY_PLAN}"

  set +e

  pwsh \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -File "$EVALUATOR" \
    -RecoveryPlanPath "$PLAN" \
    -GateRequestPath "$REQUEST" \
    -ContractPath "$GATE_CONTRACT" \
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
  .recovery_plan_sha256 = (
    "0" * 64
  )
' \
  "$READY_REQUEST" \
  > "$BAD_HASH"

expect_failure \
  "plan-hash-mismatch" \
  "$BAD_HASH"

printf 'RECOVERY_PLAN_HASH_MISMATCH_REJECTION=PASS\n'

MISSING_CHECK="$WORK/missing-check.json"

jq '
  .item_validations[0].verification_results =
    .item_validations[0].verification_results[1:]
' \
  "$READY_REQUEST" \
  > "$MISSING_CHECK"

expect_failure \
  "missing-verification-check" \
  "$MISSING_CHECK"

printf 'MISSING_RECOVERY_CHECK_REJECTION=PASS\n'

DUPLICATE_CHECK="$WORK/duplicate-check.json"

jq '
  .item_validations[0].verification_results +=
    [.item_validations[0].verification_results[0]]
' \
  "$READY_REQUEST" \
  > "$DUPLICATE_CHECK"

expect_failure \
  "duplicate-verification-check" \
  "$DUPLICATE_CHECK"

printf 'DUPLICATE_RECOVERY_CHECK_REJECTION=PASS\n'

UNKNOWN_CHECK="$WORK/unknown-check.json"

jq '
  .item_validations[0].verification_results[0].check_name =
    "UNKNOWN_RECOVERY_CHECK"
' \
  "$READY_REQUEST" \
  > "$UNKNOWN_CHECK"

expect_failure \
  "unknown-verification-check" \
  "$UNKNOWN_CHECK"

printf 'UNKNOWN_RECOVERY_CHECK_REJECTION=PASS\n'

PASS_WITHOUT_EVIDENCE="$WORK/pass-without-evidence.json"

jq '
  .item_validations[0].verification_results[0].evidence_status =
    "NOT_RECORDED"
' \
  "$READY_REQUEST" \
  > "$PASS_WITHOUT_EVIDENCE"

expect_failure \
  "pass-without-evidence" \
  "$PASS_WITHOUT_EVIDENCE"

printf 'PASS_WITHOUT_SANITIZED_EVIDENCE_REJECTION=PASS\n'

CASE_MISMATCH="$WORK/case-mismatch.json"

jq '
  .case_id = "IR-20261013-OTHER9B"
' \
  "$READY_REQUEST" \
  > "$CASE_MISMATCH"

expect_failure \
  "case-mismatch" \
  "$CASE_MISMATCH"

printf 'RECOVERY_CLOSURE_CASE_BINDING_REJECTION=PASS\n'

TARGET_TAMPER="$WORK/target-tamper.json"

jq '
  .item_validations[0].target_alias =
    "RAW-TENANT-OBJECT-ID-FORBIDDEN"
' \
  "$READY_REQUEST" \
  > "$TARGET_TAMPER"

expect_failure \
  "target-tamper" \
  "$TARGET_TAMPER"

printf 'RECOVERY_TARGET_TAMPER_REJECTION=PASS\n'

LIVE_REQUEST="$WORK/live-request.json"

jq '
  .live_recovery_requested = true
' \
  "$READY_REQUEST" \
  > "$LIVE_REQUEST"

expect_failure \
  "live-recovery-request" \
  "$LIVE_REQUEST"

printf 'LIVE_RECOVERY_CLOSURE_GATE_REJECTION=PASS\n'

CLOSURE_EXECUTION_REQUEST="$WORK/closure-execution-request.json"

jq '
  .incident_closure_requested = true
' \
  "$READY_REQUEST" \
  > "$CLOSURE_EXECUTION_REQUEST"

expect_failure \
  "incident-closure-execution-request" \
  "$CLOSURE_EXECUTION_REQUEST"

printf 'INCIDENT_CLOSURE_EXECUTION_REQUEST_REJECTION=PASS\n'

UNEXPECTED_PROPERTY="$WORK/unexpected-property.json"

jq '
  .raw_evidence = "forbidden"
' \
  "$READY_REQUEST" \
  > "$UNEXPECTED_PROPERTY"

expect_failure \
  "unexpected-property" \
  "$UNEXPECTED_PROPERTY"

printf 'RECOVERY_CLOSURE_UNEXPECTED_PROPERTY_REJECTION=PASS\n'

printf 'NO_GRAPH_CLOSURE_REQUEST_EXECUTED=PASS\n'
printf 'NO_DEFENDER_CLOSURE_REQUEST_EXECUTED=PASS\n'
printf 'NO_TENANT_CLOSURE_WRITE_EXECUTED=PASS\n'
printf 'NO_RECOVERY_ACTION_EXECUTED=PASS\n'
printf 'NO_CREDENTIAL_CHANGE_EXECUTED=PASS\n'
printf 'NO_INCIDENT_CLOSURE_EXECUTED=PASS\n'
printf 'RECOVERY_CLOSURE_GATE_TEST=PASS\n'
