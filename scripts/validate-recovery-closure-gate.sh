#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/recovery-closure-gate-contract.json"
F9A="$ROOT/configs/recovery-validation-contract.json"
PROJECT_SCOPE="$ROOT/configs/project-scope.json"
EVALUATOR="$ROOT/automation/powershell/Test-RecoveryClosureGate.ps1"
ARCHITECTURE="$ROOT/docs/architecture/RECOVERY-CLOSURE-GATE.md"
ADR="$ROOT/docs/decisions/ADR-016-recovery-closure-review-before-incident-closure.md"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

for FILE in \
  "$CONTRACT" \
  "$F9A" \
  "$PROJECT_SCOPE" \
  "$EVALUATOR" \
  "$ARCHITECTURE" \
  "$ADR"
do
  [[ -f "$FILE" ]] \
    || fail "required Feature 9B file missing"
done

jq -e . "$CONTRACT" >/dev/null \
  || fail "Feature 9B contract JSON invalid"

jq -e '
  .schema_version == 1
  and
  .feature == 9
  and
  .phase == "RECOVERY_VALIDATION_SCENARIOS_CLOSURE_GATE_COMPLETE"
  and
  .validation_state == "RECOVERY_VALIDATION_SCENARIOS_CLOSURE_GATE_COMPLETE"
  and
  .mode == "LOCAL_CLOSURE_REVIEW_ONLY"
  and
  .plan_binding.algorithm == "SHA256"
  and
  .plan_binding.exact_plan_hash_required == true
  and
  .plan_binding.stale_or_modified_plan_rejected == true
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 9B metadata or plan binding invalid"

jq -e '
  .scenario_model.verification_statuses
    == ["PASS", "FAIL", "PENDING"]
  and
  .scenario_model.evidence_statuses
    == [
      "SANITIZED_EVIDENCE_RECORDED",
      "NOT_RECORDED"
    ]
  and
  .scenario_model.pass_requires_sanitized_evidence == true
  and
  .scenario_model.fail_blocks_closure_review == true
  and
  .scenario_model.pending_blocks_closure_review == true
  and
  .scenario_model.missing_check_rejected == true
  and
  .scenario_model.duplicate_check_rejected == true
  and
  .scenario_model.unknown_check_rejected == true
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 9B scenario model invalid"

jq -e '
  .operator_validation.ready_value
    == "VALIDATED_FOR_CLOSURE_REVIEW"
  and
  (.operator_validation.allowed_values | length) == 2
  and
  .operator_validation.authorizes_incident_closure == false
  and
  .operator_validation.authorizes_recovery_execution == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 9B human validation boundary invalid"

jq -e '
  .decision_model.ready_status == "READY_FOR_CLOSURE_REVIEW"
  and
  .decision_model.blocked_status == "BLOCKED"
  and
  .decision_model.all_recovery_items_must_validate == true
  and
  .decision_model.all_verification_checks_must_pass == true
  and
  .decision_model.all_passed_checks_require_sanitized_evidence == true
  and
  .decision_model.explicit_human_validation_required == true
  and
  .decision_model.ready_status_authorizes_incident_closure == false
  and
  .decision_model.automatic_incident_closure == false
  and
  .decision_model.incident_closure_release == "NOT_RELEASED"
  and
  .decision_model.recovery_release == "NOT_RELEASED"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 9B decision model invalid"

jq -e '
  .safety_boundary.graph_authentication == "NOT_PERFORMED"
  and
  .safety_boundary.graph_requests == 0
  and
  .safety_boundary.defender_api_authentication == "NOT_PERFORMED"
  and
  .safety_boundary.defender_api_requests == 0
  and
  .safety_boundary.tenant_reads == 0
  and
  .safety_boundary.tenant_writes == 0
  and
  .safety_boundary.endpoint_actions == 0
  and
  .safety_boundary.response_actions == 0
  and
  .safety_boundary.recovery_actions == 0
  and
  .safety_boundary.credential_changes == 0
  and
  .safety_boundary.permission_grants == 0
  and
  .safety_boundary.role_assignments == 0
  and
  .safety_boundary.admin_consents == 0
  and
  .safety_boundary.incident_closure_requests == 0
  and
  .safety_boundary.incident_closures == 0
  and
  .safety_boundary.live_recovery_release == false
  and
  .safety_boundary.incident_closure_release == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 9B safety boundary invalid"

jq -e '
  .feature == 9
  and
  .phase == "RECOVERY_VALIDATION_FOUNDATION_COMPLETE"
  and
  .execution.recovery_release == "NOT_RELEASED"
  and
  .closure_requirements.automatic_closure == false
' \
  "$F9A" \
  >/dev/null \
  || fail "Feature 9A foundation dependency invalid"

[[ "$(
  jq -r '.current_feature' "$PROJECT_SCOPE"
)" == "9" ]] \
  || fail "project current feature must remain 9"

[[ "$(
  jq -r '.current_state' "$PROJECT_SCOPE"
)" == "recovery-validation-scenarios-closure-gate-complete" ]] \
  || fail "unexpected Feature 9B project state"

grep -Fq \
  'Every closure-gate request must contain the SHA-256 digest' \
  "$ARCHITECTURE" \
  || fail "Feature 9B SHA binding documentation missing"

grep -Fq \
  'That state does not authorize or execute incident closure.' \
  "$ADR" \
  || fail "ADR-016 closure boundary missing"

printf 'RECOVERY_CLOSURE_GATE_VALIDATION=PASS\n'
printf 'FEATURE_9B_PLAN_SHA256_BINDING=REQUIRED\n'
printf 'FEATURE_9B_SCENARIO_STATUSES=PASS_FAIL_PENDING\n'
printf 'FEATURE_9B_SANITIZED_EVIDENCE_REQUIRED_FOR_PASS=YES\n'
printf 'FEATURE_9B_EXPLICIT_HUMAN_VALIDATION_REQUIRED=YES\n'
printf 'FEATURE_9B_READY_STATUS_AUTHORIZES_CLOSURE=NO\n'
printf 'FEATURE_9B_AUTOMATIC_INCIDENT_CLOSURE=NO\n'
printf 'FEATURE_9B_RECOVERY_ACTIONS=0\n'
printf 'FEATURE_9B_TENANT_WRITES=0\n'
printf 'FEATURE_9B_INCIDENT_CLOSURES=0\n'
printf 'FEATURE_9B_RECOVERY_RELEASE=NOT_RELEASED\n'
printf 'FEATURE_9B_INCIDENT_CLOSURE_RELEASE=NOT_RELEASED\n'
