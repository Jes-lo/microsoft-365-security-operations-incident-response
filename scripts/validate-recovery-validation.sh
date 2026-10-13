#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/recovery-validation-contract.json"
F8="$ROOT/configs/containment-eradication-contract.json"
PROJECT_SCOPE="$ROOT/configs/project-scope.json"
PLANNER="$ROOT/automation/powershell/New-RecoveryValidationPlan.ps1"
ARCHITECTURE="$ROOT/docs/architecture/RECOVERY-VALIDATION.md"
ADR="$ROOT/docs/decisions/ADR-015-recovery-validation-before-incident-closure.md"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

for FILE in \
  "$CONTRACT" \
  "$F8" \
  "$PROJECT_SCOPE" \
  "$PLANNER" \
  "$ARCHITECTURE" \
  "$ADR"
do
  [[ -f "$FILE" ]] \
    || fail "required Feature 9A file missing"
done

jq -e . "$CONTRACT" >/dev/null \
  || fail "Feature 9A contract JSON invalid"

jq -e '
  .schema_version == 1
  and
  .feature == 9
  and
  .phase == "RECOVERY_VALIDATION_FOUNDATION_COMPLETE"
  and
  .validation_state == "RECOVERY_VALIDATION_FOUNDATION_COMPLETE"
  and
  .mode == "LOCAL_VALIDATION_PLAN_ONLY"
  and
  .execution.live_recovery_allowed == false
  and
  .execution.automatic_rollback_allowed == false
  and
  .execution.automatic_incident_closure_allowed == false
  and
  .execution.recovery_release == "NOT_RELEASED"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 9A execution boundary invalid"

jq -e '
  .closure_requirements.all_recovery_items_require_validation == true
  and
  .closure_requirements.verification_evidence_required == true
  and
  .closure_requirements.explicit_human_validation_required == true
  and
  .closure_requirements.unresolved_item_blocks_closure == true
  and
  .closure_requirements.failed_validation_blocks_closure == true
  and
  .closure_requirements.automatic_closure == false
  and
  .closure_requirements.closure_status_before_validation
    == "NOT_READY_FOR_CLOSURE"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 9A closure boundary invalid"

EXPECTED_ACTIONS="$(
  jq -c -S '
    [.action_catalog[].action_type]
    | sort
  ' \
    "$F8"
)"

RECOVERY_ACTIONS="$(
  jq -c -S '
    [.recovery_profiles[].action_type]
    | sort
  ' \
    "$CONTRACT"
)"

[[ "$EXPECTED_ACTIONS" == "$RECOVERY_ACTIONS" ]] \
  || fail "Feature 9A recovery coverage differs from Feature 8 action catalog"

[[ "$(
  jq '.recovery_profiles | length' "$CONTRACT"
)" == "8" ]] \
  || fail "Feature 9A must cover exactly eight recovery profiles"

[[ "$(
  jq '[.recovery_profiles[].action_type] | unique | length' "$CONTRACT"
)" == "8" ]] \
  || fail "Feature 9A recovery action types must be unique"

jq -e '
  all(
    .recovery_profiles[];
    (
      .restore_previous_state_automatically == false
      and
      (.verification_checks | length) >= 3
    )
  )
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "automatic recovery or insufficient validation checks detected"

jq -e '
  (
    .recovery_profiles[]
    | select(.action_type == "OAUTH_GRANT_REMOVE")
    | .recovery_strategy
  ) == "REAPPROVAL_REQUIRED"
  and
  (
    .recovery_profiles[]
    | select(.action_type == "APPLICATION_CREDENTIAL_REMEDIATE")
    | .recovery_strategy
  ) == "REPLACEMENT_CREDENTIAL_ONLY"
  and
  (
    .recovery_profiles[]
    | select(.action_type == "SUBJECT_CREDENTIAL_RESET")
    | .recovery_strategy
  ) == "NEW_CREDENTIAL_REESTABLISHMENT"
  and
  (
    .recovery_profiles[]
    | select(.action_type == "FILE_QUARANTINE")
    | .recovery_strategy
  ) == "BENIGN_RECLASSIFICATION_REQUIRED"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "sensitive recovery semantics invalid"

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
  .safety_boundary.permission_grants == 0
  and
  .safety_boundary.role_assignments == 0
  and
  .safety_boundary.admin_consents == 0
  and
  .safety_boundary.credential_changes == 0
  and
  .safety_boundary.incident_closures == 0
  and
  .safety_boundary.live_recovery_release == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 9A safety boundary invalid"
CURRENT_FEATURE="$(
  jq -r '.current_feature' "$PROJECT_SCOPE"
)"

case "$CURRENT_FEATURE" in
  9|10)
    ;;
  *)
    fail "unexpected project current feature for Feature 9 history"
    ;;
esac

CURRENT_STATE="$(
  jq -r '.current_state' "$PROJECT_SCOPE"
)"
case "$CURRENT_STATE" in
  recovery-validation-foundation-complete|\
recovery-validation-scenarios-closure-gate-complete|\
incident-closure-authorization-gate-complete|\
postmortem-local-case-closure-foundation-complete)
    ;;
  *)
    fail "unexpected Feature 9A/10A project state"
    ;;
esac
grep -Fq \
  'Recovery does not mean blindly undoing' \
  "$ARCHITECTURE" \
  || fail "recovery architecture boundary missing"

grep -Fq \
  'Feature 9A does not authorize live recovery' \
  "$ADR" \
  || fail "ADR-015 live recovery boundary missing"

printf 'RECOVERY_VALIDATION_FOUNDATION_VALIDATION=PASS\n'
printf 'FEATURE_9A_ACTION_COVERAGE=8_OF_8\n'
printf 'FEATURE_9A_AUTOMATIC_RESTORE=NO\n'
printf 'FEATURE_9A_AUTOMATIC_INCIDENT_CLOSURE=NO\n'
printf 'FEATURE_9A_LIVE_RECOVERY=NO\n'
printf 'FEATURE_9A_RECOVERY_ACTIONS=0\n'
printf 'FEATURE_9A_TENANT_WRITES=0\n'
printf 'FEATURE_9A_RECOVERY_RELEASE=NOT_RELEASED\n'
