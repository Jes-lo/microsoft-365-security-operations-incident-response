#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/incident-closure-authorization-gate-contract.json"
PROJECT_SCOPE="$ROOT/configs/project-scope.json"
EVALUATOR="$ROOT/automation/powershell/Test-IncidentClosureAuthorizationGate.ps1"
ARCHITECTURE="$ROOT/docs/architecture/INCIDENT-CLOSURE-AUTHORIZATION-GATE.md"
ADR="$ROOT/docs/decisions/ADR-017-explicit-incident-closure-authorization-gate.md"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

for FILE in \
  "$CONTRACT" \
  "$PROJECT_SCOPE" \
  "$EVALUATOR" \
  "$ARCHITECTURE" \
  "$ADR"
do
  [[ -f "$FILE" ]] \
    || fail "required Feature 9C file missing"
done

jq -e . "$CONTRACT" >/dev/null \
  || fail "Feature 9C contract JSON invalid"

jq -e '
  .schema_version == 1
  and
  .feature == 9
  and
  .phase == "INCIDENT_CLOSURE_AUTHORIZATION_GATE_COMPLETE"
  and
  .validation_state
    == "EXPLICIT_INCIDENT_CLOSURE_AUTHORIZATION_GATE_COMPLETE"
  and
  .mode == "LOCAL_INCIDENT_CLOSURE_AUTHORIZATION_REVIEW_ONLY"
  and
  .source_gate_binding.algorithm == "SHA256"
  and
  .source_gate_binding.exact_source_hash_required == true
  and
  .source_gate_binding.stale_or_modified_source_rejected == true
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 9C metadata or SHA binding invalid"

[[ "$(
  jq '.review_controls | length' "$CONTRACT"
)" == "8" ]] \
  || fail "Feature 9C must define exactly eight review controls"

[[ "$(
  jq '.review_controls | unique | length' "$CONTRACT"
)" == "8" ]] \
  || fail "Feature 9C review controls must be unique"

jq -e '
  .operator_authorization.ready_value
    == "AUTHORIZED_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW"
  and
  .operator_authorization.scope
    == "SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW_ONLY"
  and
  .operator_authorization.authorizes_incident_closure == false
  and
  .operator_authorization.authorizes_tenant_write == false
  and
  .operator_authorization.authorizes_recovery_execution == false
  and
  .decision_model.ready_status
    == "READY_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW"
  and
  .decision_model.blocked_status == "BLOCKED"
  and
  .decision_model.all_review_controls_required == true
  and
  .decision_model.ready_status_authorizes_incident_closure == false
  and
  .decision_model.ready_status_authorizes_tenant_write == false
  and
  .decision_model.automatic_incident_closure == false
  and
  .decision_model.incident_closure_execution_release == "NOT_RELEASED"
  and
  .decision_model.recovery_release == "NOT_RELEASED"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 9C authorization semantics invalid"

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
  .safety_boundary.incident_closure_execution_release == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 9C safety boundary invalid"

[[ "$(
  jq -r '.current_feature' "$PROJECT_SCOPE"
)" == "9" ]] \
  || fail "project current feature must remain 9"

[[ "$(
  jq -r '.current_state' "$PROJECT_SCOPE"
)" == "incident-closure-authorization-gate-complete" ]] \
  || fail "unexpected Feature 9C project state"

grep -Fq \
  'Every authorization request is SHA-256 bound' \
  "$ARCHITECTURE" \
  || fail "Feature 9C SHA binding documentation missing"

grep -Fq \
  'It does not authorize incident closure or tenant mutation.' \
  "$ADR" \
  || fail "ADR-017 authorization boundary missing"

printf 'INCIDENT_CLOSURE_AUTHORIZATION_GATE_VALIDATION=PASS\n'
printf 'FEATURE_9C_SOURCE_SHA256_BINDING=REQUIRED\n'
printf 'FEATURE_9C_REVIEW_CONTROL_COUNT=8\n'
printf 'FEATURE_9C_READY_STATUS_AUTHORIZES_CLOSURE=NO\n'
printf 'FEATURE_9C_READY_STATUS_AUTHORIZES_TENANT_WRITE=NO\n'
printf 'FEATURE_9C_AUTOMATIC_INCIDENT_CLOSURE=NO\n'
printf 'FEATURE_9C_INCIDENT_CLOSURE_REQUESTS=0\n'
printf 'FEATURE_9C_INCIDENT_CLOSURES=0\n'
printf 'FEATURE_9C_TENANT_WRITES=0\n'
printf 'FEATURE_9C_INCIDENT_CLOSURE_EXECUTION_RELEASE=NOT_RELEASED\n'
