#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/containment-eradication-action-gate-contract.json"
EVALUATOR="$ROOT/automation/powershell/Test-ContainmentEradicationActionGate.ps1"
ARCHITECTURE="$ROOT/docs/architecture/CONTAINMENT-ERADICATION-ACTION-GATE.md"
ADR="$ROOT/docs/decisions/ADR-011-explicit-response-action-gate.md"
PROJECT_SCOPE="$ROOT/configs/project-scope.json"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

for FILE in \
  "$CONTRACT" \
  "$EVALUATOR" \
  "$ARCHITECTURE" \
  "$ADR" \
  "$PROJECT_SCOPE"
do
  [[ -f "$FILE" ]] \
    || fail "required Feature 8B file missing"
done

command -v jq >/dev/null \
  || fail "jq is required"

jq -e . "$CONTRACT" >/dev/null \
  || fail "Feature 8B contract JSON invalid"

jq -e '
  .schema_version == 1
  and
  .feature == 8
  and
  .phase == "ACTION_GATE_MODEL_COMPLETE"
  and
  .validation_state == "EXPLICIT_ACTION_GATE_MODEL_COMPLETE"
  and
  .mode == "LOCAL_MODEL_REVIEW_ONLY"
  and
  .input_contract.plan_source == "FEATURE_8A_SIMULATION_PLAN"
  and
  .input_contract.plan_execution_mode_required == "SIMULATION_ONLY"
  and
  .input_contract.plan_live_execution_authorized_required == false
  and
  .input_contract.gate_scope == "LOCAL_MODEL_REVIEW_ONLY"
  and
  .input_contract.live_execution_requested == false
  and
  .input_contract.maximum_actions == 50
  and
  .input_contract.unexpected_properties_allowed == false
  and
  .input_contract.free_form_text_allowed == false
  and
  .input_contract.raw_identifiers_allowed == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 8B input contract invalid"

[[ "$(
  jq '.local_review_requirements | length' "$CONTRACT"
)" == "10" ]] \
  || fail "Feature 8B review requirements incomplete"

jq -e '
  .operator_authorization.allowed_value
    == "AUTHORIZED_FOR_SEPARATE_LIVE_GATE_REVIEW"
  and
  .operator_authorization.authorization_scope
    == "SEPARATE_LIVE_GATE_REVIEW_ONLY"
  and
  .operator_authorization.authorizes_live_execution == false
  and
  .operator_authorization.authorizes_permission_grant == false
  and
  .operator_authorization.authorizes_role_assignment == false
  and
  .operator_authorization.authorizes_endpoint_action == false
  and
  .operator_authorization.authorizes_tenant_write == false
  and
  .permission_boundary.symbolic_capability_confirmation_allowed == true
  and
  .permission_boundary.concrete_permission_resolution
    == "DEFERRED_TO_SEPARATE_LIVE_GATE"
  and
  .permission_boundary.concrete_write_scope_allowed == false
  and
  .permission_boundary.new_permission_grant_allowed == false
  and
  .permission_boundary.role_assignment_allowed == false
  and
  .permission_boundary.trial_activation_allowed == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 8B authorization/permission boundary invalid"

jq -e '
  .decision_model.ready_status
    == "READY_FOR_SEPARATE_LIVE_GATE_REVIEW"
  and
  .decision_model.blocked_status == "BLOCKED"
  and
  .decision_model.all_local_requirements_required_for_ready == true
  and
  .decision_model.ready_status_authorizes_execution == false
  and
  .decision_model.blocked_status_fail_closed == true
  and
  .decision_model.execution_release_status == "NOT_RELEASED"
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
  .safety_boundary.live_execution_available == false
  and
  .safety_boundary.live_execution_release == false
  and
  .safety_boundary.destructive_action_default == "DENY"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 8B decision/safety boundary invalid"

CURRENT_FEATURE="$(
  jq -r \
    '.current_feature' \
    "$PROJECT_SCOPE"
)"

[[ "$CURRENT_FEATURE" =~ ^[0-9]+$ ]] \
  || fail "project current feature must be numeric"

(( CURRENT_FEATURE >= 8 )) \
  || fail "project current feature must not regress below 8"

if (( CURRENT_FEATURE == 8 )); then
  [[ "$(
    jq -r '.current_state' "$PROJECT_SCOPE"
  )" == "containment-eradication-action-gate-model-complete" ]] \
    || fail "unexpected project Feature 8B state"
fi

for PARAMETER in \
  PlanPath \
  GateRequestPath \
  OutputPath
do
  grep -Fq \
    "\$$PARAMETER" \
    "$EVALUATOR" \
    || fail "Feature 8B evaluator parameter missing: $PARAMETER"
done

for REQUIRED_TEXT in \
  "LOCAL_MODEL_REVIEW_ONLY" \
  "AUTHORIZED_FOR_SEPARATE_LIVE_GATE_REVIEW" \
  "READY_FOR_SEPARATE_LIVE_GATE_REVIEW" \
  "BLOCKED" \
  "NOT_RELEASED" \
  "NOT_EXECUTED" \
  "DEFERRED_TO_SEPARATE_LIVE_GATE"
do
  grep -Fq \
    "$REQUIRED_TEXT" \
    "$EVALUATOR" \
    || fail "Feature 8B evaluator safety marker missing"
done

if grep -Eiq \
  'Connect-MgGraph|Invoke-MgGraphRequest|Invoke-RestMethod|Invoke-WebRequest|New-Mg|Update-Mg|Remove-Mg|Start-Process' \
  "$EVALUATOR"
then
  fail "Feature 8B evaluator contains live/external execution primitive"
fi

if grep -Eiq \
  '[A-Za-z]+[.]ReadWrite[.]|[A-Za-z]+[.]Write[.]All' \
  "$CONTRACT" \
  "$EVALUATOR"
then
  fail "Feature 8B must not resolve concrete write-capable permissions"
fi

grep -Fq \
  'It does not execute containment or eradication actions.' \
  "$ARCHITECTURE" \
  || fail "Feature 8B architecture execution boundary missing"

grep -Fq \
  'It cannot release execution.' \
  "$ADR" \
  || fail "ADR-011 execution-release boundary missing"

printf 'CONTAINMENT_ERADICATION_ACTION_GATE_VALIDATION=PASS\n'
printf 'FEATURE_8B_GATE_SCOPE=LOCAL_MODEL_REVIEW_ONLY\n'
printf 'FEATURE_8B_READY_STATUS_AUTHORIZES_EXECUTION=NO\n'
printf 'FEATURE_8B_LIVE_EXECUTION_RELEASE=NO\n'
printf 'FEATURE_8B_CONCRETE_PERMISSION_RESOLUTION=DEFERRED\n'
printf 'FEATURE_8B_GRAPH_DEPENDENCY=NONE\n'
