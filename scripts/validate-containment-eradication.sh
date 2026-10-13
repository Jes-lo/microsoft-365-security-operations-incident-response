#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/containment-eradication-contract.json"
PLANNER="$ROOT/automation/powershell/New-ContainmentEradicationPlan.ps1"
ARCHITECTURE="$ROOT/docs/architecture/CONTAINMENT-ERADICATION.md"
ADR="$ROOT/docs/decisions/ADR-010-safety-gated-containment-eradication.md"
PROJECT_SCOPE="$ROOT/configs/project-scope.json"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

for FILE in \
  "$CONTRACT" \
  "$PLANNER" \
  "$ARCHITECTURE" \
  "$ADR" \
  "$PROJECT_SCOPE"
do
  [[ -f "$FILE" ]] \
    || fail "required Feature 8 file missing"
done

command -v jq >/dev/null \
  || fail "jq is required"

jq -e . "$CONTRACT" >/dev/null \
  || fail "Feature 8 contract JSON invalid"

jq -e '
  .schema_version == 1
  and
  .feature == 8
  and
  .phase == "SIMULATION_FOUNDATION_COMPLETE"
  and
  .validation_state
    == "CONTAINMENT_ERADICATION_SIMULATION_FOUNDATION_COMPLETE"
  and
  .mode == "LOCAL_SIMULATION_ONLY"
  and
  .input_contract.execution_mode == "SIMULATION_ONLY"
  and
  .input_contract.live_execution_authorized == false
  and
  .input_contract.case_binding_required == true
  and
  .input_contract.maximum_actions == 50
  and
  .input_contract.free_form_target_identifiers_allowed == false
  and
  .input_contract.free_form_reason_text_allowed == false
  and
  .input_contract.unexpected_properties_allowed == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 8 core contract invalid"

[[ "$(
  jq '.action_catalog | length' "$CONTRACT"
)" == "8" ]] \
  || fail "unexpected Feature 8 action catalog size"

[[ "$(
  jq '
    [.action_catalog[].action_type]
    | unique
    | length
  ' "$CONTRACT"
)" == "8" ]] \
  || fail "Feature 8 action types must be unique"

jq -e '
  all(
    .action_catalog[];
    (
      .phase == "CONTAINMENT"
      or
      .phase == "ERADICATION"
    )
    and
    (
      .target_class == "SUBJECT"
      or
      .target_class == "APPLICATION"
      or
      .target_class == "DEVICE"
      or
      .target_class == "FILE"
    )
    and
    (
      .impact == "HIGH"
      or
      .impact == "CRITICAL"
    )
    and
    (
      .reversibility == "REVERSIBLE"
      or
      .reversibility == "LIMITED"
    )
    and
    .permission_resolution
      == "DEFERRED_TO_EXPLICIT_ACTION_GATE"
  )
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 8 action metadata invalid"

[[ "$(
  jq '.action_gate_requirements | length' "$CONTRACT"
)" == "10" ]] \
  || fail "Feature 8 action gate requirements incomplete"

jq -e '
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
  .safety_boundary.live_execution_authorized == false
  and
  .safety_boundary.destructive_action_default == "DENY"
  and
  .safety_boundary.live_response_action_default == "DENY"
  and
  .safety_boundary.explicit_action_gate_required == true
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 8 safety boundary invalid"

jq -e '
  .privacy_boundary.raw_tenant_identifiers_allowed == false
  and
  .privacy_boundary.raw_user_identifiers_allowed == false
  and
  .privacy_boundary.raw_application_identifiers_allowed == false
  and
  .privacy_boundary.raw_device_identifiers_allowed == false
  and
  .privacy_boundary.raw_file_identifiers_allowed == false
  and
  .privacy_boundary.raw_network_indicators_allowed == false
  and
  .privacy_boundary.raw_credentials_allowed == false
  and
  .privacy_boundary.raw_tokens_allowed == false
  and
  .privacy_boundary.free_form_target_values_allowed == false
  and
  .privacy_boundary.controlled_aliases_only == true
  and
  .privacy_boundary.controlled_reason_categories_only == true
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 8 privacy boundary invalid"

[[ "$(jq -r '.current_feature' "$PROJECT_SCOPE")" == "8" ]] \
  || fail "project current feature must be 8"

[[ "$(
  jq -r '.current_state' "$PROJECT_SCOPE"
)" == "containment-eradication-simulation-foundation-complete" ]] \
  || fail "unexpected project Feature 8 state"

for PARAMETER in \
  CasePath \
  RequestPath \
  OutputPath
do
  grep -Fq \
    "\$$PARAMETER" \
    "$PLANNER" \
    || fail "Feature 8 planner parameter missing: $PARAMETER"
done

for REQUIRED_TEXT in \
  "SIMULATION_ONLY" \
  "NOT_EXECUTED" \
  "DEFERRED_TO_EXPLICIT_ACTION_GATE" \
  "NOT_PASSED"
do
  grep -Fq \
    "$REQUIRED_TEXT" \
    "$PLANNER" \
    || fail "Feature 8 planner safety marker missing"
done

if grep -Eiq \
  'Connect-MgGraph|Invoke-MgGraphRequest|Invoke-RestMethod|Invoke-WebRequest|New-Mg|Update-Mg|Remove-Mg|Start-Process' \
  "$PLANNER"
then
  fail "Feature 8 planner contains a live external execution primitive"
fi

if grep -Eiq \
  '[A-Za-z]+[.]ReadWrite[.]|[A-Za-z]+[.]Write[.]All' \
  "$CONTRACT" \
  "$PLANNER"
then
  fail "Feature 8A must not resolve concrete write-capable Graph permissions"
fi

grep -Fq \
  'A proposed action is not an authorized action.' \
  "$ARCHITECTURE" \
  || fail "Feature 8 architecture authorization boundary missing"

grep -Fq \
  'Live execution is prohibited.' \
  "$ADR" \
  || fail "ADR-010 must explicitly prohibit live execution"

if grep -Eiq \
  '\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b' \
  "$CONTRACT" \
  "$ARCHITECTURE" \
  "$ADR"
then
  fail "GUID-like identifier detected in Feature 8 artifacts"
fi

printf 'CONTAINMENT_ERADICATION_VALIDATION=PASS\n'
printf 'FEATURE_8_EXECUTION_MODE=SIMULATION_ONLY\n'
printf 'FEATURE_8_LIVE_EXECUTION_ALLOWED=NO\n'
printf 'FEATURE_8_DESTRUCTIVE_ACTION_DEFAULT=DENY\n'
printf 'FEATURE_8_EXPLICIT_ACTION_GATE_REQUIRED=YES\n'
printf 'FEATURE_8_GRAPH_DEPENDENCY=NONE\n'
