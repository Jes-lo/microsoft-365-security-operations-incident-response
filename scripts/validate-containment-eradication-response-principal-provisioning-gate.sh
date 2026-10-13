#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/containment-eradication-response-principal-provisioning-gate-contract.json"
DESIGN="$ROOT/configs/containment-eradication-response-principal-design.json"
PROJECT_SCOPE="$ROOT/configs/project-scope.json"
EVALUATOR="$ROOT/automation/powershell/Test-ResponsePrincipalProvisioningAuthorizationGate.ps1"
ARCHITECTURE="$ROOT/docs/architecture/RESPONSE-PRINCIPAL-PROVISIONING-AUTHORIZATION-GATE.md"
ADR="$ROOT/docs/decisions/ADR-014-explicit-response-principal-provisioning-authorization-gate.md"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

for FILE in \
  "$CONTRACT" \
  "$DESIGN" \
  "$PROJECT_SCOPE" \
  "$EVALUATOR" \
  "$ARCHITECTURE" \
  "$ADR"
do
  [[ -f "$FILE" ]] \
    || fail "required Feature 8E file missing"
done

jq -e . "$CONTRACT" >/dev/null \
  || fail "Feature 8E contract JSON invalid"

jq -e '
  .schema_version == 1
  and
  .feature == 8
  and
  .phase == "PROVISIONING_AUTHORIZATION_GATE_COMPLETE"
  and
  .validation_state
    == "EXPLICIT_RESPONSE_PRINCIPAL_PROVISIONING_AUTHORIZATION_GATE_COMPLETE"
  and
  .mode == "LOCAL_AUTHORIZATION_REVIEW_ONLY"
  and
  .design_binding.algorithm == "SHA256"
  and
  .design_binding.exact_design_hash_required == true
  and
  .design_binding.stale_or_modified_design_request_rejected == true
  and
  .gate_input.gate_scope
    == "LOCAL_PROVISIONING_AUTHORIZATION_REVIEW_ONLY"
  and
  .gate_input.live_provisioning_requested == false
  and
  .gate_input.principal_count == 3
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 8E gate metadata invalid"

jq -e '
  .operator_authorization.allowed_value
    == "AUTHORIZED_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW"
  and
  .operator_authorization.authorizes_app_registration == false
  and
  .operator_authorization.authorizes_service_principal_creation == false
  and
  .operator_authorization.authorizes_credential_creation == false
  and
  .operator_authorization.authorizes_permission_grant == false
  and
  .operator_authorization.authorizes_role_assignment == false
  and
  .operator_authorization.authorizes_admin_consent == false
  and
  .operator_authorization.authorizes_live_authentication == false
  and
  .operator_authorization.authorizes_response_execution == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 8E operator authorization boundary invalid"

[[ "$(
  jq '.required_principal_reviews | length' "$CONTRACT"
)" == "10" ]] \
  || fail "Feature 8E must require exactly ten principal review controls"

[[ "$(
  jq '.principal_aliases | unique | length' "$CONTRACT"
)" == "3" ]] \
  || fail "Feature 8E must identify exactly three unique response principals"

DESIGN_ALIASES="$(
  jq -c -S '
    [.principal_topology.principals[].principal_alias]
    | sort
  ' \
    "$DESIGN"
)"

GATE_ALIASES="$(
  jq -c -S '
    .principal_aliases
    | sort
  ' \
    "$CONTRACT"
)"

[[ "$DESIGN_ALIASES" == "$GATE_ALIASES" ]] \
  || fail "Feature 8E principal aliases differ from Feature 8D design"

jq -e '
  .decision_model.ready_status
    == "READY_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW"
  and
  .decision_model.blocked_status == "BLOCKED"
  and
  .decision_model.all_principal_reviews_required == true
  and
  .decision_model.ready_status_authorizes_provisioning == false
  and
  .decision_model.ready_status_authorizes_permission_grants == false
  and
  .decision_model.ready_status_authorizes_admin_consent == false
  and
  .decision_model.blocked_fail_closed == true
  and
  .decision_model.provisioning_release_status == "NOT_RELEASED"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 8E decision semantics invalid"

jq -e '
  .safety_boundary.app_registrations_created == 0
  and
  .safety_boundary.service_principals_created == 0
  and
  .safety_boundary.credentials_created == 0
  and
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
  .safety_boundary.permission_grants == 0
  and
  .safety_boundary.role_assignments == 0
  and
  .safety_boundary.admin_consents == 0
  and
  .safety_boundary.trial_activations == 0
  and
  .safety_boundary.current_read_only_app_mutated == false
  and
  .safety_boundary.live_provisioning_available == false
  and
  .safety_boundary.provisioning_release == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 8E safety boundary invalid"

CURRENT_FEATURE="$(
  jq -r '.current_feature' "$PROJECT_SCOPE"
)"

[[ "$CURRENT_FEATURE" =~ ^[0-9]+$ ]] \
  || fail "project current feature must be numeric"

(( CURRENT_FEATURE >= 8 )) \
  || fail "project feature regressed"

if (( CURRENT_FEATURE == 8 )); then
  [[ "$(
    jq -r '.current_state' "$PROJECT_SCOPE"
  )" == "containment-eradication-response-principal-provisioning-authorization-gate-complete" ]] \
    || fail "unexpected Feature 8E project state"
fi

grep -Fq \
  'SHA-256 digest of the exact Feature 8D' \
  "$ARCHITECTURE" \
  || fail "Feature 8E SHA binding documentation missing"

grep -Fq \
  'The release remains `NOT_RELEASED`.' \
  "$ADR" \
  || fail "ADR-014 release boundary missing"

printf 'RESPONSE_PRINCIPAL_PROVISIONING_AUTHORIZATION_GATE_VALIDATION=PASS\n'
printf 'FEATURE_8E_PRINCIPAL_COUNT=3\n'
printf 'FEATURE_8E_REVIEW_CONTROLS_PER_PRINCIPAL=10\n'
printf 'FEATURE_8E_DESIGN_SHA256_BINDING=REQUIRED\n'
printf 'FEATURE_8E_READY_STATUS_AUTHORIZES_PROVISIONING=NO\n'
printf 'FEATURE_8E_APP_REGISTRATIONS_CREATED=0\n'
printf 'FEATURE_8E_SERVICE_PRINCIPALS_CREATED=0\n'
printf 'FEATURE_8E_CREDENTIALS_CREATED=0\n'
printf 'FEATURE_8E_PERMISSION_GRANTS=0\n'
printf 'FEATURE_8E_ROLE_ASSIGNMENTS=0\n'
printf 'FEATURE_8E_ADMIN_CONSENTS=0\n'
printf 'FEATURE_8E_PROVISIONING_RELEASE=NOT_RELEASED\n'
