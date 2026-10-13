#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CATALOG="$ROOT/configs/containment-eradication-capability-readiness.json"
F8A="$ROOT/configs/containment-eradication-contract.json"
PROJECT_SCOPE="$ROOT/configs/project-scope.json"
ARCHITECTURE="$ROOT/docs/architecture/CONTAINMENT-ERADICATION-CAPABILITY-READINESS.md"
ADR="$ROOT/docs/decisions/ADR-012-separate-response-principal-readiness.md"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

for FILE in \
  "$CATALOG" \
  "$F8A" \
  "$PROJECT_SCOPE" \
  "$ARCHITECTURE" \
  "$ADR"
do
  [[ -f "$FILE" ]] \
    || fail "required Feature 8C file missing"
done

jq -e . "$CATALOG" >/dev/null \
  || fail "Feature 8C catalog JSON invalid"

jq -e '
  .schema_version == 1
  and
  .feature == 8
  and
  .phase == "CAPABILITY_PERMISSION_READINESS_DISCOVERY_COMPLETE"
  and
  .validation_state == "CAPABILITY_PERMISSION_READINESS_DISCOVERY_COMPLETE"
  and
  .mode == "DOCUMENTATION_AND_REPOSITORY_DISCOVERY_ONLY"
  and
  .source_review.authority == "MICROSOFT_LEARN"
  and
  .source_review.live_tenant_validation_performed == false
  and
  .source_review.live_permission_enumeration_performed == false
' \
  "$CATALOG" \
  >/dev/null \
  || fail "Feature 8C discovery metadata invalid"

EXPECTED_SCOPES="$(
  jq -c -S -n '
    [
      "AuditLog.Read.All",
      "IdentityRiskEvent.Read.All",
      "IdentityRiskyUser.Read.All",
      "SecurityAlert.Read.All",
      "SecurityIncident.Read.All"
    ]
    | sort
  '
)"

ACTUAL_SCOPES="$(
  jq -c -S '
    .declared_current_read_only_boundary.delegated_scopes
    | sort
  ' \
    "$CATALOG"
)"

[[ "$ACTUAL_SCOPES" == "$EXPECTED_SCOPES" ]] \
  || fail "declared read-only boundary changed unexpectedly"

jq -e '
  .declared_current_read_only_boundary.write_or_action_permissions_present == false
  and
  .declared_current_read_only_boundary.current_app_mutation == "PROHIBITED"
  and
  .future_identity_boundary.response_principal_strategy
    == "SEPARATE_RESPONSE_APP_REQUIRED"
  and
  .future_identity_boundary.reuse_current_read_only_app_for_write_actions == false
  and
  .future_identity_boundary.permission_grant_authorized_by_feature_8c == false
  and
  .future_identity_boundary.role_assignment_authorized_by_feature_8c == false
  and
  .future_identity_boundary.live_authentication_authorized_by_feature_8c == false
  and
  .future_identity_boundary.live_execution_authorized_by_feature_8c == false
' \
  "$CATALOG" \
  >/dev/null \
  || fail "Feature 8C principal boundary invalid"

[[ "$(
  jq '.capabilities | length' "$CATALOG"
)" == "8" ]] \
  || fail "Feature 8C must map exactly eight response actions"

CATALOG_ACTIONS="$(
  jq -c -S '
    [.capabilities[].action_type]
    | sort
  ' \
    "$CATALOG"
)"

FEATURE8_ACTIONS="$(
  jq -c -S '
    [.action_catalog[].action_type]
    | sort
  ' \
    "$F8A"
)"

[[ "$CATALOG_ACTIONS" == "$FEATURE8_ACTIONS" ]] \
  || fail "Feature 8C action catalog does not match Feature 8A"

[[ "$(
  jq '
    [.capabilities[].action_type]
    | unique
    | length
  ' \
    "$CATALOG"
)" == "8" ]] \
  || fail "Feature 8C action types must be unique"

[[ "$(
  jq '
    [.capabilities[].symbolic_capability]
    | unique
    | length
  ' \
    "$CATALOG"
)" == "8" ]] \
  || fail "Feature 8C symbolic capabilities must be unique"

jq -e '
  all(
    .capabilities[];
    (
      .current_declared_permission_status
        == "ABSENT_FROM_DECLARED_READ_ONLY_BOUNDARY"
      and
      .permission_grant_status
        == "NOT_GRANTED_BY_FEATURE_8C"
      and
      .live_validation_status
        == "NOT_PERFORMED"
      and
      .live_execution_readiness
        == "BLOCKED"
      and
      (.least_privileged_delegated_permissions | length) >= 1
    )
  )
' \
  "$CATALOG" \
  >/dev/null \
  || fail "Feature 8C fail-closed capability state invalid"

[[ "$(
  jq '
    [
      .capabilities[]
      | select(.provider == "MICROSOFT_GRAPH")
    ]
    | length
  ' \
    "$CATALOG"
)" == "6" ]] \
  || fail "expected six Microsoft Graph response capabilities"

[[ "$(
  jq '
    [
      .capabilities[]
      | select(.provider == "DEFENDER_FOR_ENDPOINT_API")
    ]
    | length
  ' \
    "$CATALOG"
)" == "2" ]] \
  || fail "expected two Defender for Endpoint response capabilities"

jq -e '
  .readiness_decision.capability_catalog_complete_for_feature_8_actions == true
  and
  .readiness_decision.current_read_only_principal_sufficient_for_live_response == false
  and
  .readiness_decision.current_project_ready_for_live_execution == false
  and
  .readiness_decision.separate_response_principal_required == true
  and
  .readiness_decision.explicit_permission_grant_gate_required == true
  and
  .readiness_decision.live_capability_validation_required == true
  and
  .readiness_decision.execution_release == "NOT_RELEASED"
  and
  .readiness_decision.next_gate
    == "SEPARATE_RESPONSE_PRINCIPAL_AND_PERMISSION_DESIGN"
' \
  "$CATALOG" \
  >/dev/null \
  || fail "Feature 8C readiness decision invalid"

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
  .safety_boundary.new_permission_grants == 0
  and
  .safety_boundary.role_assignments == 0
  and
  .safety_boundary.trial_activations == 0
  and
  .safety_boundary.current_read_only_app_mutated == false
  and
  .safety_boundary.live_execution_release == false
' \
  "$CATALOG" \
  >/dev/null \
  || fail "Feature 8C safety boundary invalid"

CURRENT_FEATURE="$(
  jq -r '.current_feature' "$PROJECT_SCOPE"
)"

[[ "$CURRENT_FEATURE" =~ ^[0-9]+$ ]] \
  || fail "project current feature must be numeric"

(( CURRENT_FEATURE >= 8 )) \
  || fail "project current feature must not regress below 8"

if (( CURRENT_FEATURE == 8 )); then
  CURRENT_STATE="$(
    jq -r '.current_state' "$PROJECT_SCOPE"
  )"

  case "$CURRENT_STATE" in
    containment-eradication-capability-readiness-discovery-complete|\
containment-eradication-response-principal-design-complete)
      ;;
    *)
      fail "unexpected Feature 8C/8D project state"
      ;;
  esac
fi

grep -Fq \
  'SEPARATE_RESPONSE_APP_REQUIRED' \
  "$ARCHITECTURE" \
  || fail "Feature 8C separate response-principal boundary missing"

grep -Fq \
  'Discovery is not a permission grant.' \
  "$ADR" \
  || fail "ADR-012 permission boundary missing"

printf 'CONTAINMENT_ERADICATION_CAPABILITY_READINESS_VALIDATION=PASS\n'
printf 'FEATURE_8C_ACTION_COVERAGE=8_OF_8\n'
printf 'FEATURE_8C_GRAPH_CAPABILITIES=6\n'
printf 'FEATURE_8C_DEFENDER_CAPABILITIES=2\n'
printf 'FEATURE_8C_CURRENT_READ_ONLY_APP_MUTATION=NO\n'
printf 'FEATURE_8C_NEW_PERMISSION_GRANTS=0\n'
printf 'FEATURE_8C_LIVE_VALIDATION=NOT_PERFORMED\n'
printf 'FEATURE_8C_LIVE_EXECUTION_READY=NO\n'
printf 'FEATURE_8C_EXECUTION_RELEASE=NOT_RELEASED\n'
