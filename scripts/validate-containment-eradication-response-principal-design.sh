#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

DESIGN="${RESPONSE_PRINCIPAL_DESIGN_PATH:-$ROOT/configs/containment-eradication-response-principal-design.json}"
F8A="$ROOT/configs/containment-eradication-contract.json"
PROJECT_SCOPE="$ROOT/configs/project-scope.json"
ARCHITECTURE="$ROOT/docs/architecture/CONTAINMENT-ERADICATION-RESPONSE-PRINCIPAL-DESIGN.md"
ADR="$ROOT/docs/decisions/ADR-013-provider-and-domain-separated-response-principals.md"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

for FILE in \
  "$DESIGN" \
  "$F8A" \
  "$PROJECT_SCOPE" \
  "$ARCHITECTURE" \
  "$ADR"
do
  [[ -f "$FILE" ]] \
    || fail "required Feature 8D file missing"
done

jq -e . "$DESIGN" >/dev/null \
  || fail "Feature 8D design JSON invalid"

jq -e '
  .schema_version == 1
  and
  .feature == 8
  and
  .phase == "SEPARATE_RESPONSE_PRINCIPAL_DESIGN_COMPLETE"
  and
  .validation_state == "SEPARATE_RESPONSE_PRINCIPAL_DESIGN_COMPLETE"
  and
  .mode == "LOCAL_ARCHITECTURE_ONLY"
  and
  .source_review.authority == "MICROSOFT_LEARN"
  and
  .source_review.application_context_reviewed == true
  and
  .source_review.credential_security_guidance_reviewed == true
  and
  .source_review.live_tenant_validation_performed == false
  and
  .source_review.live_permission_validation_performed == false
' \
  "$DESIGN" \
  >/dev/null \
  || fail "Feature 8D source/design metadata invalid"

jq -e '
  .investigation_principal_boundary.reuse_for_response == false
  and
  .investigation_principal_boundary.mutation_allowed == false
  and
  .investigation_principal_boundary.permission_expansion_allowed == false
  and
  .investigation_principal_boundary.credential_changes_allowed == false
  and
  .design_principles.provider_separation == true
  and
  .design_principles.response_domain_separation == true
  and
  .design_principles.least_privilege == true
  and
  .design_principles.blast_radius_minimization == true
  and
  .design_principles.credential_isolation == true
  and
  .design_principles.shared_response_credentials_allowed == false
  and
  .design_principles.shared_response_principal_for_all_actions_allowed == false
' \
  "$DESIGN" \
  >/dev/null \
  || fail "Feature 8D separation boundary invalid"

jq -e '
  .credential_policy.preference_order == [
    "MANAGED_IDENTITY_IF_AZURE_HOSTED_AND_COMPATIBLE",
    "WORKLOAD_IDENTITY_FEDERATION_IF_SUPPORTED",
    "CERTIFICATE_CREDENTIAL"
  ]
  and
  .credential_policy.production_client_secret_allowed == false
  and
  .credential_policy.credential_material_in_repository_allowed == false
  and
  .credential_policy.credentials_created_by_feature_8d == false
  and
  .credential_policy.credential_selection_status
    == "DEFERRED_TO_PROVISIONING_GATE"
' \
  "$DESIGN" \
  >/dev/null \
  || fail "Feature 8D credential policy invalid"

[[ "$(
  jq '.principal_topology.principals | length' "$DESIGN"
)" == "3" ]] \
  || fail "Feature 8D must define exactly three response principals"

[[ "$(
  jq '
    [.principal_topology.principals[].principal_alias]
    | unique
    | length
  ' "$DESIGN"
)" == "3" ]] \
  || fail "response principal aliases must be unique"

jq -e '
  .principal_topology.principal_count == 3
  and
  .principal_topology.planned_runtime_context == "APPLICATION_CONTEXT"
  and
  all(
    .principal_topology.principals[];
    (
      .creation_status == "NOT_CREATED"
      and
      .credential_status == "NOT_CREATED"
      and
      .permission_grant_status == "NOT_GRANTED"
      and
      .directory_role_assignment_status == "NOT_ASSIGNED"
      and
      .live_authentication_status == "NOT_PERFORMED"
      and
      .execution_release == "NOT_RELEASED"
    )
  )
' \
  "$DESIGN" \
  >/dev/null \
  || fail "Feature 8D principal lifecycle state invalid"

jq -e '
  (
    [
      .principal_topology.principals[]
      | select(
          .principal_alias == "RESP-GRAPH-IDENTITY-001"
          and
          .provider == "MICROSOFT_GRAPH"
          and
          .response_domain == "IDENTITY_RESPONSE"
      )
    ]
    | length
  ) == 1
  and
  (
    [
      .principal_topology.principals[]
      | select(
          .principal_alias == "RESP-GRAPH-APPLICATION-001"
          and
          .provider == "MICROSOFT_GRAPH"
          and
          .response_domain == "APPLICATION_AND_OAUTH_RESPONSE"
      )
    ]
    | length
  ) == 1
  and
  (
    [
      .principal_topology.principals[]
      | select(
          .principal_alias == "RESP-DEFENDER-ENDPOINT-001"
          and
          .provider == "DEFENDER_FOR_ENDPOINT_API"
          and
          .response_domain == "ENDPOINT_RESPONSE"
      )
    ]
    | length
  ) == 1
' \
  "$DESIGN" \
  >/dev/null \
  || fail "Feature 8D principal topology invalid"

EXPECTED_ACTIONS="$(
  jq -c -S '
    [.action_catalog[].action_type]
    | sort
  ' \
    "$F8A"
)"

DESIGNED_ACTIONS="$(
  jq -c -S '
    [
      .principal_topology.principals[].action_types[]
    ]
    | sort
  ' \
    "$DESIGN"
)"

[[ "$DESIGNED_ACTIONS" == "$EXPECTED_ACTIONS" ]] \
  || fail "Feature 8D action coverage differs from Feature 8A"

[[ "$(
  jq '
    [
      .principal_topology.principals[].action_types[]
    ]
    | unique
    | length
  ' \
    "$DESIGN"
)" == "8" ]] \
  || fail "every response action must map to exactly one principal"

[[ "$(
  jq '
    [
      .principal_topology.principals[].application_permission_candidates[]
      | .action_type
    ]
    | unique
    | length
  ' \
    "$DESIGN"
)" == "8" ]] \
  || fail "permission candidate mapping must cover eight unique actions"

jq -e '
  all(
    .principal_topology.principals[].application_permission_candidates[];
    (
      (.permissions | length) >= 1
      and
      (.resolution | length) > 0
    )
  )
' \
  "$DESIGN" \
  >/dev/null \
  || fail "Feature 8D permission candidate metadata incomplete"

jq -e '
  .provisioning_gate.exact_permission_revalidation_required == true
  and
  .provisioning_gate.exact_role_revalidation_required == true
  and
  .provisioning_gate.tenant_capability_validation_required == true
  and
  .provisioning_gate.license_validation_required == true
  and
  .provisioning_gate.credential_method_review_required == true
  and
  .provisioning_gate.admin_consent_review_required == true
  and
  .provisioning_gate.target_scope_review_required == true
  and
  .provisioning_gate.rollback_design_required == true
  and
  .provisioning_gate.verification_design_required == true
  and
  .provisioning_gate.explicit_human_authorization_required == true
  and
  .provisioning_gate.principal_creation_authorized_by_feature_8d == false
  and
  .provisioning_gate.credential_creation_authorized_by_feature_8d == false
  and
  .provisioning_gate.permission_grant_authorized_by_feature_8d == false
  and
  .provisioning_gate.role_assignment_authorized_by_feature_8d == false
  and
  .provisioning_gate.admin_consent_authorized_by_feature_8d == false
  and
  .provisioning_gate.live_authentication_authorized_by_feature_8d == false
  and
  .provisioning_gate.response_execution_authorized_by_feature_8d == false
  and
  .provisioning_gate.next_gate
    == "EXPLICIT_RESPONSE_PRINCIPAL_PROVISIONING_AUTHORIZATION"
' \
  "$DESIGN" \
  >/dev/null \
  || fail "Feature 8D provisioning gate invalid"

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
  .safety_boundary.live_execution_release == false
' \
  "$DESIGN" \
  >/dev/null \
  || fail "Feature 8D safety boundary invalid"

CURRENT_FEATURE="$(
  jq -r '.current_feature' "$PROJECT_SCOPE"
)"

[[ "$CURRENT_FEATURE" =~ ^[0-9]+$ ]] \
  || fail "project current feature must be numeric"

(( CURRENT_FEATURE >= 8 )) \
  || fail "project current feature must not regress below 8"

if (( CURRENT_FEATURE == 8 )); then
  [[ "$(
    jq -r '.current_state' "$PROJECT_SCOPE"
  )" == "containment-eradication-response-principal-design-complete" ]] \
    || fail "unexpected Feature 8D project state"
fi

grep -Fq \
  'three independent future response principals' \
  "$ARCHITECTURE" \
  || fail "Feature 8D architecture topology statement missing"

grep -Fq \
  'Production client secrets are prohibited' \
  "$ADR" \
  || fail "ADR-013 credential boundary missing"

printf 'CONTAINMENT_ERADICATION_RESPONSE_PRINCIPAL_DESIGN_VALIDATION=PASS\n'
printf 'FEATURE_8D_PRINCIPAL_COUNT=3\n'
printf 'FEATURE_8D_ACTION_COVERAGE=8_OF_8\n'
printf 'FEATURE_8D_APPLICATION_CONTEXT_DESIGN=YES\n'
printf 'FEATURE_8D_CURRENT_READ_ONLY_APP_MUTATION=NO\n'
printf 'FEATURE_8D_APP_REGISTRATIONS_CREATED=0\n'
printf 'FEATURE_8D_SERVICE_PRINCIPALS_CREATED=0\n'
printf 'FEATURE_8D_CREDENTIALS_CREATED=0\n'
printf 'FEATURE_8D_PERMISSION_GRANTS=0\n'
printf 'FEATURE_8D_ROLE_ASSIGNMENTS=0\n'
printf 'FEATURE_8D_ADMIN_CONSENTS=0\n'
printf 'FEATURE_8D_LIVE_AUTHENTICATION=NOT_PERFORMED\n'
printf 'FEATURE_8D_EXECUTION_RELEASE=NOT_RELEASED\n'
