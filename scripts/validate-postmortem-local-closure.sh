#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/postmortem-local-closure-contract.json"
PROJECT_SCOPE="$ROOT/configs/project-scope.json"
BUILDER="$ROOT/automation/powershell/New-PostmortemLocalClosureRecord.ps1"
ARCHITECTURE="$ROOT/docs/architecture/POSTMORTEM-AND-LOCAL-CLOSURE.md"
ADR="$ROOT/docs/decisions/ADR-018-postmortem-and-local-case-closure.md"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

for FILE in \
  "$CONTRACT" \
  "$PROJECT_SCOPE" \
  "$BUILDER" \
  "$ARCHITECTURE" \
  "$ADR"
do
  [[ -f "$FILE" ]] \
    || fail "required Feature 10A file missing"
done

jq -e . "$CONTRACT" >/dev/null \
  || fail "Feature 10A contract JSON invalid"

jq -e '
  .schema_version == 1
  and
  .feature == 10
  and
  .phase == "POSTMORTEM_LOCAL_CASE_CLOSURE_FOUNDATION_COMPLETE"
  and
  .validation_state == "POSTMORTEM_LOCAL_CASE_CLOSURE_FOUNDATION_COMPLETE"
  and
  .mode == "LOCAL_POSTMORTEM_CASE_CLOSURE_ONLY"
  and
  .source_authorization_binding.algorithm == "SHA256"
  and
  .source_authorization_binding.exact_source_hash_required == true
  and
  .source_authorization_binding.stale_or_modified_source_rejected == true
  and
  .source_authorization_binding.required_source_status
    == "READY_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10A metadata or source binding invalid"

jq -e '
  .input.gate_scope == "LOCAL_POSTMORTEM_CASE_CLOSURE_RECORD_ONLY"
  and
  .input.external_incident_closure_requested == false
  and
  .input.unexpected_properties_allowed == false
  and
  .input.raw_tenant_identifiers_allowed == false
  and
  .input.raw_object_identifiers_allowed == false
  and
  .input.credentials_allowed == false
  and
  .input.tokens_allowed == false
  and
  .input.free_form_narrative_allowed == false
  and
  .input.max_follow_up_actions == 20
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10A input boundary invalid"

jq -e '
  (.taxonomy.root_cause_categories | length) == 8
  and
  (.taxonomy.impact_scopes | length) == 5
  and
  (.taxonomy.contributing_factors | length) == 9
  and
  (.taxonomy.lessons_learned | length) == 8
  and
  (.taxonomy.follow_up_categories | length) == 8
  and
  (.taxonomy.follow_up_priorities | length) == 3
  and
  (.taxonomy.follow_up_owner_roles | length) == 6
  and
  (.taxonomy.follow_up_due_windows | length) == 4
  and
  (.taxonomy.follow_up_statuses | length) == 3
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10A taxonomy invalid"

jq -e '
  .closure_model.postmortem_status == "POSTMORTEM_COMPLETE"
  and
  .closure_model.local_case_closure_scope == "LOCAL_CASE_RECORD_ONLY"
  and
  .closure_model.local_case_closure_status
    == "LOCAL_CASE_CLOSED_POSTMORTEM_COMPLETE"
  and
  .closure_model.external_incident_closure_status == "NOT_EXECUTED"
  and
  .closure_model.external_incident_closure_release == "NOT_RELEASED"
  and
  .closure_model.local_closure_implies_tenant_write == false
  and
  .closure_model.local_closure_implies_external_incident_closure == false
  and
  .closure_model.external_incident_closure_authorized == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10A closure semantics invalid"

[[ "$(
  jq '.lifecycle_phases | length' "$CONTRACT"
)" == "8" ]] \
  || fail "Feature 10A lifecycle phase count invalid"

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
  .safety_boundary.external_incident_closure_requests == 0
  and
  .safety_boundary.external_incident_closures == 0
  and
  .safety_boundary.external_incident_closure_release == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10A safety boundary invalid"

[[ "$(
  jq -r '.current_feature' "$PROJECT_SCOPE"
)" == "10" ]] \
  || fail "project current feature must be 10"

[[ "$(
  jq -r '.current_state' "$PROJECT_SCOPE"
)" == "postmortem-local-case-closure-foundation-complete" ]] \
  || fail "unexpected Feature 10A project state"

grep -Fq \
  'It does not close an incident in Microsoft 365.' \
  "$ARCHITECTURE" \
  || fail "Feature 10A external closure boundary missing"

grep -Fq \
  'Local case closure is an internal workflow/documentation state.' \
  "$ADR" \
  || fail "ADR-018 local closure distinction missing"

printf 'POSTMORTEM_LOCAL_CLOSURE_VALIDATION=PASS\n'
printf 'FEATURE_10A_SOURCE_SHA256_BINDING=REQUIRED\n'
printf 'FEATURE_10A_FREE_FORM_NARRATIVE=NO\n'
printf 'FEATURE_10A_LIFECYCLE_PHASE_COUNT=8\n'
printf 'FEATURE_10A_LOCAL_CASE_CLOSURE=YES\n'
printf 'FEATURE_10A_LOCAL_CLOSURE_IMPLIES_TENANT_WRITE=NO\n'
printf 'FEATURE_10A_LOCAL_CLOSURE_IMPLIES_EXTERNAL_CLOSURE=NO\n'
printf 'FEATURE_10A_EXTERNAL_INCIDENT_CLOSURE_STATUS=NOT_EXECUTED\n'
printf 'FEATURE_10A_EXTERNAL_INCIDENT_CLOSURE_RELEASE=NOT_RELEASED\n'
printf 'FEATURE_10A_TENANT_WRITES=0\n'
printf 'FEATURE_10A_EXTERNAL_INCIDENT_CLOSURES=0\n'
