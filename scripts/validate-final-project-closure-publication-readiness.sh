#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="${PUBLICATION_READINESS_CONTRACT_PATH:-$ROOT/configs/final-project-closure-publication-readiness-contract.json}"
PROJECT_SCOPE="${PUBLICATION_READINESS_PROJECT_SCOPE_PATH:-$ROOT/configs/project-scope.json}"

ARCHITECTURE="$ROOT/docs/architecture/FINAL-PROJECT-CLOSURE-AND-PUBLICATION-READINESS.md"
ADR="$ROOT/docs/decisions/ADR-019-final-project-closure-and-publication-readiness.md"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

[[ -f "$CONTRACT" ]] \
  || fail "publication-readiness contract missing"

[[ -f "$PROJECT_SCOPE" ]] \
  || fail "project scope missing"

[[ -f "$ARCHITECTURE" ]] \
  || fail "publication-readiness architecture missing"

[[ -f "$ADR" ]] \
  || fail "publication-readiness ADR missing"

jq -e . "$CONTRACT" >/dev/null \
  || fail "publication-readiness contract JSON invalid"

jq -e '
  .schema_version == 1
  and
  .feature == 10
  and
  .phase == "FINAL_PROJECT_CLOSURE_PUBLICATION_READINESS_AUDIT_COMPLETE"
  and
  .validation_state == "FINAL_PROJECT_CLOSURE_PUBLICATION_READINESS_AUDIT_COMPLETE"
  and
  .mode == "LOCAL_PUBLICATION_READINESS_AUDIT_ONLY"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10B contract metadata invalid"

jq -e '
  .project_closure.implementation_status == "IMPLEMENTATION_COMPLETE"
  and
  .project_closure.modeled_incident_response_lifecycle_complete == true
  and
  .project_closure.final_feature == 10
  and
  .project_closure.external_incident_closure_executed == false
  and
  .project_closure.external_incident_closure_release == "NOT_RELEASED"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10B project-closure state invalid"

jq -e '
  .publication_boundary.audit_status
    == "READY_FOR_MANUAL_PUBLICATION_REVIEW"
  and
  .publication_boundary.publication_release == "NOT_RELEASED"
  and
  .publication_boundary.repository_visibility_change_status
    == "NOT_PERFORMED"
  and
  .publication_boundary.repository_visibility_change_authorized == false
  and
  .publication_boundary.automatic_publication_allowed == false
  and
  .publication_boundary.manual_human_review_required == true
  and
  .publication_boundary.required_visibility_during_audit == "PRIVATE"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10B publication boundary invalid"

jq -e '
  .required_governance_files == [
    "README.md",
    "COPYRIGHT.md",
    "LICENSE",
    "NOTICE.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "TRADEMARKS.md"
  ]
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10B governance-file contract invalid"

jq -e '
  (.publication_audit_domains | length) == 10
  and
  (.publication_audit_domains | unique | length) == 10
  and
  (.publication_audit_domains | index("MANUAL_PUBLICATION_DECISION")) != null
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10B audit-domain model invalid"

jq -e '
  .automated_requirements.repository_validation_required == true
  and
  .automated_requirements.adversarial_validation_required == true
  and
  .automated_requirements.tracked_local_private_directory_allowed == false
  and
  .automated_requirements.tracked_raw_tenant_evidence_allowed == false
  and
  .automated_requirements.tracked_credentials_allowed == false
  and
  .automated_requirements.tracked_tokens_allowed == false
  and
  .automated_requirements.tracked_private_keys_allowed == false
  and
  .automated_requirements.tenant_write_claim_allowed == false
  and
  .automated_requirements.live_response_execution_claim_allowed == false
  and
  .automated_requirements.external_incident_closure_claim_allowed == false
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10B automated requirements invalid"

jq -e '
  .manual_review_requirements.third_party_attribution_review == "MANUAL_REQUIRED"
  and
  .manual_review_requirements.trademark_wording_review == "MANUAL_REQUIRED"
  and
  .manual_review_requirements.portfolio_claim_review == "MANUAL_REQUIRED"
  and
  .manual_review_requirements.sensitive_evidence_review == "MANUAL_REQUIRED"
  and
  .manual_review_requirements.repository_visibility_change_review == "MANUAL_REQUIRED"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10B manual-review boundary invalid"

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
  .safety_boundary.repository_visibility_changes == 0
  and
  .safety_boundary.publication_actions == 0
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 10B safety boundary invalid"

jq -e '
  .current_feature == 10
  and
  .current_state
    == "final-project-closure-publication-readiness-audit-complete"
' \
  "$PROJECT_SCOPE" \
  >/dev/null \
  || fail "Feature 10B project scope invalid"

while IFS= read -r FILE
do
  [[ -f "$ROOT/$FILE" ]] \
    || fail "required governance file missing"
done < <(
  jq -r \
    '.required_governance_files[]' \
    "$CONTRACT"
)

if git -C "$ROOT" ls-files |
   grep -Eq '(^|/)\.local/'
then
  fail "tracked .local content is prohibited"
fi

if git -C "$ROOT" ls-files |
   grep -Eq '(^|/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)$'
then
  fail "tracked private-key filename detected"
fi

grep -Fq \
  'The repository remains private until a separate manual publication decision.' \
  "$ARCHITECTURE" \
  || fail "publication visibility boundary documentation missing"

grep -Fq \
  'It cannot authorize publication or change repository visibility.' \
  "$ADR" \
  || fail "ADR-019 publication boundary missing"

printf 'FINAL_PROJECT_CLOSURE_PUBLICATION_READINESS_VALIDATION=PASS\n'
printf 'FEATURE_10B_IMPLEMENTATION_STATUS=IMPLEMENTATION_COMPLETE\n'
printf 'FEATURE_10B_AUDIT_STATUS=READY_FOR_MANUAL_PUBLICATION_REVIEW\n'
printf 'FEATURE_10B_PUBLICATION_RELEASE=NOT_RELEASED\n'
printf 'FEATURE_10B_VISIBILITY_CHANGE_STATUS=NOT_PERFORMED\n'
printf 'FEATURE_10B_VISIBILITY_CHANGE_AUTHORIZED=NO\n'
printf 'FEATURE_10B_AUTOMATIC_PUBLICATION=NO\n'
printf 'FEATURE_10B_MANUAL_PUBLICATION_REVIEW_REQUIRED=YES\n'
printf 'FEATURE_10B_TRACKED_LOCAL_PRIVATE_CONTENT=NO\n'
printf 'FEATURE_10B_TENANT_WRITES=0\n'
printf 'FEATURE_10B_EXTERNAL_INCIDENT_CLOSURES=0\n'
printf 'FEATURE_10B_PUBLICATION_ACTIONS=0\n'
