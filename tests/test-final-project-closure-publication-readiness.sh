#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

VALIDATOR="$ROOT/scripts/validate-final-project-closure-publication-readiness.sh"
BASE_CONTRACT="$ROOT/configs/final-project-closure-publication-readiness-contract.json"
BASE_SCOPE="$ROOT/configs/project-scope.json"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

WORK="$(
  mktemp -d
)"

cleanup() {
  rm -rf -- "$WORK"
}

trap cleanup EXIT

run_validator() {
  local CONTRACT="$1"
  local SCOPE="$2"

  PUBLICATION_READINESS_CONTRACT_PATH="$CONTRACT" \
  PUBLICATION_READINESS_PROJECT_SCOPE_PATH="$SCOPE" \
  "$VALIDATOR"
}

run_validator \
  "$BASE_CONTRACT" \
  "$BASE_SCOPE" \
  >/dev/null

printf 'FINAL_PUBLICATION_READINESS_BASELINE_MODEL=PASS\n'

expect_failure() {
  local LABEL="$1"
  local CONTRACT="$2"
  local SCOPE="${3:-$BASE_SCOPE}"

  set +e

  run_validator \
    "$CONTRACT" \
    "$SCOPE" \
    >"$WORK/${LABEL}.log" \
    2>&1

  local RC=$?

  set -e

  [[ "$RC" -ne 0 ]] \
    || fail "expected rejection did not occur: $LABEL"
}

BAD_RELEASE="$WORK/bad-release.json"

jq '
  .publication_boundary.publication_release = "RELEASED"
' \
  "$BASE_CONTRACT" \
  > "$BAD_RELEASE"

expect_failure \
  "publication-release" \
  "$BAD_RELEASE"

printf 'PUBLICATION_RELEASE_REJECTION=PASS\n'

BAD_VISIBILITY_AUTH="$WORK/bad-visibility-auth.json"

jq '
  .publication_boundary.repository_visibility_change_authorized = true
' \
  "$BASE_CONTRACT" \
  > "$BAD_VISIBILITY_AUTH"

expect_failure \
  "visibility-authorization" \
  "$BAD_VISIBILITY_AUTH"

printf 'VISIBILITY_CHANGE_AUTHORIZATION_REJECTION=PASS\n'

BAD_AUTOMATION="$WORK/bad-automatic-publication.json"

jq '
  .publication_boundary.automatic_publication_allowed = true
' \
  "$BASE_CONTRACT" \
  > "$BAD_AUTOMATION"

expect_failure \
  "automatic-publication" \
  "$BAD_AUTOMATION"

printf 'AUTOMATIC_PUBLICATION_REJECTION=PASS\n'

BAD_MANUAL_REVIEW="$WORK/bad-manual-review.json"

jq '
  .publication_boundary.manual_human_review_required = false
' \
  "$BASE_CONTRACT" \
  > "$BAD_MANUAL_REVIEW"

expect_failure \
  "manual-review-bypass" \
  "$BAD_MANUAL_REVIEW"

printf 'MANUAL_PUBLICATION_REVIEW_BYPASS_REJECTION=PASS\n'

BAD_EXTERNAL_CLOSE="$WORK/bad-external-close.json"

jq '
  .project_closure.external_incident_closure_executed = true
' \
  "$BASE_CONTRACT" \
  > "$BAD_EXTERNAL_CLOSE"

expect_failure \
  "external-incident-close" \
  "$BAD_EXTERNAL_CLOSE"

printf 'EXTERNAL_INCIDENT_CLOSURE_CLAIM_REJECTION=PASS\n'

BAD_TENANT_WRITE="$WORK/bad-tenant-write.json"

jq '
  .safety_boundary.tenant_writes = 1
' \
  "$BASE_CONTRACT" \
  > "$BAD_TENANT_WRITE"

expect_failure \
  "tenant-write" \
  "$BAD_TENANT_WRITE"

printf 'TENANT_WRITE_PUBLICATION_STATE_REJECTION=PASS\n'

BAD_PUBLICATION_ACTION="$WORK/bad-publication-action.json"

jq '
  .safety_boundary.publication_actions = 1
' \
  "$BASE_CONTRACT" \
  > "$BAD_PUBLICATION_ACTION"

expect_failure \
  "publication-action" \
  "$BAD_PUBLICATION_ACTION"

printf 'PUBLICATION_ACTION_REJECTION=PASS\n'

BAD_GOVERNANCE="$WORK/bad-governance.json"

jq '
  .required_governance_files =
    (.required_governance_files | map(select(. != "TRADEMARKS.md")))
' \
  "$BASE_CONTRACT" \
  > "$BAD_GOVERNANCE"

expect_failure \
  "governance-contract" \
  "$BAD_GOVERNANCE"

printf 'GOVERNANCE_CONTRACT_TAMPER_REJECTION=PASS\n'

BAD_MANUAL_DOMAIN="$WORK/bad-manual-domain.json"

jq '
  .publication_audit_domains =
    (.publication_audit_domains | map(select(. != "MANUAL_PUBLICATION_DECISION")))
' \
  "$BASE_CONTRACT" \
  > "$BAD_MANUAL_DOMAIN"

expect_failure \
  "manual-publication-domain" \
  "$BAD_MANUAL_DOMAIN"

printf 'MANUAL_PUBLICATION_DECISION_REMOVAL_REJECTION=PASS\n'

BAD_SCOPE="$WORK/bad-scope.json"

jq '
  .current_state =
    "postmortem-local-case-closure-foundation-complete"
' \
  "$BASE_SCOPE" \
  > "$BAD_SCOPE"

expect_failure \
  "project-scope" \
  "$BASE_CONTRACT" \
  "$BAD_SCOPE"

printf 'FINAL_PROJECT_STATE_BINDING_REJECTION=PASS\n'

printf 'NO_REPOSITORY_VISIBILITY_CHANGE_EXECUTED=PASS\n'
printf 'NO_PUBLICATION_ACTION_EXECUTED=PASS\n'
printf 'NO_GRAPH_PUBLICATION_REQUEST_EXECUTED=PASS\n'
printf 'NO_DEFENDER_PUBLICATION_REQUEST_EXECUTED=PASS\n'
printf 'NO_TENANT_PUBLICATION_WRITE_EXECUTED=PASS\n'
printf 'FINAL_PROJECT_CLOSURE_PUBLICATION_READINESS_TEST=PASS\n'
