#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

DESIGN="$ROOT/configs/containment-eradication-response-principal-design.json"
VALIDATOR="$ROOT/scripts/validate-containment-eradication-response-principal-design.sh"

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

RESPONSE_PRINCIPAL_DESIGN_PATH="$DESIGN" \
  "$VALIDATOR" \
  >/dev/null

printf 'FEATURE_8D_BASELINE_DESIGN=PASS\n'

expect_failure() {
  local LABEL="$1"
  local FILTER="$2"
  local MUTATED="$WORK/${LABEL}.json"
  local LOG="$WORK/${LABEL}.log"

  jq \
    "$FILTER" \
    "$DESIGN" \
    > "$MUTATED"

  set +e

  RESPONSE_PRINCIPAL_DESIGN_PATH="$MUTATED" \
    "$VALIDATOR" \
    >"$LOG" \
    2>&1

  local RC=$?

  set -e

  [[ "$RC" -ne 0 ]] \
    || fail "expected Feature 8D rejection did not occur: $LABEL"
}

expect_failure \
  "reuse-investigation-principal" \
  '.investigation_principal_boundary.reuse_for_response = true'

printf 'INVESTIGATION_PRINCIPAL_REUSE_REJECTION=PASS\n'

expect_failure \
  "principal-created" \
  '.principal_topology.principals[0].creation_status = "CREATED"'

printf 'UNAUTHORIZED_PRINCIPAL_CREATION_STATE_REJECTION=PASS\n'

expect_failure \
  "permission-granted" \
  '.principal_topology.principals[1].permission_grant_status = "GRANTED"'

printf 'UNAUTHORIZED_PERMISSION_GRANT_STATE_REJECTION=PASS\n'

expect_failure \
  "client-secret-enabled" \
  '.credential_policy.production_client_secret_allowed = true'

printf 'PRODUCTION_CLIENT_SECRET_REJECTION=PASS\n'

expect_failure \
  "credential-created" \
  '.principal_topology.principals[2].credential_status = "CREATED"'

printf 'UNAUTHORIZED_CREDENTIAL_CREATION_STATE_REJECTION=PASS\n'

expect_failure \
  "duplicate-action" \
  '.principal_topology.principals[1].action_types[0] = "SUBJECT_REVOKE_SESSIONS"'

printf 'DUPLICATE_OR_MISSING_ACTION_MAPPING_REJECTION=PASS\n'

expect_failure \
  "execution-released" \
  '.principal_topology.principals[0].execution_release = "RELEASED"'

printf 'EXECUTION_RELEASE_REJECTION=PASS\n'

expect_failure \
  "admin-consent-authorized" \
  '.provisioning_gate.admin_consent_authorized_by_feature_8d = true'

printf 'UNAUTHORIZED_ADMIN_CONSENT_REJECTION=PASS\n'

expect_failure \
  "current-app-mutated" \
  '.safety_boundary.current_read_only_app_mutated = true'

printf 'CURRENT_READ_ONLY_APP_MUTATION_REJECTION=PASS\n'

jq -e '
  .principal_topology.principals[0].action_types
    == [
      "SUBJECT_REVOKE_SESSIONS",
      "SUBJECT_BLOCK_SIGN_IN",
      "SUBJECT_CREDENTIAL_RESET"
    ]
  and
  .principal_topology.principals[1].action_types
    == [
      "APPLICATION_DISABLE_ACCESS",
      "OAUTH_GRANT_REMOVE",
      "APPLICATION_CREDENTIAL_REMEDIATE"
    ]
  and
  .principal_topology.principals[2].action_types
    == [
      "DEVICE_ISOLATE",
      "FILE_QUARANTINE"
    ]
' \
  "$DESIGN" \
  >/dev/null \
  || fail "response-domain action separation invalid"

printf 'RESPONSE_DOMAIN_SEPARATION=PASS\n'

jq -e '
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
  || fail "response principals do not remain fail closed"

printf 'ALL_RESPONSE_PRINCIPALS_FAIL_CLOSED=PASS\n'
printf 'NO_RESPONSE_PRINCIPAL_PROVISIONED=PASS\n'
printf 'NO_RESPONSE_CREDENTIAL_CREATED=PASS\n'
printf 'NO_RESPONSE_PERMISSION_GRANTED=PASS\n'
printf 'NO_RESPONSE_ROLE_ASSIGNED=PASS\n'
printf 'NO_RESPONSE_ADMIN_CONSENT_GRANTED=PASS\n'
printf 'NO_RESPONSE_AUTHENTICATION_PERFORMED=PASS\n'
printf 'NO_RESPONSE_EXECUTION_RELEASED=PASS\n'
printf 'CONTAINMENT_ERADICATION_RESPONSE_PRINCIPAL_DESIGN_TEST=PASS\n'
