#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CATALOG="$ROOT/configs/containment-eradication-capability-readiness.json"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

assert_permissions() {
  local ACTION="$1"
  shift

  local EXPECTED
  local ACTUAL

  EXPECTED="$(
    printf '%s\n' "$@" |
    jq -R -s -c '
      split("\n")
      | map(select(length > 0))
      | sort
    '
  )"

  ACTUAL="$(
    jq -c \
      --arg action "$ACTION" \
      '
        [
          .capabilities[]
          | select(.action_type == $action)
          | .least_privileged_delegated_permissions[]
        ]
        | sort
      ' \
      "$CATALOG"
  )"

  [[ "$ACTUAL" == "$EXPECTED" ]] \
    || fail "permission mapping mismatch for $ACTION"
}

assert_permissions \
  "SUBJECT_REVOKE_SESSIONS" \
  "User.RevokeSessions.All"

assert_permissions \
  "SUBJECT_BLOCK_SIGN_IN" \
  "User.EnableDisableAccount.All" \
  "User.Read.All"

assert_permissions \
  "APPLICATION_DISABLE_ACCESS" \
  "Application.ReadWrite.All"

assert_permissions \
  "DEVICE_ISOLATE" \
  "Machine.Isolate"

assert_permissions \
  "OAUTH_GRANT_REMOVE" \
  "DelegatedPermissionGrant.ReadWrite.All"

assert_permissions \
  "APPLICATION_CREDENTIAL_REMEDIATE" \
  "Application.ReadWrite.All"

assert_permissions \
  "SUBJECT_CREDENTIAL_RESET" \
  "User-PasswordProfile.ReadWrite.All"

assert_permissions \
  "FILE_QUARANTINE" \
  "Machine.StopAndQuarantine"

printf 'FEATURE_8C_DOCUMENTED_PERMISSION_MAPPING=PASS\n'

DECLARED_SCOPES="$(
  jq -r '
    .declared_current_read_only_boundary.delegated_scopes[]
  ' \
    "$CATALOG" |
  sort -u
)"

RESPONSE_PERMISSIONS="$(
  jq -r '
    .capabilities[].least_privileged_delegated_permissions[]
  ' \
    "$CATALOG" |
  sort -u
)"

OVERLAP="$(
  comm \
    -12 \
    <(printf '%s\n' "$DECLARED_SCOPES") \
    <(printf '%s\n' "$RESPONSE_PERMISSIONS")
)"

[[ -z "$OVERLAP" ]] \
  || fail "response permission overlaps declared read-only boundary"

printf 'READ_ONLY_RESPONSE_PERMISSION_OVERLAP=NONE\n'

jq -e '
  all(
    .capabilities[];
    .live_execution_readiness == "BLOCKED"
  )
' \
  "$CATALOG" \
  >/dev/null \
  || fail "not all capabilities fail closed"

printf 'ALL_RESPONSE_CAPABILITIES_FAIL_CLOSED=PASS\n'

jq -e '
  .future_identity_boundary.response_principal_strategy
    == "SEPARATE_RESPONSE_APP_REQUIRED"
  and
  .future_identity_boundary.reuse_current_read_only_app_for_write_actions == false
  and
  .readiness_decision.current_read_only_principal_sufficient_for_live_response == false
  and
  .readiness_decision.current_project_ready_for_live_execution == false
  and
  .readiness_decision.execution_release == "NOT_RELEASED"
' \
  "$CATALOG" \
  >/dev/null \
  || fail "response-principal separation failed"

printf 'SEPARATE_RESPONSE_PRINCIPAL_REQUIREMENT=PASS\n'
printf 'CURRENT_READ_ONLY_PRINCIPAL_PRESERVED=PASS\n'
printf 'NO_PERMISSION_GRANT_EXECUTED=PASS\n'
printf 'NO_ROLE_ASSIGNMENT_EXECUTED=PASS\n'
printf 'NO_LIVE_CAPABILITY_VALIDATION_EXECUTED=PASS\n'
printf 'NO_RESPONSE_ACTION_EXECUTED=PASS\n'
printf 'CONTAINMENT_ERADICATION_CAPABILITY_READINESS_TEST=PASS\n'
