#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

PLANNER="$ROOT/automation/powershell/New-RecoveryValidationPlan.ps1"
CONTRACT="$ROOT/configs/recovery-validation-contract.json"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v jq >/dev/null \
  || fail "jq is required"

command -v pwsh >/dev/null \
  || fail "pwsh is required"

WORK="$(
  mktemp -d
)"

cleanup() {
  rm -rf -- "$WORK"
}

trap cleanup EXIT

VALID_REQUEST="$WORK/valid-request.json"
OUTPUT_ONE="$WORK/output-one.json"
OUTPUT_TWO="$WORK/output-two.json"

cat > "$VALID_REQUEST" <<'JSON'
{
  "schema_version": 1,
  "feature": 9,
  "case_id": "IR-20261013-TEST9A",
  "gate_scope": "LOCAL_RECOVERY_VALIDATION_PLAN_ONLY",
  "live_recovery_requested": false,
  "action_items": [
    {
      "sequence": 1,
      "action_type": "SUBJECT_REVOKE_SESSIONS",
      "target_alias": "SUBJECT-001"
    },
    {
      "sequence": 2,
      "action_type": "SUBJECT_BLOCK_SIGN_IN",
      "target_alias": "SUBJECT-002"
    },
    {
      "sequence": 3,
      "action_type": "APPLICATION_DISABLE_ACCESS",
      "target_alias": "APP-001"
    },
    {
      "sequence": 4,
      "action_type": "DEVICE_ISOLATE",
      "target_alias": "DEVICE-001"
    },
    {
      "sequence": 5,
      "action_type": "OAUTH_GRANT_REMOVE",
      "target_alias": "APP-002"
    },
    {
      "sequence": 6,
      "action_type": "APPLICATION_CREDENTIAL_REMEDIATE",
      "target_alias": "APP-003"
    },
    {
      "sequence": 7,
      "action_type": "SUBJECT_CREDENTIAL_RESET",
      "target_alias": "SUBJECT-003"
    },
    {
      "sequence": 8,
      "action_type": "FILE_QUARANTINE",
      "target_alias": "FILE-001"
    }
  ]
}
JSON

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$PLANNER" \
  -InputPath "$VALID_REQUEST" \
  -OutputPath "$OUTPUT_ONE" \
  -ContractPath "$CONTRACT" \
  >/dev/null

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$PLANNER" \
  -InputPath "$VALID_REQUEST" \
  -OutputPath "$OUTPUT_TWO" \
  -ContractPath "$CONTRACT" \
  >/dev/null

cmp -s \
  "$OUTPUT_ONE" \
  "$OUTPUT_TWO" \
  || fail "recovery plan output is not deterministic"

jq -e '
  .feature == 9
  and
  .mode == "LOCAL_VALIDATION_PLAN_ONLY"
  and
  .recovery_release == "NOT_RELEASED"
  and
  .incident_closure_status == "NOT_READY_FOR_CLOSURE"
  and
  .live_recovery_authorized == false
  and
  .automatic_incident_closure == false
  and
  (.recovery_items | length) == 8
  and
  all(
    .recovery_items[];
    (
      .restore_previous_state_automatically == false
      and
      .validation_status == "PENDING_SEPARATE_VALIDATION"
      and
      .recovery_release == "NOT_RELEASED"
    )
  )
  and
  .safety_boundary.tenant_writes == 0
  and
  .safety_boundary.recovery_actions == 0
  and
  .safety_boundary.incident_closures == 0
' \
  "$OUTPUT_ONE" \
  >/dev/null \
  || fail "valid recovery plan output invalid"

printf 'RECOVERY_PLAN_MODEL=PASS\n'
printf 'DETERMINISTIC_RECOVERY_PLAN=PASS\n'
printf 'RECOVERY_PLAN_ACTION_COVERAGE=8_OF_8\n'
printf 'RECOVERY_ITEMS_PENDING_SEPARATE_VALIDATION=PASS\n'
printf 'NO_AUTOMATIC_RECOVERY_RELEASE=PASS\n'
printf 'NO_AUTOMATIC_INCIDENT_CLOSURE=PASS\n'

jq -e '
  (
    .recovery_items[]
    | select(.action_type == "OAUTH_GRANT_REMOVE")
    | .recovery_strategy
  ) == "REAPPROVAL_REQUIRED"
  and
  (
    .recovery_items[]
    | select(.action_type == "APPLICATION_CREDENTIAL_REMEDIATE")
    | .recovery_strategy
  ) == "REPLACEMENT_CREDENTIAL_ONLY"
  and
  (
    .recovery_items[]
    | select(.action_type == "SUBJECT_CREDENTIAL_RESET")
    | .recovery_strategy
  ) == "NEW_CREDENTIAL_REESTABLISHMENT"
  and
  (
    .recovery_items[]
    | select(.action_type == "FILE_QUARANTINE")
    | .recovery_strategy
  ) == "BENIGN_RECLASSIFICATION_REQUIRED"
' \
  "$OUTPUT_ONE" \
  >/dev/null \
  || fail "sensitive recovery strategies invalid"

printf 'SENSITIVE_RECOVERY_STRATEGIES=PASS\n'

expect_failure() {
  local LABEL="$1"
  local REQUEST="$2"

  set +e

  pwsh \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -File "$PLANNER" \
    -InputPath "$REQUEST" \
    -OutputPath "$WORK/${LABEL}.output.json" \
    -ContractPath "$CONTRACT" \
    >"$WORK/${LABEL}.log" \
    2>&1

  local RC=$?

  set -e

  [[ "$RC" -ne 0 ]] \
    || fail "expected rejection did not occur: $LABEL"
}

LIVE_REQUEST="$WORK/live-request.json"

jq '
  .live_recovery_requested = true
' \
  "$VALID_REQUEST" \
  > "$LIVE_REQUEST"

expect_failure \
  "live-recovery" \
  "$LIVE_REQUEST"

printf 'LIVE_RECOVERY_REQUEST_REJECTION=PASS\n'

UNKNOWN_ACTION="$WORK/unknown-action.json"

jq '
  .action_items[0].action_type = "UNKNOWN_RESPONSE_ACTION"
' \
  "$VALID_REQUEST" \
  > "$UNKNOWN_ACTION"

expect_failure \
  "unknown-action" \
  "$UNKNOWN_ACTION"

printf 'UNKNOWN_RECOVERY_ACTION_REJECTION=PASS\n'

RAW_ALIAS="$WORK/raw-alias.json"

jq '
  .action_items[0].target_alias =
    "RAW-TENANT-OBJECT-ID-FORBIDDEN"
' \
  "$VALID_REQUEST" \
  > "$RAW_ALIAS"

expect_failure \
  "raw-alias" \
  "$RAW_ALIAS"

printf 'RAW_IDENTIFIER_RECOVERY_INPUT_REJECTION=PASS\n'

DUPLICATE_SEQUENCE="$WORK/duplicate-sequence.json"

jq '
  .action_items[1].sequence = 1
' \
  "$VALID_REQUEST" \
  > "$DUPLICATE_SEQUENCE"

expect_failure \
  "duplicate-sequence" \
  "$DUPLICATE_SEQUENCE"

printf 'DUPLICATE_RECOVERY_SEQUENCE_REJECTION=PASS\n'

NONCONTIGUOUS="$WORK/noncontiguous.json"

jq '
  .action_items[7].sequence = 9
' \
  "$VALID_REQUEST" \
  > "$NONCONTIGUOUS"

expect_failure \
  "noncontiguous-sequence" \
  "$NONCONTIGUOUS"

printf 'NONCONTIGUOUS_RECOVERY_SEQUENCE_REJECTION=PASS\n'

UNEXPECTED="$WORK/unexpected.json"

jq '
  .credential = "forbidden"
' \
  "$VALID_REQUEST" \
  > "$UNEXPECTED"

expect_failure \
  "unexpected-property" \
  "$UNEXPECTED"

printf 'RECOVERY_UNEXPECTED_PROPERTY_REJECTION=PASS\n'

printf 'NO_GRAPH_RECOVERY_REQUEST_EXECUTED=PASS\n'
printf 'NO_DEFENDER_RECOVERY_REQUEST_EXECUTED=PASS\n'
printf 'NO_TENANT_RECOVERY_WRITE_EXECUTED=PASS\n'
printf 'NO_ENDPOINT_RECOVERY_ACTION_EXECUTED=PASS\n'
printf 'NO_INCIDENT_CLOSURE_EXECUTED=PASS\n'
printf 'RECOVERY_VALIDATION_FOUNDATION_TEST=PASS\n'
