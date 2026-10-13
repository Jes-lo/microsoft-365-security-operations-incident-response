#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

DESIGN="$ROOT/configs/containment-eradication-response-principal-design.json"
EVALUATOR="$ROOT/automation/powershell/Test-ResponsePrincipalProvisioningAuthorizationGate.ps1"

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

DESIGN_HASH="$(
  sha256sum "$DESIGN" |
  awk '{print $1}'
)"

create_request() {
  local OUTPUT="$1"

  jq -n \
    --arg hash "$DESIGN_HASH" \
    '{
      schema_version: 1,
      feature: 8,
      design_sha256: $hash,
      gate_scope: "LOCAL_PROVISIONING_AUTHORIZATION_REVIEW_ONLY",
      live_provisioning_requested: false,
      operator_authorization: "AUTHORIZED_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW",
      principal_reviews: [
        {
          principal_alias: "RESP-GRAPH-IDENTITY-001",
          exact_principal_confirmed: true,
          exact_response_domain_confirmed: true,
          exact_permission_candidates_reviewed: true,
          role_requirements_reviewed: true,
          tenant_capability_reviewed: true,
          license_requirements_reviewed: true,
          credential_method_reviewed: true,
          admin_consent_impact_reviewed: true,
          verification_plan_reviewed: true,
          rollback_plan_reviewed: true
        },
        {
          principal_alias: "RESP-GRAPH-APPLICATION-001",
          exact_principal_confirmed: true,
          exact_response_domain_confirmed: true,
          exact_permission_candidates_reviewed: true,
          role_requirements_reviewed: true,
          tenant_capability_reviewed: true,
          license_requirements_reviewed: true,
          credential_method_reviewed: true,
          admin_consent_impact_reviewed: true,
          verification_plan_reviewed: true,
          rollback_plan_reviewed: true
        },
        {
          principal_alias: "RESP-DEFENDER-ENDPOINT-001",
          exact_principal_confirmed: true,
          exact_response_domain_confirmed: true,
          exact_permission_candidates_reviewed: true,
          role_requirements_reviewed: true,
          tenant_capability_reviewed: true,
          license_requirements_reviewed: true,
          credential_method_reviewed: true,
          admin_consent_impact_reviewed: true,
          verification_plan_reviewed: true,
          rollback_plan_reviewed: true
        }
      ]
    }' \
    > "$OUTPUT"
}

VALID_REQUEST="$WORK/valid-request.json"
READY_ONE="$WORK/ready-one.json"
READY_TWO="$WORK/ready-two.json"

create_request "$VALID_REQUEST"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$EVALUATOR" \
  -DesignPath "$DESIGN" \
  -GateRequestPath "$VALID_REQUEST" \
  -OutputPath "$READY_ONE" \
  >"$WORK/ready-one.log"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$EVALUATOR" \
  -DesignPath "$DESIGN" \
  -GateRequestPath "$VALID_REQUEST" \
  -OutputPath "$READY_TWO" \
  >"$WORK/ready-two.log"

cmp -s \
  "$READY_ONE" \
  "$READY_TWO" \
  || fail "Feature 8E output is not deterministic"

jq -e \
  --arg hash "$DESIGN_HASH" \
  '
    .design_sha256 == $hash
    and
    .gate_status
      == "READY_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW"
    and
    .provisioning_release == "NOT_RELEASED"
    and
    .ready_status_authorizes_provisioning == false
    and
    (.principal_reviews | length) == 3
    and
    all(
      .principal_reviews[];
      (
        .review_status
          == "READY_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW"
        and
        .provisioning_release == "NOT_RELEASED"
        and
        .app_registration_created == false
        and
        .service_principal_created == false
        and
        .credential_created == false
        and
        .permission_granted == false
        and
        .role_assigned == false
        and
        .admin_consent_granted == false
        and
        .live_authentication_performed == false
      )
    )
    and
    .safety_boundary.app_registrations_created == 0
    and
    .safety_boundary.service_principals_created == 0
    and
    .safety_boundary.credentials_created == 0
    and
    .safety_boundary.permission_grants == 0
    and
    .safety_boundary.role_assignments == 0
    and
    .safety_boundary.admin_consents == 0
    and
    .safety_boundary.provisioning_release == false
  ' \
  "$READY_ONE" \
  >/dev/null \
  || fail "Feature 8E ready output invalid"

printf 'READY_PROVISIONING_REVIEW_MODEL=PASS\n'
printf 'READY_GATE_DOES_NOT_RELEASE_PROVISIONING=PASS\n'
printf 'DESIGN_SHA256_BINDING=PASS\n'
printf 'DETERMINISTIC_PROVISIONING_GATE=PASS\n'

BLOCKED_REQUEST="$WORK/blocked-request.json"
BLOCKED_OUTPUT="$WORK/blocked-output.json"

jq '
  .principal_reviews[0].rollback_plan_reviewed = false
' \
  "$VALID_REQUEST" \
  > "$BLOCKED_REQUEST"

pwsh \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -File "$EVALUATOR" \
  -DesignPath "$DESIGN" \
  -GateRequestPath "$BLOCKED_REQUEST" \
  -OutputPath "$BLOCKED_OUTPUT" \
  >/dev/null

jq -e '
  .gate_status == "BLOCKED"
  and
  .provisioning_release == "NOT_RELEASED"
' \
  "$BLOCKED_OUTPUT" \
  >/dev/null \
  || fail "incomplete review did not fail closed"

printf 'INCOMPLETE_PROVISIONING_REVIEW_FAIL_CLOSED=PASS\n'

expect_failure() {
  local LABEL="$1"
  local REQUEST="$2"
  local DESIGN_INPUT="${3:-$DESIGN}"
  local LOG="$WORK/${LABEL}.log"
  local OUTPUT="$WORK/${LABEL}.output.json"

  set +e

  pwsh \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -File "$EVALUATOR" \
    -DesignPath "$DESIGN_INPUT" \
    -GateRequestPath "$REQUEST" \
    -OutputPath "$OUTPUT" \
    >"$LOG" \
    2>&1

  local RC=$?

  set -e

  [[ "$RC" -ne 0 ]] \
    || fail "expected rejection did not occur: $LABEL"
}

LIVE_REQUEST="$WORK/live-request.json"

jq '
  .live_provisioning_requested = true
' \
  "$VALID_REQUEST" \
  > "$LIVE_REQUEST"

expect_failure \
  "live-provisioning-request" \
  "$LIVE_REQUEST"

printf 'LIVE_PROVISIONING_REQUEST_REJECTION=PASS\n'

BAD_AUTH="$WORK/bad-auth.json"

jq '
  .operator_authorization = "AUTHORIZED_TO_PROVISION"
' \
  "$VALID_REQUEST" \
  > "$BAD_AUTH"

expect_failure \
  "bad-authorization" \
  "$BAD_AUTH"

printf 'PROVISIONING_EXECUTION_AUTHORIZATION_VALUE_REJECTION=PASS\n'

BAD_HASH="$WORK/bad-hash.json"

jq '
  .design_sha256 = (
    "0" * 64
  )
' \
  "$VALID_REQUEST" \
  > "$BAD_HASH"

expect_failure \
  "design-hash-mismatch" \
  "$BAD_HASH"

printf 'DESIGN_HASH_MISMATCH_REJECTION=PASS\n'

UNKNOWN_ALIAS="$WORK/unknown-alias.json"

jq '
  .principal_reviews[0].principal_alias = "RESP-UNKNOWN-001"
' \
  "$VALID_REQUEST" \
  > "$UNKNOWN_ALIAS"

expect_failure \
  "unknown-principal" \
  "$UNKNOWN_ALIAS"

printf 'UNKNOWN_RESPONSE_PRINCIPAL_REJECTION=PASS\n'

DUPLICATE_ALIAS="$WORK/duplicate-alias.json"

jq '
  .principal_reviews[1].principal_alias =
    .principal_reviews[0].principal_alias
' \
  "$VALID_REQUEST" \
  > "$DUPLICATE_ALIAS"

expect_failure \
  "duplicate-principal" \
  "$DUPLICATE_ALIAS"

printf 'DUPLICATE_RESPONSE_PRINCIPAL_REJECTION=PASS\n'

MISSING_REVIEW="$WORK/missing-review.json"

jq '
  .principal_reviews = .principal_reviews[0:2]
' \
  "$VALID_REQUEST" \
  > "$MISSING_REVIEW"

expect_failure \
  "missing-principal-review" \
  "$MISSING_REVIEW"

printf 'MISSING_RESPONSE_PRINCIPAL_REVIEW_REJECTION=PASS\n'

UNEXPECTED_PROPERTY="$WORK/unexpected-property.json"

jq '
  .raw_object_identifier = "forbidden"
' \
  "$VALID_REQUEST" \
  > "$UNEXPECTED_PROPERTY"

expect_failure \
  "unexpected-property" \
  "$UNEXPECTED_PROPERTY"

printf 'PROVISIONING_GATE_UNEXPECTED_PROPERTY_REJECTION=PASS\n'

NONBOOLEAN="$WORK/nonboolean.json"

jq '
  .principal_reviews[0].credential_method_reviewed = "true"
' \
  "$VALID_REQUEST" \
  > "$NONBOOLEAN"

expect_failure \
  "nonboolean-review" \
  "$NONBOOLEAN"

printf 'PROVISIONING_GATE_BOOLEAN_TYPE_REJECTION=PASS\n'

TAMPERED_DESIGN="$WORK/tampered-design.json"

jq '
  .credential_policy.production_client_secret_allowed = true
' \
  "$DESIGN" \
  > "$TAMPERED_DESIGN"

expect_failure \
  "tampered-design" \
  "$VALID_REQUEST" \
  "$TAMPERED_DESIGN"

printf 'TAMPERED_DESIGN_REJECTION=PASS\n'

printf 'NO_RESPONSE_PRINCIPAL_PROVISIONED=PASS\n'
printf 'NO_RESPONSE_CREDENTIAL_CREATED=PASS\n'
printf 'NO_RESPONSE_PERMISSION_GRANTED=PASS\n'
printf 'NO_RESPONSE_ROLE_ASSIGNED=PASS\n'
printf 'NO_RESPONSE_ADMIN_CONSENT_GRANTED=PASS\n'
printf 'NO_RESPONSE_AUTHENTICATION_PERFORMED=PASS\n'
printf 'NO_PROVISIONING_RELEASE=PASS\n'
printf 'RESPONSE_PRINCIPAL_PROVISIONING_AUTHORIZATION_GATE_TEST=PASS\n'
