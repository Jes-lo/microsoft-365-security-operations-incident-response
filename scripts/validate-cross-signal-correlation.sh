#!/usr/bin/env bash
set -euo pipefail

ROOT="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
  pwd
)"

CONTRACT="$ROOT/configs/cross-signal-correlation-contract.json"
CONVERTER="$ROOT/automation/powershell/Convert-CrossSignalCorrelation.ps1"
ARCHITECTURE="$ROOT/docs/architecture/CROSS-SIGNAL-CORRELATION.md"
ADR="$ROOT/docs/decisions/ADR-009-privacy-preserving-cross-signal-correlation.md"
PROJECT_SCOPE="$ROOT/configs/project-scope.json"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

for FILE in \
  "$CONTRACT" \
  "$CONVERTER" \
  "$ARCHITECTURE" \
  "$ADR" \
  "$PROJECT_SCOPE"
do
  [[ -f "$FILE" ]] \
    || fail "required Feature 7 file missing"
done

jq -e . "$CONTRACT" >/dev/null \
  || fail "Feature 7 contract JSON invalid"

[[ "$(jq -r '.feature' "$CONTRACT")" == "7" ]] \
  || fail "unexpected Feature 7 number"

[[ "$(jq -r '.phase' "$CONTRACT")" == "FOUNDATION_COMPLETE" ]] \
  || fail "unexpected Feature 7 phase"

[[ "$(jq -r '.validation_state' "$CONTRACT")" == "CROSS_SIGNAL_CORRELATION_FOUNDATION_COMPLETE" ]] \
  || fail "unexpected Feature 7 validation state"

[[ "$(jq '.inputs | length' "$CONTRACT")" == "4" ]] \
  || fail "unexpected Feature 7 input count"

[[ "$(
  jq \
    '[.inputs[] |
      select(
        .source_feature == 4
        or
        .source_feature == 5
        or
        .source_feature == 6
      )
    ] |
    length' \
    "$CONTRACT"
)" == "3" ]] \
  || fail "Features 4-6 must be represented as correlation inputs"

[[ "$(
  jq -r \
    '.correlation_model.deterministic_temporal_timeline' \
    "$CONTRACT"
)" == "true" ]] \
  || fail "deterministic timeline must be enabled"

[[ "$(
  jq -r \
    '.correlation_model.unbound_events_preserved' \
    "$CONTRACT"
)" == "true" ]] \
  || fail "unbound events must be preserved"

[[ "$(
  jq -r \
    '.correlation_model.source_local_aliases_are_domain_scoped' \
    "$CONTRACT"
)" == "true" ]] \
  || fail "aliases must remain domain scoped"

[[ "$(
  jq -r \
    '.correlation_model.cross_domain_alias_string_equality_join_allowed' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "cross-domain alias equality join must be prohibited"

[[ "$(
  jq -r \
    '.correlation_model.explicit_sanitized_binding_required_for_entity_join' \
    "$CONTRACT"
)" == "true" ]] \
  || fail "explicit sanitized binding must be required"

[[ "$(
  jq -r \
    '.correlation_model.phantom_binding_members_allowed' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "phantom binding members must be prohibited"

[[ "$(
  jq -r \
    '.correlation_model.duplicate_member_assignment_allowed' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "duplicate binding assignment must be prohibited"

[[ "$(
  jq -r \
    '.correlation_model.supported_explicit_relationships | length' \
    "$CONTRACT"
)" == "1" ]] \
  || fail "unexpected Feature 7 relationship count"

[[ "$(
  jq -r \
    '.correlation_model.supported_explicit_relationships[0]' \
    "$CONTRACT"
)" == "SAME_SUBJECT" ]] \
  || fail "Feature 7A must support SAME_SUBJECT only"

for FIELD in \
  raw_tenant_identifiers_retained \
  raw_user_identifiers_retained \
  raw_application_identifiers_retained \
  raw_device_identifiers_retained \
  raw_network_indicators_retained \
  raw_file_artifacts_retained \
  raw_graph_payloads_retained \
  raw_cross_domain_correlation_ids_retained
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.privacy_boundary[$field]' \
      "$CONTRACT"
  )" == "false" ]] \
    || fail "unsafe Feature 7 privacy field: $FIELD"
done

[[ "$(
  jq -r \
    '.privacy_boundary.identifier_like_category_values_redacted' \
    "$CONTRACT"
)" == "true" ]] \
  || fail "identifier-like category values must be redacted"

grep -Fq \
  'function Test-SensitiveCategoryValue' \
  "$CONVERTER" \
  || fail "sensitive category detector missing"

grep -Fq \
  "return 'REDACTED_CATEGORY'" \
  "$CONVERTER" \
  || fail "category redaction behavior missing"

for FIELD in \
  graph_requests \
  tenant_reads \
  tenant_writes \
  endpoint_actions \
  response_actions \
  new_permission_grants \
  role_assignments \
  trial_activations
do
  [[ "$(
    jq -r \
      --arg field "$FIELD" \
      '.safety_boundary[$field]' \
      "$CONTRACT"
  )" == "0" ]] \
    || fail "unsafe Feature 7 safety value: $FIELD"
done

[[ "$(
  jq -r \
    '.safety_boundary.graph_authentication_required' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "Feature 7A must not require Graph authentication"

[[ "$(jq -r '.current_feature' "$PROJECT_SCOPE")" == "7" ]] \
  || fail "project current feature must be 7"

[[ "$(
  jq -r '.current_state' "$PROJECT_SCOPE"
)" == "cross-signal-correlation-foundation-complete" ]] \
  || fail "unexpected project Feature 7 state"

for PARAMETER in \
  CasePath \
  IdentitySummaryPath \
  ApplicationSummaryPath \
  EndpointSummaryPath \
  OutputPath \
  BindingsPath
do
  grep -Fq \
    "\$$PARAMETER" \
    "$CONVERTER" \
    || fail "Feature 7 converter parameter missing: $PARAMETER"
done

grep -Fq \
  'Cross-domain correlation therefore never joins records merely because their alias strings are equal.' \
  "$ARCHITECTURE" \
  || fail "architecture must prohibit alias-equality joins"

grep -Fq \
  'Entity binding is independent from temporal correlation.' \
  "$ADR" \
  || fail "ADR must separate entity and temporal correlation"

if grep -Eq \
  '\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b' \
  "$CONTRACT" \
  "$ARCHITECTURE" \
  "$ADR"
then
  fail "GUID-like identifier detected in Feature 7 repository artifacts"
fi

printf 'CROSS_SIGNAL_CORRELATION_VALIDATION=PASS\n'
printf 'CROSS_DOMAIN_ALIAS_EQUALITY_JOIN=NO\n'
printf 'EXPLICIT_SANITIZED_BINDING_REQUIRED=YES\n'
printf 'FEATURE_7_TENANT_API_DEPENDENCY=NONE\n'
