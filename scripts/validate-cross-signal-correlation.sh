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
EVIDENCE="$ROOT/docs/evidence/CROSS-SIGNAL-CORRELATION-LIVE-VALIDATION.md"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

for FILE in \
  "$CONTRACT" \
  "$CONVERTER" \
  "$ARCHITECTURE" \
  "$ADR" \
  "$PROJECT_SCOPE" \
  "$EVIDENCE"
do
  [[ -f "$FILE" ]] \
    || fail "required Feature 7 file missing"
done

jq -e . "$CONTRACT" >/dev/null \
  || fail "Feature 7 contract JSON invalid"

[[ "$(jq -r '.feature' "$CONTRACT")" == "7" ]] \
  || fail "unexpected Feature 7 number"

[[ "$(jq -r '.phase' "$CONTRACT")" == "LIVE_VALIDATION_COMPLETE" ]] \
  || fail "unexpected Feature 7 phase"

[[ "$(jq -r '.validation_state' "$CONTRACT")" == "CROSS_SIGNAL_CORRELATION_COMPLETE" ]] \
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

CURRENT_FEATURE="$(
  jq -r '.current_feature' "$PROJECT_SCOPE"
)"

[[ "$CURRENT_FEATURE" =~ ^[0-9]+$ ]] \
  || fail "project current feature must be numeric"

(( CURRENT_FEATURE >= 7 )) \
  || fail "project current feature must not regress below 7"

if (( CURRENT_FEATURE == 7 )); then
  [[ "$(
    jq -r '.current_state' "$PROJECT_SCOPE"
  )" == "cross-signal-correlation-complete" ]] \
    || fail "unexpected project Feature 7 state"
fi

[[ "$(
  jq -r \
    '.safety_boundary.applies_to' \
    "$CONTRACT"
)" == "CORRELATOR_RUNTIME" ]] \
  || fail "Feature 7 safety boundary scope must remain correlator runtime"

jq -e '
  .live_validation.status == "PASS"
  and
  .live_validation.result
    == "AVAILABLE_SURFACES_TEMPORAL_CORRELATION_VALIDATED"
  and
  .live_validation.authentication == "DELEGATED_READ_ONLY"
  and
  .live_validation.device_code_used == false
  and
  .live_validation.persistent_execution_policy_change == false
  and
  .live_validation.lookback_hours == 24
  and
  .live_validation.maximum_records_per_surface == 25
  and
  .live_validation.graph_get_request_count == 5
  and
  .live_validation.successful_get_count == 5
  and
  .live_validation.pagination_used == false
  and
  .live_validation.new_permission_grant_count == 0
  and
  .live_validation.tenant_write_count == 0
  and
  .live_validation.endpoint_action_count == 0
  and
  .live_validation.response_action_count == 0
  and
  .live_validation.role_assignment_count == 0
  and
  .live_validation.trial_activation_count == 0
  and
  .live_validation.raw_graph_payloads_printed == false
  and
  .live_validation.raw_graph_payloads_retained == false
  and
  .live_validation.raw_identifiers_retained == false
  and
  .live_validation.live_activity_counts_committed_to_git == false
  and
  .live_validation.temporary_live_inputs_committed_to_git == false
  and
  .live_validation.sanitized_live_transformation_validated == true
  and
  .live_validation.deterministic_correlation_validated == true
  and
  .live_validation.explicit_live_entity_binding_attempted == false
  and
  .live_validation.cross_domain_alias_equality_join_used == false
  and
  .live_validation.zero_signal_empty_array_regression_validated == true
  and
  .live_validation.feature_3_evidence_registration_validated == true
  and
  .live_validation.feature_3_custody_integrity_validated == true
  and
  .live_validation.source_states.sign_ins == "NONZERO"
  and
  .live_validation.source_states.directory_audits == "NONZERO"
  and
  .live_validation.source_states.risk_detections == "ZERO"
  and
  .live_validation.source_states.defender_alerts == "ZERO"
  and
  .live_validation.source_states.defender_incidents == "ZERO"
  and
  .live_validation.sanitized_domain_states.identity == "NONZERO"
  and
  .live_validation.sanitized_domain_states.application == "NONZERO"
  and
  .live_validation.sanitized_domain_states.endpoint == "ZERO"
  and
  .live_validation.sanitized_domain_states.timeline == "NONZERO"
' \
  "$CONTRACT" \
  >/dev/null \
  || fail "Feature 7 live validation contract is incomplete"

EXPECTED_EVIDENCE_PATH="$(
  jq -r \
    '.live_validation.sanitized_evidence_path' \
    "$CONTRACT"
)"

[[ "$EXPECTED_EVIDENCE_PATH" == \
  "docs/evidence/CROSS-SIGNAL-CORRELATION-LIVE-VALIDATION.md" ]] \
  || fail "unexpected Feature 7 live evidence path"

EXPECTED_EVIDENCE_SHA="$(
  jq -r \
    '.live_validation.sanitized_evidence_sha256' \
    "$CONTRACT"
)"

ACTUAL_EVIDENCE_SHA="$(
  sha256sum "$EVIDENCE" |
  awk '{print $1}'
)"

[[ "$EXPECTED_EVIDENCE_SHA" == "$ACTUAL_EVIDENCE_SHA" ]] \
  || fail "Feature 7 live evidence SHA-256 mismatch"

grep -Fq \
  'Exact live activity counts are intentionally not retained in the repository.' \
  "$EVIDENCE" \
  || fail "Feature 7 evidence must prohibit committed live activity counts"

grep -Fq \
  'No explicit live cross-domain entity binding was attempted.' \
  "$EVIDENCE" \
  || fail "Feature 7 evidence must record no live entity binding"

grep -Fq \
  'Raw Graph payloads were not retained.' \
  "$EVIDENCE" \
  || fail "Feature 7 evidence must record raw payload non-retention"

if grep -Eiq \
  '\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|https?://|\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
  "$EVIDENCE"
then
  fail "identifier-like value detected in Feature 7 live evidence"
fi

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
printf 'FEATURE_7_CORRELATOR_TENANT_API_DEPENDENCY=NONE\n'
printf 'FEATURE_7_LIVE_VALIDATION=PASS\n'
printf 'FEATURE_7_LIVE_EVIDENCE_SHA256=PASS\n'
