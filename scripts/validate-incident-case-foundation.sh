#!/usr/bin/env bash

set -euo pipefail

fail() {
  printf 'INCIDENT_CASE_FOUNDATION_VALIDATION=FAIL: %s\n' "$1" >&2
  exit 1
}

ROOT="$(
  cd \
    "$(dirname "${BASH_SOURCE[0]}")/.." \
    >/dev/null 2>&1 &&
  pwd
)"

CONTRACT="$ROOT/configs/incident-case-contract.json"

[[ -f "$CONTRACT" ]] \
  || fail "incident case contract missing"

jq -e . "$CONTRACT" >/dev/null \
  || fail "incident case contract is invalid JSON"

[[ "$(jq -r '.schema_version' "$CONTRACT")" == "1" ]] \
  || fail "unexpected schema version"

[[ "$(jq -r '.feature' "$CONTRACT")" == "3" ]] \
  || fail "unexpected feature number"

[[ "$(
  jq -r \
    '.storage_boundary.generated_case_workspaces_are_local_only' \
    "$CONTRACT"
)" == "true" ]] \
  || fail "generated case workspaces are not local-only"

[[ "$(
  jq -r \
    '.storage_boundary.raw_tenant_payloads_committed_to_git' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "contract permits raw tenant payloads in Git"

[[ "$(
  jq -r \
    '.evidence_boundary.raw_content_copied_by_default' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "contract permits raw evidence copying by default"

[[ "$(
  jq -r \
    '.evidence_boundary.source_path_persisted' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "contract permits source-path persistence"

[[ "$(
  jq -r \
    '.evidence_boundary.source_filename_persisted' \
    "$CONTRACT"
)" == "false" ]] \
  || fail "contract permits source-filename persistence"

[[ "$(
  jq -r '.custody.hash_algorithm' "$CONTRACT"
)" == "SHA256" ]] \
  || fail "custody hash algorithm is not SHA256"

[[ "$(
  jq -r '.custody.previous_record_hash_chaining' "$CONTRACT"
)" == "true" ]] \
  || fail "custody previous-record chaining is disabled"

[[ "$(
  jq -r '.custody.raw_evidence_embedded' "$CONTRACT"
)" == "false" ]] \
  || fail "custody contract permits raw evidence"

SEVERITY_COUNT="$(
  jq '.severity_values | length' "$CONTRACT"
)"

[[ "$SEVERITY_COUNT" -eq 5 ]] \
  || fail "unexpected severity count"

STATUS_COUNT="$(
  jq '.status_values | length' "$CONTRACT"
)"

[[ "$STATUS_COUNT" -eq 7 ]] \
  || fail "unexpected status count"

SOURCE_TYPE_COUNT="$(
  jq '.source_type_values | length' "$CONTRACT"
)"

[[ "$SOURCE_TYPE_COUNT" -eq 5 ]] \
  || fail "unexpected source-type count"

REQUIRED_FILES=(
  "automation/powershell/New-IncidentCase.ps1"
  "automation/powershell/Add-IncidentEvidenceRecord.ps1"
  "automation/powershell/Test-IncidentCaseIntegrity.ps1"
  "docs/architecture/INCIDENT-CASE-EVIDENCE-MODEL.md"
  "docs/decisions/ADR-005-local-first-incident-case-evidence.md"
  "scripts/validate-incident-case-foundation.sh"
  "tests/test-incident-case-foundation.sh"
)

for relative in "${REQUIRED_FILES[@]}"; do
  [[ -f "$ROOT/$relative" ]] \
    || fail "required Feature 3 file missing: $relative"
done

grep -Fxq \
  '.local/incident-cases/' \
  "$ROOT/.gitignore" \
  || fail "local incident workspace is not ignored by Git"

for script in \
  "$ROOT/automation/powershell/New-IncidentCase.ps1" \
  "$ROOT/automation/powershell/Add-IncidentEvidenceRecord.ps1" \
  "$ROOT/automation/powershell/Test-IncidentCaseIntegrity.ps1"
do
  grep -Fq \
    'Set-StrictMode -Version Latest' \
    "$script" \
    || fail "PowerShell strict mode missing"

  grep -Fq \
    '$ErrorActionPreference' \
    "$script" \
    || fail "PowerShell fail-closed error preference missing"
done

if grep -R -nEI \
  -- \
  'Invoke-MgGraphRequest|Connect-MgGraph|ReadWrite|PATCH|POST|DELETE' \
  "$ROOT/automation/powershell/New-IncidentCase.ps1" \
  "$ROOT/automation/powershell/Add-IncidentEvidenceRecord.ps1" \
  "$ROOT/automation/powershell/Test-IncidentCaseIntegrity.ps1"
then
  fail "Feature 3 local tooling contains tenant-access or write-capable patterns"
fi

grep -Fq \
  "Get-FileHash" \
  "$ROOT/automation/powershell/Add-IncidentEvidenceRecord.ps1" \
  || fail "evidence SHA256 hashing is missing"

grep -Fq \
  "previous_record_sha256" \
  "$ROOT/automation/powershell/Add-IncidentEvidenceRecord.ps1" \
  || fail "custody chain previous hash is missing"

grep -Fq \
  "record_sha256" \
  "$ROOT/automation/powershell/Test-IncidentCaseIntegrity.ps1" \
  || fail "custody record verification is missing"

printf 'INCIDENT_CASE_FOUNDATION_VALIDATION=PASS\n'
