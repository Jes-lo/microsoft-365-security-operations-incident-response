#!/usr/bin/env bash

set -euo pipefail
umask 077

fail() {
  printf 'INCIDENT_CASE_FOUNDATION_TEST=FAIL: %s\n' "$1" >&2
  exit 1
}

ROOT="$(
  cd \
    "$(dirname "${BASH_SOURCE[0]}")/.." \
    >/dev/null 2>&1 &&
  pwd
)"

WORK="$(mktemp -d)"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

PWSH_KIND=""
PWSH_CMD=()

if command -v pwsh >/dev/null; then
  PWSH_KIND="linux"
  PWSH_CMD=(
    pwsh
    -NoLogo
    -NoProfile
    -NonInteractive
  )
elif command -v pwsh.exe >/dev/null; then
  command -v wslpath >/dev/null \
    || fail "wslpath unavailable for Windows PowerShell runtime"

  PWSH_KIND="windows"
  PWSH_CMD=(
    pwsh.exe
    -NoLogo
    -NoProfile
    -NonInteractive
    -ExecutionPolicy
    Bypass
  )
else
  fail "PowerShell 7 runtime unavailable"
fi

to_runtime_path() {
  local path="$1"

  if [[ "$PWSH_KIND" == "windows" ]]; then
    wslpath -w "$path"
  else
    printf '%s\n' "$path"
  fi
}

NEW_CASE_SCRIPT="$(
  to_runtime_path \
    "$ROOT/automation/powershell/New-IncidentCase.ps1"
)"

ADD_EVIDENCE_SCRIPT="$(
  to_runtime_path \
    "$ROOT/automation/powershell/Add-IncidentEvidenceRecord.ps1"
)"

VERIFY_SCRIPT="$(
  to_runtime_path \
    "$ROOT/automation/powershell/Test-IncidentCaseIntegrity.ps1"
)"

CASE_ROOT="$WORK/cases"
mkdir -p "$CASE_ROOT"

SOURCE_ONE="$WORK/sensitive-looking-source-one.txt"
SOURCE_TWO="$WORK/sensitive-looking-source-two.txt"

printf '%s\n' \
  'SYNTHETIC_EVIDENCE_PAYLOAD_ONE' \
  > "$SOURCE_ONE"

printf '%s\n' \
  'SYNTHETIC_EVIDENCE_PAYLOAD_TWO' \
  > "$SOURCE_TWO"

CASE_ROOT_RUNTIME="$(
  to_runtime_path "$CASE_ROOT"
)"

SOURCE_ONE_RUNTIME="$(
  to_runtime_path "$SOURCE_ONE"
)"

SOURCE_TWO_RUNTIME="$(
  to_runtime_path "$SOURCE_TWO"
)"

"${PWSH_CMD[@]}" \
  -File "$NEW_CASE_SCRIPT" \
  -CaseId "IR-20990101-TEST01" \
  -Severity "SEV2" \
  -TitleSanitized "Synthetic incident case" \
  -RootPath "$CASE_ROOT_RUNTIME" \
  >/dev/null

CASE_PATH="$CASE_ROOT/IR-20990101-TEST01"

[[ -f "$CASE_PATH/case.json" ]] \
  || fail "case.json not created"

[[ -f "$CASE_PATH/evidence-index.json" ]] \
  || fail "evidence-index.json not created"

[[ -f "$CASE_PATH/custody.ndjson" ]] \
  || fail "custody.ndjson not created"

jq -e \
  '
    .schema_version == 1
    and
    .case_id == "IR-20990101-TEST01"
    and
    .severity == "SEV2"
    and
    .status == "OPEN"
    and
    .evidence_count == 0
    and
    .custody_event_count == 0
    and
    .raw_tenant_data_retained == false
  ' \
  "$CASE_PATH/case.json" \
  >/dev/null \
  || fail "initial case metadata invalid"

CASE_PATH_RUNTIME="$(
  to_runtime_path "$CASE_PATH"
)"

"${PWSH_CMD[@]}" \
  -File "$ADD_EVIDENCE_SCRIPT" \
  -CasePath "$CASE_PATH_RUNTIME" \
  -EvidenceId "EVID-TEST01" \
  -SourceType "LOCAL_FILE" \
  -SanitizedLabel "Synthetic evidence one" \
  -SourceFile "$SOURCE_ONE_RUNTIME" \
  >/dev/null

jq -e \
  '
    .evidence_count == 1
    and
    .custody_event_count == 1
    and
    .raw_tenant_data_retained == false
  ' \
  "$CASE_PATH/case.json" \
  >/dev/null \
  || fail "case counters invalid after first evidence item"

jq -e \
  '
    (.evidence | length) == 1
    and
    .evidence[0].evidence_id == "EVID-TEST01"
    and
    .evidence[0].source_type == "LOCAL_FILE"
    and
    .evidence[0].sanitized_label == "Synthetic evidence one"
    and
    (.evidence[0].sha256 | test("^[0-9a-f]{64}$"))
    and
    .evidence[0].size_bytes > 0
    and
    .evidence[0].raw_content_retained == false
  ' \
  "$CASE_PATH/evidence-index.json" \
  >/dev/null \
  || fail "first evidence metadata invalid"

[[ "$(wc -l < "$CASE_PATH/custody.ndjson")" -eq 1 ]] \
  || fail "first custody event missing"

if grep -R -Fq \
  'sensitive-looking-source-one.txt' \
  "$CASE_PATH"
then
  fail "source filename was retained in case workspace"
fi

if grep -R -Fq \
  "$SOURCE_ONE" \
  "$CASE_PATH"
then
  fail "source path was retained in case workspace"
fi

if grep -R -Fq \
  'SYNTHETIC_EVIDENCE_PAYLOAD_ONE' \
  "$CASE_PATH"
then
  fail "raw evidence content was copied into case workspace"
fi

"${PWSH_CMD[@]}" \
  -File "$VERIFY_SCRIPT" \
  -CasePath "$CASE_PATH_RUNTIME" \
  >/dev/null

set +e

"${PWSH_CMD[@]}" \
  -File "$ADD_EVIDENCE_SCRIPT" \
  -CasePath "$CASE_PATH_RUNTIME" \
  -EvidenceId "EVID-TEST01" \
  -SourceType "LOCAL_FILE" \
  -SanitizedLabel "Duplicate evidence attempt" \
  -SourceFile "$SOURCE_ONE_RUNTIME" \
  >/dev/null 2>&1

DUPLICATE_RC=$?

set -e

[[ "$DUPLICATE_RC" -ne 0 ]] \
  || fail "duplicate EvidenceId was accepted"

"${PWSH_CMD[@]}" \
  -File "$ADD_EVIDENCE_SCRIPT" \
  -CasePath "$CASE_PATH_RUNTIME" \
  -EvidenceId "EVID-TEST02" \
  -SourceType "OTHER_SANITIZED" \
  -SanitizedLabel "Synthetic evidence two" \
  -SourceFile "$SOURCE_TWO_RUNTIME" \
  >/dev/null

[[ "$(wc -l < "$CASE_PATH/custody.ndjson")" -eq 2 ]] \
  || fail "second custody event missing"

FIRST_HASH="$(
  sed -n '1p' \
    "$CASE_PATH/custody.ndjson" |
  jq -r '.record_sha256'
)"

SECOND_PREVIOUS_HASH="$(
  sed -n '2p' \
    "$CASE_PATH/custody.ndjson" |
  jq -r '.previous_record_sha256'
)"

[[ "$FIRST_HASH" == "$SECOND_PREVIOUS_HASH" ]] \
  || fail "custody chain did not link second event to first event"

"${PWSH_CMD[@]}" \
  -File "$VERIFY_SCRIPT" \
  -CasePath "$CASE_PATH_RUNTIME" \
  >/dev/null

cp \
  "$CASE_PATH/custody.ndjson" \
  "$WORK/custody.backup"

perl -0pi -e \
  's/Synthetic evidence one/Tampered evidence one/' \
  "$CASE_PATH/custody.ndjson"

set +e

"${PWSH_CMD[@]}" \
  -File "$VERIFY_SCRIPT" \
  -CasePath "$CASE_PATH_RUNTIME" \
  >/dev/null 2>&1

TAMPER_RC=$?

set -e

[[ "$TAMPER_RC" -ne 0 ]] \
  || fail "tampered custody record was not detected"

mv \
  "$WORK/custody.backup" \
  "$CASE_PATH/custody.ndjson"

"${PWSH_CMD[@]}" \
  -File "$VERIFY_SCRIPT" \
  -CasePath "$CASE_PATH_RUNTIME" \
  >/dev/null

jq -e \
  '
    .evidence_count == 2
    and
    .custody_event_count == 2
  ' \
  "$CASE_PATH/case.json" \
  >/dev/null \
  || fail "final case counters invalid"

jq -e \
  '
    (.evidence | length) == 2
  ' \
  "$CASE_PATH/evidence-index.json" \
  >/dev/null \
  || fail "final evidence count invalid"

printf 'INCIDENT_CASE_FOUNDATION_TEST=PASS\n'
printf 'DUPLICATE_EVIDENCE_REJECTION=PASS\n'
printf 'CUSTODY_TAMPER_DETECTION=PASS\n'
printf 'RAW_EVIDENCE_NON_RETENTION=PASS\n'
