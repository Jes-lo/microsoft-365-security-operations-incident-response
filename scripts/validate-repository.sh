#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

pass() {
  printf 'PASS: %s\n' "$1"
}

required_files=(
  "README.md"
  "COPYRIGHT.md"
  "LICENSE"
  "NOTICE.md"
  "SECURITY.md"
  "THIRD_PARTY_NOTICES.md"
  "TRADEMARKS.md"
  "configs/project-scope.json"
  "tests/test-security-signal-capabilities.sh"
  "scripts/validate-security-signal-capabilities.sh"
  "automation/powershell/Invoke-SecuritySignalCapabilityDiscovery.ps1"
  "docs/decisions/ADR-002-staged-least-privilege-signal-discovery.md"
  "docs/architecture/SECURITY-SIGNAL-CAPABILITY-MATRIX.md"
  "configs/security-signal-capabilities.json"
  "tests/test-identity-incident-investigation.sh"
  "scripts/validate-identity-incident-investigation.sh"
  "docs/decisions/ADR-006-privacy-preserving-identity-investigation.md"
  "docs/architecture/IDENTITY-SECURITY-INCIDENT-INVESTIGATION.md"
  "automation/powershell/Convert-IdentitySecuritySignals.ps1"
  "configs/identity-incident-investigation-contract.json"
  "configs/enterprise-app-oauth-investigation-contract.json"
  "configs/endpoint-security-investigation-contract.json"
  "automation/powershell/Convert-EndpointSecuritySignals.ps1"
  "docs/architecture/ENDPOINT-SECURITY-INCIDENT-INVESTIGATION.md"
  "docs/decisions/ADR-008-privacy-preserving-endpoint-security-investigation.md"
  "docs/evidence/ENDPOINT-SECURITY-INCIDENT-INVESTIGATION-LIVE-VALIDATION.md"
  "scripts/validate-endpoint-security-investigation.sh"
  "tests/test-endpoint-security-investigation.sh"
  "docs/evidence/ENTERPRISE-APPLICATION-OAUTH-INCIDENT-INVESTIGATION-LIVE-VALIDATION.md"
  "automation/powershell/Convert-EnterpriseAppOAuthSignals.ps1"
  "docs/architecture/ENTERPRISE-APPLICATION-OAUTH-INCIDENT-INVESTIGATION.md"
  "docs/decisions/ADR-007-privacy-preserving-enterprise-app-oauth-investigation.md"
  "scripts/validate-enterprise-app-oauth-investigation.sh"
  "tests/test-enterprise-app-oauth-investigation.sh"
  "docs/evidence/IDENTITY-SECURITY-INCIDENT-INVESTIGATION-LIVE-VALIDATION.md"
  "tests/test-incident-case-foundation.sh"
  "scripts/validate-incident-case-foundation.sh"
  "docs/decisions/ADR-005-local-first-incident-case-evidence.md"
  "docs/architecture/INCIDENT-CASE-EVIDENCE-MODEL.md"
  "automation/powershell/Test-IncidentCaseIntegrity.ps1"
  "automation/powershell/Add-IncidentEvidenceRecord.ps1"
  "automation/powershell/New-IncidentCase.ps1"
  "configs/incident-case-contract.json"
  "docs/evidence/FEATURE-2D-2E-REMAINING-SECURITY-SIGNAL-DISCOVERY.md"
  "docs/decisions/ADR-004-complete-readonly-security-signal-discovery.md"
  "docs/evidence/FEATURE-2C-AUDITLOG-READ-ONLY-DISCOVERY.md"
  "docs/decisions/ADR-003-dedicated-readonly-graph-application.md"
  "docs/architecture/SECURITY-OPERATIONS-ARCHITECTURE.md"
  "docs/decisions/ADR-001-security-operations-safety-and-evidence-boundaries.md"
  "docs/security/PRIVACY-AND-EVIDENCE-HANDLING.md"
  "docs/testing/VALIDATION-STRATEGY.md"
  ".github/workflows/repository-security.yml"
  "automation/graph/.gitkeep"
  "automation/powershell/.gitkeep"
  "detections/apps/.gitkeep"
  "detections/endpoint/.gitkeep"
  "detections/identity/.gitkeep"
  "docs/evidence/.gitkeep"
  "docs/incidents/.gitkeep"
  "docs/postmortems/.gitkeep"
  "docs/runbooks/.gitkeep"
)

required_dirs=(
  "automation/graph"
  "automation/powershell"
  "detections/apps"
  "detections/endpoint"
  "detections/identity"
  "docs/evidence"
  "docs/incidents"
  "docs/postmortems"
  "docs/runbooks"
  "scripts"
  "tests"
)

for file in "${required_files[@]}"; do
  [[ -f "$ROOT/$file" ]] || fail "missing required file: $file"
done

pass "required files present"

for dir in "${required_dirs[@]}"; do
  [[ -d "$ROOT/$dir" ]] || fail "missing required directory: $dir"
done

pass "required directories present"

jq -e . "$ROOT/configs/project-scope.json" >/dev/null \
  || fail "project-scope.json is invalid JSON"

pass "project scope JSON valid"

grep -Fq "Detect" "$ROOT/README.md" \
  || fail "README missing security operations lifecycle"

grep -Fq "LICENSE_DEFERRED" "$ROOT/README.md" \
  || fail "README missing license-deferred classification"

grep -Fq "ENVIRONMENT_DEFERRED" "$ROOT/README.md" \
  || fail "README missing environment-deferred classification"

grep -Fq "No affiliation" "$ROOT/NOTICE.md" \
  || fail "NOTICE missing independence language"

grep -Fq "All Rights Reserved" "$ROOT/LICENSE" \
  || fail "LICENSE missing restrictive copyright language"

grep -Fq "Jesus Lopez" "$ROOT/LICENSE" \
  || fail "LICENSE missing project copyright holder"

[[ ! -e "$ROOT/CONTRIBUTING.md" ]] \
  || fail "CONTRIBUTING.md is intentionally not part of this repository"

pass "governance baseline valid"

WORKFLOW="$ROOT/.github/workflows/repository-security.yml"

grep -Eq '^[[:space:]]*permissions:[[:space:]]*$' "$WORKFLOW" \
  || fail "workflow missing explicit permissions block"

grep -Eq '^[[:space:]]*contents:[[:space:]]*read[[:space:]]*$' "$WORKFLOW" \
  || fail "workflow contents permission is not read-only"

if grep -Eq \
  '^[[:space:]]*permissions:[[:space:]]*write-all|^[[:space:]]*[A-Za-z0-9_-]+:[[:space:]]*write[[:space:]]*$' \
  "$WORKFLOW"
then
  fail "workflow contains write token permission"
fi

if grep -Eq \
  '^[[:space:]]*(pull_request_target|workflow_run):' \
  "$WORKFLOW"
then
  fail "workflow contains a prohibited high-risk trigger"
fi

python3 - "$WORKFLOW" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

refs = re.findall(r"^\s*uses:\s*['\"]?([^'\"\s#]+)", text, re.MULTILINE)
external = [ref for ref in refs if not ref.startswith("./") and not ref.startswith("docker://")]

if not external:
    raise SystemExit("FAIL: no external GitHub Action reference found")

bad = []

for ref in external:
    if "@" not in ref:
        bad.append(ref)
        continue

    _, revision = ref.rsplit("@", 1)

    if not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        bad.append(ref)

if bad:
    raise SystemExit("FAIL: external GitHub Actions must use full commit SHAs")

print("PASS: external GitHub Actions use full commit SHAs")
PY

pass "workflow security policy valid"

if grep -RIlE \
  --exclude-dir=.git \
  --exclude='validate-repository.sh' \
  -- \
  '-----BEGIN (OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----' \
  "$ROOT" \
  | grep -q .
then
  fail "private-key material detected"
fi

pass "private-key scan clean"

if find "$ROOT" \
  -path "$ROOT/.git" -prune -o \
  -type f \
  \( \
    -name '*.pfx' -o \
    -name '*.p12' -o \
    -name '*.key' -o \
    -name '*.jks' -o \
    -name '*.keystore' \
  \) \
  -print \
  | grep -q .
then
  fail "high-risk credential file detected"
fi

pass "credential-file scan clean"

LARGE_FILE_COUNT="$(
  find "$ROOT" \
    -path "$ROOT/.git" -prune -o \
    -type f \
    -size +1M \
    -print \
    | wc -l
)"

[[ "$LARGE_FILE_COUNT" -eq 0 ]] \
  || fail "tracked-source tree contains file larger than 1 MiB"

pass "file-size guardrail valid"

"$ROOT/scripts/validate-security-signal-capabilities.sh" "$ROOT/configs/security-signal-capabilities.json" >/dev/null

./scripts/validate-incident-case-foundation.sh
./tests/test-incident-case-foundation.sh

./scripts/validate-identity-incident-investigation.sh
./tests/test-identity-incident-investigation.sh

./scripts/validate-enterprise-app-oauth-investigation.sh
./tests/test-enterprise-app-oauth-investigation.sh

./scripts/validate-endpoint-security-investigation.sh
./tests/test-endpoint-security-investigation.sh

printf 'REPOSITORY_VALIDATION=PASS\n'
