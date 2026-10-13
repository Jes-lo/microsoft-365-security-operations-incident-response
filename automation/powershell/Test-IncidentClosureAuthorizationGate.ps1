#!/usr/bin/env pwsh

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ClosureGateOutputPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AuthorizationRequestPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ContractPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail-Closed {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    throw "FAIL: $Message"
}

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string[]]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $actual = @(
        $Object.PSObject.Properties.Name |
            Sort-Object
    )

    $expectedSorted = @(
        $Expected |
            Sort-Object
    )

    if (
        ($actual -join "`n") -ne
        ($expectedSorted -join "`n")
    ) {
        Fail-Closed "$Context contains missing or unexpected properties."
    }
}

function Assert-Boolean {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if ($Value -isnot [bool]) {
        Fail-Closed "$Context must be a JSON Boolean."
    }
}

foreach ($path in @(
    $ClosureGateOutputPath,
    $AuthorizationRequestPath,
    $ContractPath
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Fail-Closed 'Required input file is missing.'
    }
}

$sourceGate = Get-Content -LiteralPath $ClosureGateOutputPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

$request = Get-Content -LiteralPath $AuthorizationRequestPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

$contract = Get-Content -LiteralPath $ContractPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

Assert-ExactProperties `
    -Object $request `
    -Expected @(
        'schema_version',
        'feature',
        'case_id',
        'closure_gate_sha256',
        'gate_scope',
        'incident_closure_requested',
        'operator_authorization',
        'reviews'
    ) `
    -Context 'Incident closure authorization request'

if ([int]$request.schema_version -ne 1) {
    Fail-Closed 'Unsupported authorization schema.'
}

if ([int]$request.feature -ne 9) {
    Fail-Closed 'Authorization feature mismatch.'
}

if (
    [string]$request.gate_scope -ne
    'LOCAL_INCIDENT_CLOSURE_AUTHORIZATION_REVIEW_ONLY'
) {
    Fail-Closed 'Unsupported authorization gate scope.'
}

Assert-Boolean `
    -Value $request.incident_closure_requested `
    -Context 'incident_closure_requested'

if ([bool]$request.incident_closure_requested) {
    Fail-Closed 'Incident closure execution is prohibited by Feature 9C.'
}

$caseId = [string]$request.case_id

if ($caseId -notmatch '^IR-[0-9]{8}-[A-Z0-9]{4,12}$') {
    Fail-Closed 'Invalid sanitized case ID.'
}

if ([int]$sourceGate.feature -ne 9) {
    Fail-Closed 'Source closure gate feature mismatch.'
}

if (
    [string]$sourceGate.mode -ne
    'LOCAL_CLOSURE_REVIEW_ONLY'
) {
    Fail-Closed 'Source artifact is not a Feature 9B closure-review output.'
}

if (
    [string]$sourceGate.gate_status -ne
    'READY_FOR_CLOSURE_REVIEW'
) {
    Fail-Closed 'Source closure gate is not ready for closure review.'
}

if (
    [string]$sourceGate.recovery_release -ne
    'NOT_RELEASED'
) {
    Fail-Closed 'Source closure gate unexpectedly releases recovery.'
}

if (
    [string]$sourceGate.incident_closure_release -ne
    'NOT_RELEASED'
) {
    Fail-Closed 'Source closure gate unexpectedly releases incident closure.'
}

if ([bool]$sourceGate.ready_status_authorizes_incident_closure) {
    Fail-Closed 'Source closure gate unexpectedly authorizes incident closure.'
}

if ([bool]$sourceGate.automatic_incident_closure) {
    Fail-Closed 'Source closure gate unexpectedly allows automatic closure.'
}

if ([bool]$sourceGate.incident_closed) {
    Fail-Closed 'Source closure gate unexpectedly reports incident closed.'
}

if ([string]$sourceGate.case_id -ne $caseId) {
    Fail-Closed 'Authorization case does not match source closure gate.'
}

$actualHash = (
    Get-FileHash -LiteralPath $ClosureGateOutputPath -Algorithm SHA256
).Hash.ToLowerInvariant()

$requestedHash = (
    [string]$request.closure_gate_sha256
).ToLowerInvariant()

if ($requestedHash -notmatch '^[0-9a-f]{64}$') {
    Fail-Closed 'closure_gate_sha256 must be a SHA-256 hexadecimal digest.'
}

if ($requestedHash -ne $actualHash) {
    Fail-Closed 'Authorization request is not bound to the exact source gate.'
}

$allowedAuthorizationValues = @(
    $contract.operator_authorization.allowed_values
)

$operatorAuthorization = [string]$request.operator_authorization

if ($operatorAuthorization -notin $allowedAuthorizationValues) {
    Fail-Closed 'Unsupported operator authorization state.'
}

Assert-ExactProperties `
    -Object $request.reviews `
    -Expected @($contract.review_controls) `
    -Context 'Incident closure authorization reviews'

$allReviewsApproved = $true

foreach ($reviewName in @($contract.review_controls)) {
    $reviewValue = $request.reviews.$reviewName

    Assert-Boolean `
        -Value $reviewValue `
        -Context $reviewName

    if (-not [bool]$reviewValue) {
        $allReviewsApproved = $false
    }
}

$readyAuthorization = (
    $operatorAuthorization -eq
    [string]$contract.operator_authorization.ready_value
)

$gateStatus = if (
    $allReviewsApproved -and
    $readyAuthorization
) {
    'READY_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW'
}
else {
    'BLOCKED'
}

$output = [ordered]@{
    schema_version = 1
    feature = 9
    case_id = $caseId
    mode = 'LOCAL_INCIDENT_CLOSURE_AUTHORIZATION_REVIEW_ONLY'
    closure_gate_sha256 = $actualHash
    operator_authorization = $operatorAuthorization
    gate_status = $gateStatus
    ready_status_authorizes_incident_closure = $false
    ready_status_authorizes_tenant_write = $false
    automatic_incident_closure = $false
    incident_closure_execution_release = 'NOT_RELEASED'
    recovery_release = 'NOT_RELEASED'
    incident_closed = $false
    reviews = [ordered]@{
        EXACT_CASE_CONFIRMED =
            [bool]$request.reviews.EXACT_CASE_CONFIRMED
        RECOVERY_CLOSURE_GATE_READY_CONFIRMED =
            [bool]$request.reviews.RECOVERY_CLOSURE_GATE_READY_CONFIRMED
        RECOVERY_EVIDENCE_REVIEWED =
            [bool]$request.reviews.RECOVERY_EVIDENCE_REVIEWED
        RESIDUAL_RISK_REVIEWED =
            [bool]$request.reviews.RESIDUAL_RISK_REVIEWED
        BUSINESS_SERVICE_VALIDATED =
            [bool]$request.reviews.BUSINESS_SERVICE_VALIDATED
        FOLLOW_UP_ACTIONS_RECORDED =
            [bool]$request.reviews.FOLLOW_UP_ACTIONS_RECORDED
        POSTMORTEM_HANDOFF_CONFIRMED =
            [bool]$request.reviews.POSTMORTEM_HANDOFF_CONFIRMED
        EXPLICIT_CLOSURE_EXECUTION_REVIEW_AUTHORIZATION =
            [bool]$request.reviews.EXPLICIT_CLOSURE_EXECUTION_REVIEW_AUTHORIZATION
    }
    safety_boundary = [ordered]@{
        graph_authentication = 'NOT_PERFORMED'
        graph_requests = 0
        defender_api_authentication = 'NOT_PERFORMED'
        defender_api_requests = 0
        tenant_reads = 0
        tenant_writes = 0
        endpoint_actions = 0
        response_actions = 0
        recovery_actions = 0
        credential_changes = 0
        permission_grants = 0
        role_assignments = 0
        admin_consents = 0
        incident_closure_requests = 0
        incident_closures = 0
        incident_closure_execution_release = $false
    }
}

$json = $output |
    ConvertTo-Json -Depth 100

[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath($OutputPath),
    $json + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output 'INCIDENT_CLOSURE_AUTHORIZATION_GATE=PASS'
Write-Output "GATE_STATUS=$gateStatus"
Write-Output 'CLOSURE_GATE_SHA256_BINDING=PASS'
Write-Output 'READY_STATUS_AUTHORIZES_INCIDENT_CLOSURE=NO'
Write-Output 'READY_STATUS_AUTHORIZES_TENANT_WRITE=NO'
Write-Output 'INCIDENT_CLOSURE_EXECUTION_RELEASE=NOT_RELEASED'
Write-Output 'RECOVERY_RELEASE=NOT_RELEASED'
Write-Output 'INCIDENT_CLOSED=NO'
Write-Output 'TENANT_WRITES=0'
Write-Output 'INCIDENT_CLOSURE_REQUESTS=0'
Write-Output 'INCIDENT_CLOSURES=0'
