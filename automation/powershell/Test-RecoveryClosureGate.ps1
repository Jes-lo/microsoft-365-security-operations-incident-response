#!/usr/bin/env pwsh

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RecoveryPlanPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GateRequestPath,

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
    $RecoveryPlanPath,
    $GateRequestPath,
    $ContractPath
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Fail-Closed 'Required input file is missing.'
    }
}

$plan = Get-Content -LiteralPath $RecoveryPlanPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

$request = Get-Content -LiteralPath $GateRequestPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

$contract = Get-Content -LiteralPath $ContractPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

Assert-ExactProperties `
    -Object $request `
    -Expected @(
        'schema_version',
        'feature',
        'case_id',
        'recovery_plan_sha256',
        'gate_scope',
        'live_recovery_requested',
        'incident_closure_requested',
        'operator_validation',
        'item_validations'
    ) `
    -Context 'Closure gate request'

if ([int]$request.schema_version -ne 1) {
    Fail-Closed 'Unsupported closure gate schema.'
}

if ([int]$request.feature -ne 9) {
    Fail-Closed 'Closure gate feature mismatch.'
}

if (
    [string]$request.gate_scope -ne
    'LOCAL_RECOVERY_CLOSURE_REVIEW_ONLY'
) {
    Fail-Closed 'Unsupported closure gate scope.'
}

Assert-Boolean `
    -Value $request.live_recovery_requested `
    -Context 'live_recovery_requested'

Assert-Boolean `
    -Value $request.incident_closure_requested `
    -Context 'incident_closure_requested'

if ([bool]$request.live_recovery_requested) {
    Fail-Closed 'Live recovery is prohibited by Feature 9B.'
}

if ([bool]$request.incident_closure_requested) {
    Fail-Closed 'Incident closure execution is prohibited by Feature 9B.'
}

$caseId = [string]$request.case_id

if ($caseId -notmatch '^IR-[0-9]{8}-[A-Z0-9]{4,12}$') {
    Fail-Closed 'Invalid sanitized case ID.'
}

if ([int]$plan.feature -ne 9) {
    Fail-Closed 'Recovery plan feature mismatch.'
}

if ([string]$plan.mode -ne 'LOCAL_VALIDATION_PLAN_ONLY') {
    Fail-Closed 'Recovery plan is not a Feature 9A local validation plan.'
}

if ([string]$plan.recovery_release -ne 'NOT_RELEASED') {
    Fail-Closed 'Recovery plan unexpectedly releases recovery.'
}

if (
    [string]$plan.incident_closure_status -ne
    'NOT_READY_FOR_CLOSURE'
) {
    Fail-Closed 'Recovery plan has unexpected incident closure state.'
}

if ([bool]$plan.live_recovery_authorized) {
    Fail-Closed 'Recovery plan unexpectedly authorizes live recovery.'
}

if ([bool]$plan.automatic_incident_closure) {
    Fail-Closed 'Recovery plan unexpectedly authorizes automatic closure.'
}

if ([string]$plan.case_id -ne $caseId) {
    Fail-Closed 'Closure gate case does not match recovery plan case.'
}

$actualPlanHash = (
    Get-FileHash -LiteralPath $RecoveryPlanPath -Algorithm SHA256
).Hash.ToLowerInvariant()

$requestedPlanHash = (
    [string]$request.recovery_plan_sha256
).ToLowerInvariant()

if ($requestedPlanHash -notmatch '^[0-9a-f]{64}$') {
    Fail-Closed 'recovery_plan_sha256 must be a SHA-256 hexadecimal digest.'
}

if ($requestedPlanHash -ne $actualPlanHash) {
    Fail-Closed 'Closure gate is not bound to the exact recovery plan.'
}

$allowedOperatorValues = @(
    $contract.operator_validation.allowed_values
)

$operatorValidation = [string]$request.operator_validation

if ($operatorValidation -notin $allowedOperatorValues) {
    Fail-Closed 'Unsupported operator validation state.'
}

$planItems = @($plan.recovery_items)
$requestItems = @($request.item_validations)

if ($planItems.Count -lt 1) {
    Fail-Closed 'Recovery plan contains no recovery items.'
}

if ($requestItems.Count -ne $planItems.Count) {
    Fail-Closed 'Closure gate item count differs from recovery plan.'
}

$planBySequence = @{}
$requestBySequence = @{}

foreach ($planItem in $planItems) {
    $sequence = [int]$planItem.sequence

    if ($planBySequence.ContainsKey($sequence)) {
        Fail-Closed 'Recovery plan contains duplicate sequences.'
    }

    $planBySequence[$sequence] = $planItem
}

foreach ($requestItem in $requestItems) {
    Assert-ExactProperties `
        -Object $requestItem `
        -Expected @(
            'sequence',
            'action_type',
            'target_alias',
            'verification_results'
        ) `
        -Context 'Closure gate item validation'

    $sequence = [int]$requestItem.sequence

    if ($requestBySequence.ContainsKey($sequence)) {
        Fail-Closed 'Closure gate contains duplicate item sequences.'
    }

    $requestBySequence[$sequence] = $requestItem
}

$allowedStatuses = @(
    $contract.scenario_model.verification_statuses
)

$allowedEvidenceStatuses = @(
    $contract.scenario_model.evidence_statuses
)

$resultItems = [System.Collections.Generic.List[object]]::new()
$gateBlocked = $false

foreach ($sequence in @($planBySequence.Keys | Sort-Object)) {
    if (-not $requestBySequence.ContainsKey($sequence)) {
        Fail-Closed 'Closure gate is missing a recovery item.'
    }

    $planItem = $planBySequence[$sequence]
    $requestItem = $requestBySequence[$sequence]

    if (
        [string]$requestItem.action_type -ne
        [string]$planItem.action_type
    ) {
        Fail-Closed 'Closure gate action type differs from recovery plan.'
    }

    if (
        [string]$requestItem.target_alias -ne
        [string]$planItem.target_alias
    ) {
        Fail-Closed 'Closure gate target alias differs from recovery plan.'
    }

    $expectedChecks = @(
        $planItem.verification_checks |
            Sort-Object
    )

    if ($expectedChecks.Count -lt 1) {
        Fail-Closed 'Recovery plan item contains no verification checks.'
    }

    $verificationResults = @(
        $requestItem.verification_results
    )

    if ($verificationResults.Count -ne $expectedChecks.Count) {
        Fail-Closed 'Verification result count differs from recovery plan.'
    }

    $resultsByCheck = @{}

    foreach ($verification in $verificationResults) {
        Assert-ExactProperties `
            -Object $verification `
            -Expected @(
                'check_name',
                'status',
                'evidence_status'
            ) `
            -Context 'Verification result'

        $checkName = [string]$verification.check_name
        $status = [string]$verification.status
        $evidenceStatus = [string]$verification.evidence_status

        if ($checkName -notin $expectedChecks) {
            Fail-Closed 'Unknown recovery verification check.'
        }

        if ($resultsByCheck.ContainsKey($checkName)) {
            Fail-Closed 'Duplicate recovery verification check.'
        }

        if ($status -notin $allowedStatuses) {
            Fail-Closed 'Unsupported recovery verification status.'
        }

        if ($evidenceStatus -notin $allowedEvidenceStatuses) {
            Fail-Closed 'Unsupported recovery evidence status.'
        }

        if (
            $status -eq 'PASS' -and
            $evidenceStatus -ne 'SANITIZED_EVIDENCE_RECORDED'
        ) {
            Fail-Closed 'PASS requires sanitized evidence to be recorded.'
        }

        $resultsByCheck[$checkName] = [pscustomobject][ordered]@{
            check_name = $checkName
            status = $status
            evidence_status = $evidenceStatus
        }
    }

    foreach ($expectedCheck in $expectedChecks) {
        if (-not $resultsByCheck.ContainsKey($expectedCheck)) {
            Fail-Closed 'Required recovery verification check is missing.'
        }
    }

    $sortedVerificationResults = @(
        $resultsByCheck.Values |
            Sort-Object check_name
    )

    $itemValidated = $true

    foreach ($verification in $sortedVerificationResults) {
        if (
            [string]$verification.status -ne 'PASS' -or
            [string]$verification.evidence_status -ne
            'SANITIZED_EVIDENCE_RECORDED'
        ) {
            $itemValidated = $false
        }
    }

    $itemStatus = if ($itemValidated) {
        'VALIDATED_FOR_CLOSURE_REVIEW'
    }
    else {
        'BLOCKED'
    }

    if (-not $itemValidated) {
        $gateBlocked = $true
    }

    $resultItems.Add(
        [pscustomobject][ordered]@{
            sequence = $sequence
            action_type = [string]$planItem.action_type
            target_alias = [string]$planItem.target_alias
            recovery_strategy = [string]$planItem.recovery_strategy
            validation_status = $itemStatus
            verification_results = $sortedVerificationResults
            recovery_release = 'NOT_RELEASED'
            incident_closure_release = 'NOT_RELEASED'
        }
    )
}

if (
    $operatorValidation -ne
    [string]$contract.operator_validation.ready_value
) {
    $gateBlocked = $true
}

$gateStatus = if ($gateBlocked) {
    'BLOCKED'
}
else {
    'READY_FOR_CLOSURE_REVIEW'
}

$output = [ordered]@{
    schema_version = 1
    feature = 9
    case_id = $caseId
    mode = 'LOCAL_CLOSURE_REVIEW_ONLY'
    recovery_plan_sha256 = $actualPlanHash
    operator_validation = $operatorValidation
    gate_status = $gateStatus
    recovery_release = 'NOT_RELEASED'
    incident_closure_release = 'NOT_RELEASED'
    ready_status_authorizes_incident_closure = $false
    automatic_incident_closure = $false
    incident_closed = $false
    recovery_items = @(
        $resultItems |
            Sort-Object sequence
    )
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
        live_recovery_release = $false
        incident_closure_release = $false
    }
}

$json = $output |
    ConvertTo-Json -Depth 100

[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath($OutputPath),
    $json + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output 'RECOVERY_CLOSURE_GATE=PASS'
Write-Output "GATE_STATUS=$gateStatus"
Write-Output 'RECOVERY_PLAN_SHA256_BINDING=PASS'
Write-Output 'READY_STATUS_AUTHORIZES_INCIDENT_CLOSURE=NO'
Write-Output 'RECOVERY_RELEASE=NOT_RELEASED'
Write-Output 'INCIDENT_CLOSURE_RELEASE=NOT_RELEASED'
Write-Output 'INCIDENT_CLOSED=NO'
Write-Output 'TENANT_WRITES=0'
Write-Output 'RECOVERY_ACTIONS=0'
Write-Output 'INCIDENT_CLOSURES=0'
