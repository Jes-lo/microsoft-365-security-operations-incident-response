#!/usr/bin/env pwsh

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ContractPath = (
        Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'configs/recovery-validation-contract.json'
    )
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

foreach ($path in @($InputPath, $ContractPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Fail-Closed 'Required input file is missing.'
    }
}

$contract = Get-Content -LiteralPath $ContractPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

$inputDocument = Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

Assert-ExactProperties `
    -Object $inputDocument `
    -Expected @(
        'schema_version',
        'feature',
        'case_id',
        'gate_scope',
        'live_recovery_requested',
        'action_items'
    ) `
    -Context 'Recovery plan request'

if ([int]$inputDocument.schema_version -ne 1) {
    Fail-Closed 'Unsupported request schema.'
}

if ([int]$inputDocument.feature -ne 9) {
    Fail-Closed 'Request feature mismatch.'
}

if (
    [string]$inputDocument.gate_scope -ne
    'LOCAL_RECOVERY_VALIDATION_PLAN_ONLY'
) {
    Fail-Closed 'Unsupported recovery gate scope.'
}

if ($inputDocument.live_recovery_requested -isnot [bool]) {
    Fail-Closed 'live_recovery_requested must be Boolean.'
}

if ([bool]$inputDocument.live_recovery_requested) {
    Fail-Closed 'Live recovery is prohibited by Feature 9A.'
}

$caseId = [string]$inputDocument.case_id

if ($caseId -notmatch '^IR-[0-9]{8}-[A-Z0-9]{4,12}$') {
    Fail-Closed 'Invalid sanitized case ID.'
}

$items = @($inputDocument.action_items)

if ($items.Count -lt 1) {
    Fail-Closed 'At least one action item is required.'
}

if ($items.Count -gt [int]$contract.input_contract.max_action_items) {
    Fail-Closed 'Action item count exceeds contract maximum.'
}

$profiles = @{}

foreach ($profile in @($contract.recovery_profiles)) {
    $profiles[[string]$profile.action_type] = $profile
}

$seenSequences = [System.Collections.Generic.HashSet[int]]::new()
$results = [System.Collections.Generic.List[object]]::new()

foreach ($item in $items) {
    Assert-ExactProperties `
        -Object $item `
        -Expected @(
            'sequence',
            'action_type',
            'target_alias'
        ) `
        -Context 'Recovery action item'

    $sequence = [int]$item.sequence
    $actionType = [string]$item.action_type
    $targetAlias = [string]$item.target_alias

    if ($sequence -lt 1) {
        Fail-Closed 'Sequence must begin at one.'
    }

    if (-not $seenSequences.Add($sequence)) {
        Fail-Closed 'Duplicate sequence detected.'
    }

    if (-not $profiles.ContainsKey($actionType)) {
        Fail-Closed 'Unknown response action type.'
    }

    $profile = $profiles[$actionType]

    if ($targetAlias -notmatch [string]$profile.target_alias_regex) {
        Fail-Closed 'Target alias does not match the required sanitized alias class.'
    }

    $results.Add(
        [pscustomobject][ordered]@{
            sequence = $sequence
            action_type = $actionType
            target_alias = $targetAlias
            target_class = [string]$profile.target_class
            recovery_strategy = [string]$profile.recovery_strategy
            restore_previous_state_automatically = $false
            verification_checks = @($profile.verification_checks)
            validation_status = 'PENDING_SEPARATE_VALIDATION'
            recovery_release = 'NOT_RELEASED'
        }
    )
}

$sorted = @(
    $results |
        Sort-Object sequence
)

for ($index = 0; $index -lt $sorted.Count; $index++) {
    $expectedSequence = $index + 1

    if ([int]$sorted[$index].sequence -ne $expectedSequence) {
        Fail-Closed 'Sequences must be contiguous starting at one.'
    }
}

$output = [ordered]@{
    schema_version = 1
    feature = 9
    case_id = $caseId
    mode = 'LOCAL_VALIDATION_PLAN_ONLY'
    recovery_release = 'NOT_RELEASED'
    incident_closure_status = 'NOT_READY_FOR_CLOSURE'
    live_recovery_authorized = $false
    automatic_incident_closure = $false
    recovery_items = $sorted
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
        permission_grants = 0
        role_assignments = 0
        admin_consents = 0
        credential_changes = 0
        incident_closures = 0
        live_recovery_release = $false
    }
}

$json = $output | ConvertTo-Json -Depth 100

[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath($OutputPath),
    $json + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output 'RECOVERY_VALIDATION_PLAN_GENERATION=PASS'
Write-Output "RECOVERY_ITEM_COUNT=$($sorted.Count)"
Write-Output 'RECOVERY_RELEASE=NOT_RELEASED'
Write-Output 'INCIDENT_CLOSURE_STATUS=NOT_READY_FOR_CLOSURE'
Write-Output 'LIVE_RECOVERY_AUTHORIZED=NO'
Write-Output 'TENANT_WRITES=0'
Write-Output 'RECOVERY_ACTIONS=0'
Write-Output 'INCIDENT_CLOSURES=0'
