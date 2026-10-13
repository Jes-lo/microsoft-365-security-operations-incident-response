#!/usr/bin/env pwsh

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AuthorizationGateOutputPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PostmortemRequestPath,

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
    $AuthorizationGateOutputPath,
    $PostmortemRequestPath,
    $ContractPath
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Fail-Closed 'Required input file is missing.'
    }
}

$authorization = Get-Content `
    -LiteralPath $AuthorizationGateOutputPath `
    -Raw `
    -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

$request = Get-Content `
    -LiteralPath $PostmortemRequestPath `
    -Raw `
    -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

$contract = Get-Content `
    -LiteralPath $ContractPath `
    -Raw `
    -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

Assert-ExactProperties `
    -Object $request `
    -Expected @(
        'schema_version',
        'feature',
        'case_id',
        'authorization_gate_sha256',
        'gate_scope',
        'external_incident_closure_requested',
        'root_cause_category',
        'impact_scope',
        'contributing_factors',
        'lessons_learned',
        'follow_up_actions'
    ) `
    -Context 'Postmortem request'

if ([int]$request.schema_version -ne 1) {
    Fail-Closed 'Unsupported postmortem schema.'
}

if ([int]$request.feature -ne 10) {
    Fail-Closed 'Postmortem feature mismatch.'
}

if (
    [string]$request.gate_scope -ne
    'LOCAL_POSTMORTEM_CASE_CLOSURE_RECORD_ONLY'
) {
    Fail-Closed 'Unsupported postmortem gate scope.'
}

Assert-Boolean `
    -Value $request.external_incident_closure_requested `
    -Context 'external_incident_closure_requested'

if ([bool]$request.external_incident_closure_requested) {
    Fail-Closed 'External incident closure is prohibited by Feature 10A.'
}

$caseId = [string]$request.case_id

if ($caseId -notmatch '^IR-[0-9]{8}-[A-Z0-9]{4,12}$') {
    Fail-Closed 'Invalid sanitized case ID.'
}

if ([int]$authorization.feature -ne 9) {
    Fail-Closed 'Authorization source feature mismatch.'
}

if (
    [string]$authorization.mode -ne
    'LOCAL_INCIDENT_CLOSURE_AUTHORIZATION_REVIEW_ONLY'
) {
    Fail-Closed 'Source is not a Feature 9C authorization output.'
}

if (
    [string]$authorization.gate_status -ne
    'READY_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW'
) {
    Fail-Closed 'Feature 9C authorization source is not ready.'
}

if ([bool]$authorization.ready_status_authorizes_incident_closure) {
    Fail-Closed 'Feature 9C source unexpectedly authorizes incident closure.'
}

if ([bool]$authorization.ready_status_authorizes_tenant_write) {
    Fail-Closed 'Feature 9C source unexpectedly authorizes tenant writes.'
}

if ([bool]$authorization.automatic_incident_closure) {
    Fail-Closed 'Feature 9C source unexpectedly allows automatic closure.'
}

if (
    [string]$authorization.incident_closure_execution_release -ne
    'NOT_RELEASED'
) {
    Fail-Closed 'Feature 9C source unexpectedly releases closure execution.'
}

if ([bool]$authorization.incident_closed) {
    Fail-Closed 'Feature 9C source already reports incident closed.'
}

if ([string]$authorization.case_id -ne $caseId) {
    Fail-Closed 'Postmortem case does not match Feature 9C source.'
}

$actualAuthorizationHash = (
    Get-FileHash `
        -LiteralPath $AuthorizationGateOutputPath `
        -Algorithm SHA256
).Hash.ToLowerInvariant()

$requestedAuthorizationHash = (
    [string]$request.authorization_gate_sha256
).ToLowerInvariant()

if ($requestedAuthorizationHash -notmatch '^[0-9a-f]{64}$') {
    Fail-Closed 'authorization_gate_sha256 must be a SHA-256 digest.'
}

if ($requestedAuthorizationHash -ne $actualAuthorizationHash) {
    Fail-Closed 'Postmortem request is not bound to the exact Feature 9C output.'
}

$rootCause = [string]$request.root_cause_category
$impactScope = [string]$request.impact_scope

if (
    $rootCause -notin
    @($contract.taxonomy.root_cause_categories)
) {
    Fail-Closed 'Unsupported root-cause category.'
}

if (
    $impactScope -notin
    @($contract.taxonomy.impact_scopes)
) {
    Fail-Closed 'Unsupported impact scope.'
}

$contributingFactors = @(
    $request.contributing_factors
)

if ($contributingFactors.Count -lt 1) {
    Fail-Closed 'At least one contributing factor is required.'
}

$contributingFactorStrings = @(
    foreach ($factor in $contributingFactors) {
        [string]$factor
    }
)

if (
    @($contributingFactorStrings | Sort-Object -Unique).Count -ne
    $contributingFactorStrings.Count
) {
    Fail-Closed 'Contributing factors must be unique.'
}

foreach ($factor in $contributingFactorStrings) {
    if (
        $factor -notin
        @($contract.taxonomy.contributing_factors)
    ) {
        Fail-Closed 'Unsupported contributing factor.'
    }
}

$lessonsLearned = @(
    $request.lessons_learned
)

if ($lessonsLearned.Count -lt 1) {
    Fail-Closed 'At least one lesson learned is required.'
}

$lessonStrings = @(
    foreach ($lesson in $lessonsLearned) {
        [string]$lesson
    }
)

if (
    @($lessonStrings | Sort-Object -Unique).Count -ne
    $lessonStrings.Count
) {
    Fail-Closed 'Lessons learned must be unique.'
}

foreach ($lesson in $lessonStrings) {
    if (
        $lesson -notin
        @($contract.taxonomy.lessons_learned)
    ) {
        Fail-Closed 'Unsupported lesson learned.'
    }
}

$followUps = @(
    $request.follow_up_actions
)

$maxFollowUps = [int]$contract.input.max_follow_up_actions

if (
    $followUps.Count -lt 1 -or
    $followUps.Count -gt $maxFollowUps
) {
    Fail-Closed 'Invalid follow-up action count.'
}

$followUpBySequence = @{}

foreach ($followUp in $followUps) {
    Assert-ExactProperties `
        -Object $followUp `
        -Expected @(
            'sequence',
            'category',
            'priority',
            'owner_role',
            'due_window',
            'status'
        ) `
        -Context 'Follow-up action'

    $sequence = [int]$followUp.sequence

    if ($sequence -lt 1) {
        Fail-Closed 'Follow-up sequence must start at one.'
    }

    if ($followUpBySequence.ContainsKey($sequence)) {
        Fail-Closed 'Duplicate follow-up sequence.'
    }

    $category = [string]$followUp.category
    $priority = [string]$followUp.priority
    $ownerRole = [string]$followUp.owner_role
    $dueWindow = [string]$followUp.due_window
    $status = [string]$followUp.status

    if (
        $category -notin
        @($contract.taxonomy.follow_up_categories)
    ) {
        Fail-Closed 'Unsupported follow-up category.'
    }

    if (
        $priority -notin
        @($contract.taxonomy.follow_up_priorities)
    ) {
        Fail-Closed 'Unsupported follow-up priority.'
    }

    if (
        $ownerRole -notin
        @($contract.taxonomy.follow_up_owner_roles)
    ) {
        Fail-Closed 'Unsupported follow-up owner role.'
    }

    if (
        $dueWindow -notin
        @($contract.taxonomy.follow_up_due_windows)
    ) {
        Fail-Closed 'Unsupported follow-up due window.'
    }

    if (
        $status -notin
        @($contract.taxonomy.follow_up_statuses)
    ) {
        Fail-Closed 'Unsupported follow-up status.'
    }

    $followUpBySequence[$sequence] = [pscustomobject][ordered]@{
        sequence = $sequence
        category = $category
        priority = $priority
        owner_role = $ownerRole
        due_window = $dueWindow
        status = $status
    }
}

$expectedSequences = @(1..$followUps.Count)
$actualSequences = @(
    $followUpBySequence.Keys |
        Sort-Object
)

if (
    ($actualSequences -join ',') -ne
    ($expectedSequences -join ',')
) {
    Fail-Closed 'Follow-up sequences must be contiguous starting at one.'
}

$output = [ordered]@{
    schema_version = 1
    feature = 10
    case_id = $caseId
    mode = 'LOCAL_POSTMORTEM_CASE_CLOSURE_ONLY'
    authorization_gate_sha256 = $actualAuthorizationHash
    postmortem_status = 'POSTMORTEM_COMPLETE'
    local_case_closure_scope = 'LOCAL_CASE_RECORD_ONLY'
    local_case_closure_status =
        'LOCAL_CASE_CLOSED_POSTMORTEM_COMPLETE'
    external_incident_closure_status = 'NOT_EXECUTED'
    external_incident_closure_release = 'NOT_RELEASED'
    local_closure_implies_tenant_write = $false
    local_closure_implies_external_incident_closure = $false
    external_incident_closure_authorized = $false
    external_incident_closed = $false
    root_cause_category = $rootCause
    impact_scope = $impactScope
    contributing_factors = @(
        $contributingFactorStrings |
            Sort-Object
    )
    lessons_learned = @(
        $lessonStrings |
            Sort-Object
    )
    lifecycle_phases = @(
        $contract.lifecycle_phases
    )
    follow_up_actions = @(
        $followUpBySequence.Values |
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
        external_incident_closure_requests = 0
        external_incident_closures = 0
        external_incident_closure_release = $false
    }
}

$json = $output |
    ConvertTo-Json -Depth 100

[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath($OutputPath),
    $json + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output 'POSTMORTEM_LOCAL_CASE_CLOSURE=PASS'
Write-Output 'POSTMORTEM_STATUS=POSTMORTEM_COMPLETE'
Write-Output 'LOCAL_CASE_CLOSURE_STATUS=LOCAL_CASE_CLOSED_POSTMORTEM_COMPLETE'
Write-Output 'EXTERNAL_INCIDENT_CLOSURE_STATUS=NOT_EXECUTED'
Write-Output 'EXTERNAL_INCIDENT_CLOSURE_RELEASE=NOT_RELEASED'
Write-Output 'LOCAL_CLOSURE_IMPLIES_TENANT_WRITE=NO'
Write-Output 'LOCAL_CLOSURE_IMPLIES_EXTERNAL_INCIDENT_CLOSURE=NO'
Write-Output 'TENANT_WRITES=0'
Write-Output 'EXTERNAL_INCIDENT_CLOSURE_REQUESTS=0'
Write-Output 'EXTERNAL_INCIDENT_CLOSURES=0'
