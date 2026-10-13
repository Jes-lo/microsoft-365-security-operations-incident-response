#!/usr/bin/env pwsh

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DesignPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GateRequestPath,

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

    $actualNames = @(
        $Object.PSObject.Properties.Name |
            Sort-Object
    )

    $expectedNames = @(
        $Expected |
            Sort-Object
    )

    if (
        ($actualNames -join "`n") -ne
        ($expectedNames -join "`n")
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

foreach ($requiredPath in @(
    $DesignPath,
    $GateRequestPath
)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        Fail-Closed "Required input file is missing."
    }
}

$design = Get-Content `
    -LiteralPath $DesignPath `
    -Raw `
    -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

$request = Get-Content `
    -LiteralPath $GateRequestPath `
    -Raw `
    -Encoding UTF8 |
    ConvertFrom-Json -Depth 100

Assert-ExactProperties `
    -Object $request `
    -Expected @(
        'schema_version',
        'feature',
        'design_sha256',
        'gate_scope',
        'live_provisioning_requested',
        'operator_authorization',
        'principal_reviews'
    ) `
    -Context 'Gate request'

if ([int]$request.schema_version -ne 1) {
    Fail-Closed 'Unsupported gate request schema version.'
}

if ([int]$request.feature -ne 8) {
    Fail-Closed 'Gate request feature mismatch.'
}

if (
    [string]$request.gate_scope -ne
    'LOCAL_PROVISIONING_AUTHORIZATION_REVIEW_ONLY'
) {
    Fail-Closed 'Unsupported gate scope.'
}

Assert-Boolean `
    -Value $request.live_provisioning_requested `
    -Context 'live_provisioning_requested'

if ([bool]$request.live_provisioning_requested) {
    Fail-Closed 'Live provisioning requests are prohibited by Feature 8E.'
}

if (
    [string]$request.operator_authorization -ne
    'AUTHORIZED_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW'
) {
    Fail-Closed 'Operator authorization value is not allowed.'
}

if ([string]$design.phase -ne 'SEPARATE_RESPONSE_PRINCIPAL_DESIGN_COMPLETE') {
    Fail-Closed 'Input design is not the completed Feature 8D design.'
}

if ([string]$design.mode -ne 'LOCAL_ARCHITECTURE_ONLY') {
    Fail-Closed 'Feature 8D design mode is not fail-closed.'
}

if ([int]$design.principal_topology.principal_count -ne 3) {
    Fail-Closed 'Feature 8D design must contain exactly three principals.'
}

if ([bool]$design.investigation_principal_boundary.reuse_for_response) {
    Fail-Closed 'Investigation principal reuse is prohibited.'
}

if ([bool]$design.credential_policy.production_client_secret_allowed) {
    Fail-Closed 'Production client secrets are prohibited.'
}

if ([bool]$design.safety_boundary.live_execution_release) {
    Fail-Closed 'Feature 8D design unexpectedly releases execution.'
}

$actualDesignHash = (
    Get-FileHash `
        -LiteralPath $DesignPath `
        -Algorithm SHA256
).Hash.ToLowerInvariant()

$requestedHash = (
    [string]$request.design_sha256
).ToLowerInvariant()

if ($requestedHash -notmatch '^[0-9a-f]{64}$') {
    Fail-Closed 'design_sha256 must be a lowercase or uppercase SHA-256 hexadecimal digest.'
}

if ($requestedHash -ne $actualDesignHash) {
    Fail-Closed 'Gate request is not bound to the exact Feature 8D design.'
}

$expectedAliases = @(
    'RESP-DEFENDER-ENDPOINT-001',
    'RESP-GRAPH-APPLICATION-001',
    'RESP-GRAPH-IDENTITY-001'
)

$reviews = @($request.principal_reviews)

if ($reviews.Count -ne 3) {
    Fail-Closed 'Exactly three principal reviews are required.'
}

$reviewProperties = @(
    'principal_alias',
    'exact_principal_confirmed',
    'exact_response_domain_confirmed',
    'exact_permission_candidates_reviewed',
    'role_requirements_reviewed',
    'tenant_capability_reviewed',
    'license_requirements_reviewed',
    'credential_method_reviewed',
    'admin_consent_impact_reviewed',
    'verification_plan_reviewed',
    'rollback_plan_reviewed'
)

$seenAliases = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal
)

$resultReviews = [System.Collections.Generic.List[object]]::new()

foreach ($review in $reviews) {
    Assert-ExactProperties `
        -Object $review `
        -Expected $reviewProperties `
        -Context 'Principal review'

    $alias = [string]$review.principal_alias

    if ($alias -notin $expectedAliases) {
        Fail-Closed 'Unknown response principal alias.'
    }

    if (-not $seenAliases.Add($alias)) {
        Fail-Closed 'Duplicate response principal review.'
    }

    $booleanNames = @(
        'exact_principal_confirmed',
        'exact_response_domain_confirmed',
        'exact_permission_candidates_reviewed',
        'role_requirements_reviewed',
        'tenant_capability_reviewed',
        'license_requirements_reviewed',
        'credential_method_reviewed',
        'admin_consent_impact_reviewed',
        'verification_plan_reviewed',
        'rollback_plan_reviewed'
    )

    foreach ($booleanName in $booleanNames) {
        Assert-Boolean `
            -Value $review.$booleanName `
            -Context "$alias.$booleanName"
    }

    $allSatisfied = $true

    foreach ($booleanName in $booleanNames) {
        if (-not [bool]$review.$booleanName) {
            $allSatisfied = $false
        }
    }

    $principalStatus = if ($allSatisfied) {
        'READY_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW'
    }
    else {
        'BLOCKED'
    }

    $resultReviews.Add(
        [pscustomobject][ordered]@{
            principal_alias = $alias
            review_status = $principalStatus
            provisioning_release = 'NOT_RELEASED'
            app_registration_created = $false
            service_principal_created = $false
            credential_created = $false
            permission_granted = $false
            role_assigned = $false
            admin_consent_granted = $false
            live_authentication_performed = $false
        }
    )
}

if ($seenAliases.Count -ne $expectedAliases.Count) {
    Fail-Closed 'One or more required principal reviews are missing.'
}

$sortedResults = @(
    $resultReviews |
        Sort-Object principal_alias
)

$blockedCount = @(
    $sortedResults |
        Where-Object {
            $_.review_status -eq 'BLOCKED'
        }
).Count

$gateStatus = if ($blockedCount -eq 0) {
    'READY_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW'
}
else {
    'BLOCKED'
}

$output = [ordered]@{
    schema_version = 1
    feature = 8
    gate_scope = 'LOCAL_PROVISIONING_AUTHORIZATION_REVIEW_ONLY'
    design_sha256 = $actualDesignHash
    operator_authorization = 'AUTHORIZED_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW'
    gate_status = $gateStatus
    provisioning_release = 'NOT_RELEASED'
    ready_status_authorizes_provisioning = $false
    principal_reviews = $sortedResults
    safety_boundary = [ordered]@{
        app_registrations_created = 0
        service_principals_created = 0
        credentials_created = 0
        graph_authentication = 'NOT_PERFORMED'
        graph_requests = 0
        defender_api_authentication = 'NOT_PERFORMED'
        defender_api_requests = 0
        tenant_reads = 0
        tenant_writes = 0
        endpoint_actions = 0
        response_actions = 0
        permission_grants = 0
        role_assignments = 0
        admin_consents = 0
        trial_activations = 0
        current_read_only_app_mutated = $false
        live_provisioning_available = $false
        provisioning_release = $false
    }
}

$json = $output |
    ConvertTo-Json `
        -Depth 100

[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath($OutputPath),
    $json + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output 'RESPONSE_PRINCIPAL_PROVISIONING_AUTHORIZATION_GATE=PASS'
Write-Output "GATE_STATUS=$gateStatus"
Write-Output 'GATE_SCOPE=LOCAL_PROVISIONING_AUTHORIZATION_REVIEW_ONLY'
Write-Output 'DESIGN_SHA256_BINDING=PASS'
Write-Output 'READY_STATUS_AUTHORIZES_PROVISIONING=NO'
Write-Output 'PROVISIONING_RELEASE=NOT_RELEASED'
Write-Output 'APP_REGISTRATIONS_CREATED=0'
Write-Output 'SERVICE_PRINCIPALS_CREATED=0'
Write-Output 'CREDENTIALS_CREATED=0'
Write-Output 'PERMISSION_GRANTS=0'
Write-Output 'ROLE_ASSIGNMENTS=0'
Write-Output 'ADMIN_CONSENTS=0'
Write-Output 'GRAPH_AUTHENTICATION=NOT_PERFORMED'
Write-Output 'GRAPH_REQUESTS=0'
Write-Output 'DEFENDER_API_AUTHENTICATION=NOT_PERFORMED'
Write-Output 'DEFENDER_API_REQUESTS=0'
Write-Output 'TENANT_WRITES=0'
Write-Output 'RESPONSE_ACTIONS=0'
