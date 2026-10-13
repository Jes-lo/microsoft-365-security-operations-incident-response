[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PlanPath,

    [Parameter(Mandatory = $true)]
    [string]$GateRequestPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $fullPath = [IO.Path]::GetFullPath($Path)

    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "$Label does not exist."
    }

    try {
        return (
            Get-Content `
                -LiteralPath $fullPath `
                -Raw `
                -Encoding UTF8 |
            ConvertFrom-Json `
                -Depth 100 `
                -ErrorAction Stop
        )
    }
    catch {
        throw "$Label is not valid JSON."
    }
}

function Assert-AllowedProperties {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string[]]$Allowed,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    foreach ($property in $Object.PSObject.Properties.Name) {
        if ($property -notin $Allowed) {
            throw "$Context contains unexpected property '$property'."
        }
    }
}

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $property = $Object.PSObject.Properties[$Name]

    if ($null -eq $property) {
        throw "$Context is missing required property '$Name'."
    }

    if ($null -eq $property.Value) {
        throw "$Context property '$Name' cannot be null."
    }

    return $property.Value
}

function Get-RequiredBoolean {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $value = Get-RequiredProperty `
        -Object $Object `
        -Name $Name `
        -Context $Context

    if ($value -isnot [bool]) {
        throw "$Context property '$Name' must be Boolean."
    }

    return [bool]$value
}

$plan = Read-JsonFile `
    -Path $PlanPath `
    -Label 'Containment and eradication plan'

$request = Read-JsonFile `
    -Path $GateRequestPath `
    -Label 'Action gate request'

Assert-AllowedProperties `
    -Object $request `
    -Allowed @(
        'schema_version',
        'feature',
        'case_id',
        'gate_scope',
        'live_execution_requested',
        'operator_authorization',
        'concrete_permission_resolution',
        'action_reviews'
    ) `
    -Context 'Action gate request'

$schemaVersion = Get-RequiredProperty `
    -Object $request `
    -Name 'schema_version' `
    -Context 'Action gate request'

$feature = Get-RequiredProperty `
    -Object $request `
    -Name 'feature' `
    -Context 'Action gate request'

$requestCaseId = [string](
    Get-RequiredProperty `
        -Object $request `
        -Name 'case_id' `
        -Context 'Action gate request'
)

$gateScope = [string](
    Get-RequiredProperty `
        -Object $request `
        -Name 'gate_scope' `
        -Context 'Action gate request'
)

$liveExecutionRequested = Get-RequiredBoolean `
    -Object $request `
    -Name 'live_execution_requested' `
    -Context 'Action gate request'

$operatorAuthorization = [string](
    Get-RequiredProperty `
        -Object $request `
        -Name 'operator_authorization' `
        -Context 'Action gate request'
)

$concretePermissionResolution = [string](
    Get-RequiredProperty `
        -Object $request `
        -Name 'concrete_permission_resolution' `
        -Context 'Action gate request'
)

$reviewsProperty = $request.PSObject.Properties['action_reviews']

if ($null -eq $reviewsProperty) {
    throw "Action gate request is missing required property 'action_reviews'."
}

if ($null -eq $reviewsProperty.Value) {
    throw "Action gate request property 'action_reviews' cannot be null."
}

if ($reviewsProperty.Value -isnot [System.Array]) {
    throw "Action gate request property 'action_reviews' must be an array."
}

$reviews = @($reviewsProperty.Value)

if ([int]$schemaVersion -ne 1) {
    throw 'Unsupported gate request schema version.'
}

if ([int]$feature -ne 8) {
    throw 'Unexpected gate request feature.'
}

if ($gateScope -ne 'LOCAL_MODEL_REVIEW_ONLY') {
    throw 'Only LOCAL_MODEL_REVIEW_ONLY gate scope is permitted.'
}

if ($liveExecutionRequested) {
    throw 'Live execution requests are prohibited by Feature 8B.'
}

if (
    $operatorAuthorization -ne 'AUTHORIZED_FOR_SEPARATE_LIVE_GATE_REVIEW'
) {
    throw 'Unsupported operator authorization value.'
}

if (
    $concretePermissionResolution -ne 'DEFERRED_TO_SEPARATE_LIVE_GATE'
) {
    throw 'Concrete permission resolution is prohibited by Feature 8B.'
}

if ([int]$plan.schema_version -ne 1) {
    throw 'Unsupported plan schema version.'
}

if ([int]$plan.feature -ne 8) {
    throw 'Unexpected plan feature.'
}

if (
    ([string]$plan.plan_type) -ne 'CONTAINMENT_ERADICATION_SIMULATION'
) {
    throw 'Unexpected plan type.'
}

if ([string]$plan.execution_mode -ne 'SIMULATION_ONLY') {
    throw 'Gate input plan must be simulation-only.'
}

if ($plan.live_execution_authorized -ne $false) {
    throw 'Gate input plan must not authorize live execution.'
}

$planCaseId = [string]$plan.case_id

if (
    $planCaseId -notmatch '^IR-[0-9]{8}-[A-Z0-9]{4,12}$' -or
    $requestCaseId -ne $planCaseId
) {
    throw 'Action gate case binding failed.'
}

$planActionsProperty = $plan.PSObject.Properties['actions']

if ($null -eq $planActionsProperty) {
    throw "Plan is missing required property 'actions'."
}

if ($null -eq $planActionsProperty.Value) {
    throw "Plan property 'actions' cannot be null."
}

if ($planActionsProperty.Value -isnot [System.Array]) {
    throw "Plan property 'actions' must be an array."
}

$planActions = @($planActionsProperty.Value)

if (
    $planActions.Count -lt 1 -or
    $planActions.Count -gt 50
) {
    throw 'Plan action count must be between 1 and 50.'
}

if ($reviews.Count -ne $planActions.Count) {
    throw 'Every plan action must have exactly one gate review.'
}

$planBySequence = @{}
$planSequences = [Collections.Generic.HashSet[int]]::new()

foreach ($planAction in $planActions) {
    $sequence = [int]$planAction.sequence

    if (
        $sequence -lt 1 -or
        $sequence -gt 50
    ) {
        throw 'Plan action sequence is outside the supported range.'
    }

    if (-not $planSequences.Add($sequence)) {
        throw 'Plan action sequences must be unique.'
    }

    if (
        ([string]$planAction.execution_status) -ne 'NOT_EXECUTED'
    ) {
        throw 'Gate input plan contains an executed action.'
    }

    if (
        ([string]$planAction.permission_resolution) -ne 'DEFERRED_TO_EXPLICIT_ACTION_GATE'
    ) {
        throw 'Gate input plan has an unexpected permission state.'
    }

    $planBySequence[$sequence] = $planAction
}

$seenReviewSequences = [Collections.Generic.HashSet[int]]::new()
$evaluatedActions = [Collections.Generic.List[object]]::new()

foreach ($review in $reviews) {
    if ($null -eq $review) {
        throw 'Action reviews cannot contain null entries.'
    }

    Assert-AllowedProperties `
        -Object $review `
        -Allowed @(
            'sequence',
            'exact_action_confirmed',
            'target_class_confirmed',
            'impact_acknowledged',
            'reversibility_acknowledged',
            'prerequisites_confirmed',
            'symbolic_capability_confirmed',
            'verification_plan_confirmed',
            'rollback_plan_confirmed',
            'evidence_handling_confirmed'
        ) `
        -Context 'Action review'

    $sequenceRaw = Get-RequiredProperty `
        -Object $review `
        -Name 'sequence' `
        -Context 'Action review'

    $sequence = 0

    $sequenceParsed = [int]::TryParse(
        [string]$sequenceRaw,
        [ref]$sequence
    )

    if (
        -not $sequenceParsed -or
        $sequence -lt 1 -or
        $sequence -gt 50
    ) {
        throw 'Action review sequence must be an integer from 1 through 50.'
    }

    if (-not $seenReviewSequences.Add($sequence)) {
        throw 'Action review sequences must be unique.'
    }

    if (-not $planBySequence.ContainsKey($sequence)) {
        throw 'Action review does not map to a plan action.'
    }

    $exactActionConfirmed = Get-RequiredBoolean `
        -Object $review `
        -Name 'exact_action_confirmed' `
        -Context 'Action review'

    $targetClassConfirmed = Get-RequiredBoolean `
        -Object $review `
        -Name 'target_class_confirmed' `
        -Context 'Action review'

    $impactAcknowledged = Get-RequiredBoolean `
        -Object $review `
        -Name 'impact_acknowledged' `
        -Context 'Action review'

    $reversibilityAcknowledged = Get-RequiredBoolean `
        -Object $review `
        -Name 'reversibility_acknowledged' `
        -Context 'Action review'

    $prerequisitesConfirmed = Get-RequiredBoolean `
        -Object $review `
        -Name 'prerequisites_confirmed' `
        -Context 'Action review'

    $symbolicCapabilityConfirmed = Get-RequiredBoolean `
        -Object $review `
        -Name 'symbolic_capability_confirmed' `
        -Context 'Action review'

    $verificationPlanConfirmed = Get-RequiredBoolean `
        -Object $review `
        -Name 'verification_plan_confirmed' `
        -Context 'Action review'

    $rollbackPlanConfirmed = Get-RequiredBoolean `
        -Object $review `
        -Name 'rollback_plan_confirmed' `
        -Context 'Action review'

    $evidenceHandlingConfirmed = Get-RequiredBoolean `
        -Object $review `
        -Name 'evidence_handling_confirmed' `
        -Context 'Action review'

    $allLocalRequirementsSatisfied = (
        $exactActionConfirmed -and
        $targetClassConfirmed -and
        $impactAcknowledged -and
        $reversibilityAcknowledged -and
        $prerequisitesConfirmed -and
        $symbolicCapabilityConfirmed -and
        $verificationPlanConfirmed -and
        $rollbackPlanConfirmed -and
        $evidenceHandlingConfirmed
    )

    $gateStatus = if ($allLocalRequirementsSatisfied) {
        'READY_FOR_SEPARATE_LIVE_GATE_REVIEW'
    }
    else {
        'BLOCKED'
    }

    $planAction = $planBySequence[$sequence]

    $evaluatedActions.Add(
        [pscustomobject][ordered]@{
            sequence = $sequence
            action_type = [string]$planAction.action_type
            phase = [string]$planAction.phase
            target_class = [string]$planAction.target_class
            target_alias = [string]$planAction.target_alias
            impact = [string]$planAction.impact
            reversibility = [string]$planAction.reversibility
            required_live_capability = [string]$planAction.required_live_capability
            gate_status = $gateStatus
            exact_action_confirmed = $exactActionConfirmed
            target_class_confirmed = $targetClassConfirmed
            impact_acknowledged = $impactAcknowledged
            reversibility_acknowledged = $reversibilityAcknowledged
            prerequisites_confirmed = $prerequisitesConfirmed
            symbolic_capability_confirmed = $symbolicCapabilityConfirmed
            verification_plan_confirmed = $verificationPlanConfirmed
            rollback_plan_confirmed = $rollbackPlanConfirmed
            evidence_handling_confirmed = $evidenceHandlingConfirmed
            concrete_permission_resolution = 'DEFERRED_TO_SEPARATE_LIVE_GATE'
            execution_release = 'NOT_RELEASED'
            execution_status = 'NOT_EXECUTED'
        }
    )
}

$orderedActions = @(
    $evaluatedActions |
    Sort-Object sequence
)

$readyCount = @(
    $orderedActions |
    Where-Object {
        $_.gate_status -eq 'READY_FOR_SEPARATE_LIVE_GATE_REVIEW'
    }
).Count

$blockedCount = @(
    $orderedActions |
    Where-Object {
        $_.gate_status -eq 'BLOCKED'
    }
).Count

$overallGateStatus = if ($blockedCount -eq 0) {
    'READY_FOR_SEPARATE_LIVE_GATE_REVIEW'
}
else {
    'BLOCKED'
}

$output = [ordered]@{
    schema_version = 1
    feature = 8
    case_id = $planCaseId
    gate_type = 'EXPLICIT_RESPONSE_ACTION_GATE_MODEL'
    gate_scope = 'LOCAL_MODEL_REVIEW_ONLY'
    deterministic_output = $true

    operator_authorization = [ordered]@{
        decision = 'AUTHORIZED_FOR_SEPARATE_LIVE_GATE_REVIEW'
        scope = 'SEPARATE_LIVE_GATE_REVIEW_ONLY'
        authorizes_live_execution = $false
        authorizes_permission_grant = $false
        authorizes_role_assignment = $false
        authorizes_tenant_write = $false
        authorizes_endpoint_action = $false
    }

    decision = [ordered]@{
        gate_status = $overallGateStatus
        execution_release = 'NOT_RELEASED'
        live_execution_available = $false
        concrete_permission_resolution = 'DEFERRED_TO_SEPARATE_LIVE_GATE'
    }

    counts = [ordered]@{
        reviewed_actions = $orderedActions.Count
        ready_for_separate_live_gate_review = $readyCount
        blocked_actions = $blockedCount
        executed_actions = 0
        graph_requests = 0
        tenant_reads = 0
        tenant_writes = 0
        endpoint_actions = 0
        response_actions = 0
        new_permission_grants = 0
        role_assignments = 0
        trial_activations = 0
    }

    safety_boundary = [ordered]@{
        graph_authentication_required = $false
        graph_requests = 0
        tenant_reads = 0
        tenant_writes = 0
        endpoint_actions = 0
        response_actions = 0
        new_permission_grants = 0
        role_assignments = 0
        trial_activations = 0
        live_execution_release = $false
        destructive_action_default = 'DENY'
    }

    privacy = [ordered]@{
        controlled_aliases_only = $true
        raw_identifiers_retained = $false
        raw_network_indicators_retained = $false
        raw_credentials_retained = $false
        raw_tokens_retained = $false
        free_form_authorization_text_retained = $false
    }

    actions = $orderedActions
}

$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$outputParent = Split-Path -Parent $outputFullPath

if (-not (Test-Path -LiteralPath $outputParent)) {
    New-Item `
        -ItemType Directory `
        -Path $outputParent `
        -Force |
        Out-Null
}

$utf8NoBom = [Text.UTF8Encoding]::new($false)

[IO.File]::WriteAllText(
    $outputFullPath,
    (
        $output |
        ConvertTo-Json -Depth 32
    ) + [Environment]::NewLine,
    $utf8NoBom
)

Write-Output 'CONTAINMENT_ERADICATION_ACTION_GATE=PASS'
Write-Output "GATE_STATUS=$overallGateStatus"
Write-Output 'GATE_SCOPE=LOCAL_MODEL_REVIEW_ONLY'
Write-Output 'LIVE_EXECUTION_RELEASE=NO'
Write-Output 'CONCRETE_PERMISSION_RESOLUTION=DEFERRED'
Write-Output 'GRAPH_AUTHENTICATION=NOT_REQUIRED'
Write-Output 'GRAPH_REQUESTS=0'
Write-Output 'TENANT_READS=0'
Write-Output 'TENANT_WRITES=0'
Write-Output 'ENDPOINT_ACTIONS=0'
Write-Output 'RESPONSE_ACTIONS=0'
Write-Output 'NEW_PERMISSION_GRANTS=0'
Write-Output 'ROLE_ASSIGNMENTS=0'
Write-Output 'TRIAL_ACTIVATIONS=0'
