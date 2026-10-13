[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CasePath,

    [Parameter(Mandatory = $true)]
    [string]$RequestPath,

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

function Assert-SafeAlias {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Alias,

        [Parameter(Mandatory = $true)]
        [string]$TargetClass
    )

    $patterns = @{
        SUBJECT = '^SUBJECT-[0-9]{3}$'
        APPLICATION = '^APP-[0-9]{3}$'
        DEVICE = '^DEVICE-[0-9]{3}$'
        FILE = '^FILE-[0-9]{3}$'
    }

    if (-not $patterns.ContainsKey($TargetClass)) {
        throw 'Unsupported target class.'
    }

    if ($Alias -notmatch $patterns[$TargetClass]) {
        throw 'Target alias does not match the required sanitized alias format.'
    }
}

$caseRoot = [IO.Path]::GetFullPath($CasePath)
$caseFile = Join-Path $caseRoot 'case.json'

if (-not (Test-Path -LiteralPath $caseFile -PathType Leaf)) {
    throw 'Incident case metadata is missing.'
}

$case = Read-JsonFile `
    -Path $caseFile `
    -Label 'Incident case'

$request = Read-JsonFile `
    -Path $RequestPath `
    -Label 'Containment request'

Assert-AllowedProperties `
    -Object $request `
    -Allowed @(
        'schema_version',
        'feature',
        'case_id',
        'execution_mode',
        'live_execution_authorized',
        'actions'
    ) `
    -Context 'Containment request'

$schemaVersion = Get-RequiredProperty `
    -Object $request `
    -Name 'schema_version' `
    -Context 'Containment request'

$feature = Get-RequiredProperty `
    -Object $request `
    -Name 'feature' `
    -Context 'Containment request'

$requestCaseId = [string](
    Get-RequiredProperty `
        -Object $request `
        -Name 'case_id' `
        -Context 'Containment request'
)

$executionMode = [string](
    Get-RequiredProperty `
        -Object $request `
        -Name 'execution_mode' `
        -Context 'Containment request'
)

$liveExecutionAuthorized = Get-RequiredProperty `
    -Object $request `
    -Name 'live_execution_authorized' `
    -Context 'Containment request'

$actionsProperty = $request.PSObject.Properties['actions']

if ($null -eq $actionsProperty) {
    throw "Containment request is missing required property 'actions'."
}

if ($null -eq $actionsProperty.Value) {
    throw "Containment request property 'actions' cannot be null."
}

if ($actionsProperty.Value -isnot [System.Array]) {
    throw "Containment request property 'actions' must be an array."
}

$actions = @($actionsProperty.Value)

if ([int]$schemaVersion -ne 1) {
    throw 'Unsupported request schema version.'
}

if ([int]$feature -ne 8) {
    throw 'Unexpected request feature.'
}

$caseId = [string]$case.case_id

if (
    $requestCaseId -notmatch '^IR-[0-9]{8}-[A-Z0-9]{4,12}$' -or
    $caseId -ne $requestCaseId
) {
    throw 'Request case binding failed.'
}

if ($executionMode -ne 'SIMULATION_ONLY') {
    throw 'Only SIMULATION_ONLY execution mode is permitted.'
}

if ($liveExecutionAuthorized -isnot [bool]) {
    throw 'live_execution_authorized must be Boolean.'
}

if ($liveExecutionAuthorized) {
    throw 'Live execution authorization is prohibited by this foundation.'
}

if ($actions.Count -lt 1 -or $actions.Count -gt 50) {
    throw 'Action count must be between 1 and 50.'
}

$reasonCategories = @(
    'SUSPECTED_ACCOUNT_COMPROMISE',
    'MALICIOUS_APPLICATION_ACTIVITY',
    'OAUTH_ABUSE',
    'ENDPOINT_COMPROMISE',
    'MALICIOUS_FILE_ACTIVITY',
    'CREDENTIAL_EXPOSURE',
    'POLICY_VIOLATION',
    'OTHER_SANITIZED'
)

$catalog = @{
    SUBJECT_REVOKE_SESSIONS = [ordered]@{
        phase = 'CONTAINMENT'
        target_class = 'SUBJECT'
        impact = 'HIGH'
        reversibility = 'LIMITED'
        required_live_capability = 'IDENTITY_SESSION_CONTROL_WRITE'
    }

    SUBJECT_BLOCK_SIGN_IN = [ordered]@{
        phase = 'CONTAINMENT'
        target_class = 'SUBJECT'
        impact = 'HIGH'
        reversibility = 'REVERSIBLE'
        required_live_capability = 'IDENTITY_ACCOUNT_CONTROL_WRITE'
    }

    APPLICATION_DISABLE_ACCESS = [ordered]@{
        phase = 'CONTAINMENT'
        target_class = 'APPLICATION'
        impact = 'HIGH'
        reversibility = 'REVERSIBLE'
        required_live_capability = 'APPLICATION_CONTROL_WRITE'
    }

    DEVICE_ISOLATE = [ordered]@{
        phase = 'CONTAINMENT'
        target_class = 'DEVICE'
        impact = 'HIGH'
        reversibility = 'REVERSIBLE'
        required_live_capability = 'ENDPOINT_RESPONSE_CONTROL'
    }

    OAUTH_GRANT_REMOVE = [ordered]@{
        phase = 'ERADICATION'
        target_class = 'APPLICATION'
        impact = 'HIGH'
        reversibility = 'LIMITED'
        required_live_capability = 'OAUTH_PERMISSION_CONTROL_WRITE'
    }

    APPLICATION_CREDENTIAL_REMEDIATE = [ordered]@{
        phase = 'ERADICATION'
        target_class = 'APPLICATION'
        impact = 'CRITICAL'
        reversibility = 'LIMITED'
        required_live_capability = 'APPLICATION_CREDENTIAL_CONTROL_WRITE'
    }

    SUBJECT_CREDENTIAL_RESET = [ordered]@{
        phase = 'ERADICATION'
        target_class = 'SUBJECT'
        impact = 'HIGH'
        reversibility = 'LIMITED'
        required_live_capability = 'IDENTITY_CREDENTIAL_CONTROL_WRITE'
    }

    FILE_QUARANTINE = [ordered]@{
        phase = 'ERADICATION'
        target_class = 'FILE'
        impact = 'HIGH'
        reversibility = 'REVERSIBLE'
        required_live_capability = 'ENDPOINT_FILE_RESPONSE_CONTROL'
    }
}

$seenSequences = [Collections.Generic.HashSet[int]]::new()
$seenActionTargets = [Collections.Generic.HashSet[string]]::new()
$normalized = [Collections.Generic.List[object]]::new()

foreach ($action in $actions) {
    if ($null -eq $action) {
        throw 'Action entries cannot be null.'
    }

    Assert-AllowedProperties `
        -Object $action `
        -Allowed @(
            'sequence',
            'action_type',
            'target_alias',
            'reason_category'
        ) `
        -Context 'Action'

    $sequenceRaw = Get-RequiredProperty `
        -Object $action `
        -Name 'sequence' `
        -Context 'Action'

    $sequence = 0

    if (
        -not [int]::TryParse(
            [string]$sequenceRaw,
            [ref]$sequence
        ) -or
        $sequence -lt 1 -or
        $sequence -gt 50
    ) {
        throw 'Action sequence must be an integer from 1 through 50.'
    }

    if (-not $seenSequences.Add($sequence)) {
        throw 'Action sequences must be unique.'
    }

    $actionType = [string](
        Get-RequiredProperty `
            -Object $action `
            -Name 'action_type' `
            -Context 'Action'
    )

    if (-not $catalog.ContainsKey($actionType)) {
        throw 'Unsupported action type.'
    }

    $targetAlias = [string](
        Get-RequiredProperty `
            -Object $action `
            -Name 'target_alias' `
            -Context 'Action'
    )

    $reasonCategory = [string](
        Get-RequiredProperty `
            -Object $action `
            -Name 'reason_category' `
            -Context 'Action'
    )

    if ($reasonCategory -notin $reasonCategories) {
        throw 'Unsupported reason category.'
    }

    $metadata = $catalog[$actionType]

    Assert-SafeAlias `
        -Alias $targetAlias `
        -TargetClass $metadata.target_class

    $actionTargetKey = (
        $actionType +
        '|' +
        $targetAlias
    )

    if (-not $seenActionTargets.Add($actionTargetKey)) {
        throw 'Duplicate action and target combination.'
    }

    $normalized.Add(
        [pscustomobject][ordered]@{
            sequence = $sequence
            action_type = $actionType
            phase = $metadata.phase
            target_class = $metadata.target_class
            target_alias = $targetAlias
            reason_category = $reasonCategory
            impact = $metadata.impact
            reversibility = $metadata.reversibility
            required_live_capability = $metadata.required_live_capability
            permission_resolution = 'DEFERRED_TO_EXPLICIT_ACTION_GATE'
            approval_status = 'NOT_REQUESTED'
            execution_status = 'NOT_EXECUTED'
            verification_requirement = 'REQUIRED_BEFORE_ANY_LIVE_ACTION'
            rollback_requirement = 'REQUIRED_BEFORE_ANY_LIVE_ACTION'
            evidence_requirement = 'SANITIZED_FEATURE_3_COMPATIBLE'
        }
    )
}

$orderedActions = @(
    $normalized |
    Sort-Object sequence
)

for ($index = 0; $index -lt $orderedActions.Count; $index++) {
    $expectedSequence = $index + 1

    if ($orderedActions[$index].sequence -ne $expectedSequence) {
        throw 'Action sequences must be contiguous and start at 1.'
    }
}

$containmentCount = @(
    $orderedActions |
    Where-Object {
        $_.phase -eq 'CONTAINMENT'
    }
).Count

$eradicationCount = @(
    $orderedActions |
    Where-Object {
        $_.phase -eq 'ERADICATION'
    }
).Count

$output = [ordered]@{
    schema_version = 1
    feature = 8
    case_id = $caseId
    plan_type = 'CONTAINMENT_ERADICATION_SIMULATION'
    execution_mode = 'SIMULATION_ONLY'
    live_execution_authorized = $false
    deterministic_output = $true

    counts = [ordered]@{
        planned_actions = $orderedActions.Count
        containment_actions = $containmentCount
        eradication_actions = $eradicationCount
        executed_actions = 0
        tenant_writes = 0
        endpoint_actions = 0
        response_actions = 0
        graph_requests = 0
    }

    action_gate = [ordered]@{
        status = 'NOT_PASSED'
        explicit_operator_authorization = $false
        current_permission_resolution = 'NOT_PERFORMED'
        verification_plan_confirmed = $false
        rollback_plan_confirmed = $false
        live_execution_available = $false

        required_before_live_execution = @(
            'EXACT_ACTION',
            'TARGET_CLASS',
            'IMPACT',
            'REVERSIBILITY',
            'PREREQUISITES',
            'CURRENT_PERMISSION_RESOLUTION',
            'VERIFICATION_PLAN',
            'ROLLBACK_PLAN',
            'EVIDENCE_HANDLING',
            'EXPLICIT_OPERATOR_AUTHORIZATION'
        )
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
        destructive_action_default = 'DENY'
        live_response_action_default = 'DENY'
    }

    privacy = [ordered]@{
        controlled_aliases_only = $true
        controlled_reason_categories_only = $true
        raw_tenant_identifiers_retained = $false
        raw_user_identifiers_retained = $false
        raw_application_identifiers_retained = $false
        raw_device_identifiers_retained = $false
        raw_file_identifiers_retained = $false
        raw_network_indicators_retained = $false
        raw_credentials_retained = $false
        raw_tokens_retained = $false
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

Write-Output 'CONTAINMENT_ERADICATION_PLAN=PASS'
Write-Output 'EXECUTION_MODE=SIMULATION_ONLY'
Write-Output 'LIVE_EXECUTION_AUTHORIZED=NO'
Write-Output 'GRAPH_AUTHENTICATION=NOT_REQUIRED'
Write-Output 'GRAPH_REQUESTS=0'
Write-Output 'TENANT_READS=0'
Write-Output 'TENANT_WRITES=0'
Write-Output 'ENDPOINT_ACTIONS=0'
Write-Output 'RESPONSE_ACTIONS=0'
Write-Output 'NEW_PERMISSION_GRANTS=0'
Write-Output 'ROLE_ASSIGNMENTS=0'
Write-Output 'TRIAL_ACTIVATIONS=0'
Write-Output 'ACTION_GATE_STATUS=NOT_PASSED'
