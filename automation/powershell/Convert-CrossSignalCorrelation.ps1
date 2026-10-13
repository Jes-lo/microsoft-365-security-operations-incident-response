[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CasePath,

    [Parameter(Mandatory = $true)]
    [string]$IdentitySummaryPath,

    [Parameter(Mandatory = $true)]
    [string]$ApplicationSummaryPath,

    [Parameter(Mandatory = $true)]
    [string]$EndpointSummaryPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [string]$BindingsPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PropertyValue {
    param(
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return $null
    }

    return $property.Value
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

    $value = Get-PropertyValue `
        -Object $Object `
        -Name $Name

    if ($null -eq $value) {
        throw "$Context is missing required property '$Name'."
    }

    return $value
}

function Read-JsonDocument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $fullPath = [IO.Path]::GetFullPath($Path)

    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "$Label file does not exist."
    }

    try {
        return (
            Get-Content `
                -LiteralPath $fullPath `
                -Raw `
                -Encoding UTF8 |
            ConvertFrom-Json
        )
    }
    catch {
        throw "$Label JSON could not be parsed safely."
    }
}

function ConvertTo-NormalizedUtcTimestamp {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    if ($null -eq $Value) {
        throw 'Timeline event timestamp is missing.'
    }

    $parsed = [DateTimeOffset]::MinValue

    $styles = (
        [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    )

    if (
        -not [DateTimeOffset]::TryParse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            $styles,
            [ref]$parsed
        )
    ) {
        throw 'Timeline event timestamp could not be normalized safely.'
    }

    return $parsed.UtcDateTime.ToString(
        'yyyy-MM-ddTHH:mm:ss.fffffffZ',
        [Globalization.CultureInfo]::InvariantCulture
    )
}

function Test-SensitiveCategoryValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $patterns = @(
        '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
        '(?i)\b(?:https?|ftp)://',
        '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        '(?i)(?<!\d)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}(?!\d)',
        '(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b',
        '(?i)\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b',
        '(?i)\b[A-Z]:\\',
        '(?i)(?:^|[\s])/(?:[^/\s]+/)+[^/\s]*',
        '(?i)\bBearer[ \t]+[A-Za-z0-9._~-]+',
        '-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----'
    )

    foreach ($pattern in $patterns) {
        if ($Value -match $pattern) {
            return $true
        }
    }

    return $false
}

function ConvertTo-SafeCategory {
    param(
        [AllowNull()]
        [object]$Value,

        [string]$Fallback = 'UNKNOWN'
    )

    if ($null -eq $Value) {
        return $Fallback
    }

    $text = ([string]$Value).Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $Fallback
    }

    if (
        $text.Length -gt 80 -or
        $text -match '[\x00-\x1F\x7F]' -or
        (
            Test-SensitiveCategoryValue `
                -Value $text
        )
    ) {
        return 'REDACTED_CATEGORY'
    }

    return $text
}

function Assert-BooleanFalse {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Property,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $value = Get-RequiredProperty `
        -Object $Object `
        -Name $Property `
        -Context $Context

    if ([bool]$value) {
        throw "$Context violates privacy boundary '$Property'."
    }
}

function Test-NumberedAlias {
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    if ($null -eq $Value) {
        return $false
    }

    return (
        [string]$Value -match (
            '^' +
            [regex]::Escape($Prefix) +
            '-[0-9]{3}$'
        )
    )
}

function Test-LocalAlias {
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    if ($null -eq $Value) {
        return $false
    }

    $text = [string]$Value

    return (
        $text -eq "$Prefix-UNKNOWN" -or
        (
            Test-NumberedAlias `
                -Value $text `
                -Prefix $Prefix
        )
    )
}

function Assert-LocalAlias {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if (
        -not (
            Test-LocalAlias `
                -Value $Value `
                -Prefix $Prefix
        )
    ) {
        throw "$Context contains malformed $Prefix alias."
    }

    return [string]$Value
}

$caseDocument = Read-JsonDocument `
    -Path (Join-Path $CasePath 'case.json') `
    -Label 'Incident case'

$caseId = [string](
    Get-RequiredProperty `
        -Object $caseDocument `
        -Name 'case_id' `
        -Context 'Incident case'
)

if ($caseId -notmatch '^IR-[0-9]{8}-[A-Z0-9]{4,12}$') {
    throw 'Incident case ID is invalid.'
}

$identity = Read-JsonDocument `
    -Path $IdentitySummaryPath `
    -Label 'Identity summary'

$application = Read-JsonDocument `
    -Path $ApplicationSummaryPath `
    -Label 'Application summary'

$endpoint = Read-JsonDocument `
    -Path $EndpointSummaryPath `
    -Label 'Endpoint summary'

if (
    [int](
        Get-RequiredProperty `
            -Object $identity `
            -Name 'schema_version' `
            -Context 'Identity summary'
    ) -ne 1
) {
    throw 'Unsupported identity summary schema.'
}

if (
    [string](
        Get-RequiredProperty `
            -Object $identity `
            -Name 'case_id' `
            -Context 'Identity summary'
    ) -ne $caseId
) {
    throw 'Identity summary case ID does not match incident case.'
}

if (
    [string](
        Get-RequiredProperty `
            -Object $identity `
            -Name 'investigation_type' `
            -Context 'Identity summary'
    ) -ne 'IDENTITY_SECURITY'
) {
    throw 'Unexpected identity investigation type.'
}

if (
    [string](
        Get-RequiredProperty `
            -Object $identity `
            -Name 'privacy_mode' `
            -Context 'Identity summary'
    ) -ne 'SUBJECT_ALIAS_ONLY'
) {
    throw 'Identity summary privacy mode is unsafe.'
}

Assert-BooleanFalse `
    -Object $identity `
    -Property 'raw_identifiers_retained' `
    -Context 'Identity summary'

Assert-BooleanFalse `
    -Object $identity `
    -Property 'raw_graph_payload_retained' `
    -Context 'Identity summary'

if (
    [int](
        Get-RequiredProperty `
            -Object $application `
            -Name 'schema_version' `
            -Context 'Application summary'
    ) -ne 1
) {
    throw 'Unsupported application summary schema.'
}

if (
    [int](
        Get-RequiredProperty `
            -Object $application `
            -Name 'feature' `
            -Context 'Application summary'
    ) -ne 5
) {
    throw 'Unexpected application summary feature.'
}

if (
    [string](
        Get-RequiredProperty `
            -Object $application `
            -Name 'case_id' `
            -Context 'Application summary'
    ) -ne $caseId
) {
    throw 'Application summary case ID does not match incident case.'
}

if (
    [string](
        Get-RequiredProperty `
            -Object $application `
            -Name 'investigation_type' `
            -Context 'Application summary'
    ) -ne 'ENTERPRISE_APPLICATION_OAUTH'
) {
    throw 'Unexpected application investigation type.'
}

$applicationPrivacy = Get-RequiredProperty `
    -Object $application `
    -Name 'privacy' `
    -Context 'Application summary'

foreach (
    $field in @(
        'raw_application_ids_retained',
        'raw_service_principal_ids_retained',
        'raw_user_ids_retained',
        'raw_upns_retained',
        'raw_ip_addresses_retained',
        'raw_grant_values_retained',
        'raw_graph_payloads_retained'
    )
) {
    Assert-BooleanFalse `
        -Object $applicationPrivacy `
        -Property $field `
        -Context 'Application summary'
}

if (
    [int](
        Get-RequiredProperty `
            -Object $endpoint `
            -Name 'schema_version' `
            -Context 'Endpoint summary'
    ) -ne 1
) {
    throw 'Unsupported endpoint summary schema.'
}

if (
    [int](
        Get-RequiredProperty `
            -Object $endpoint `
            -Name 'feature' `
            -Context 'Endpoint summary'
    ) -ne 6
) {
    throw 'Unexpected endpoint summary feature.'
}

if (
    [string](
        Get-RequiredProperty `
            -Object $endpoint `
            -Name 'case_id' `
            -Context 'Endpoint summary'
    ) -ne $caseId
) {
    throw 'Endpoint summary case ID does not match incident case.'
}

if (
    [string](
        Get-RequiredProperty `
            -Object $endpoint `
            -Name 'investigation_type' `
            -Context 'Endpoint summary'
    ) -ne 'ENDPOINT_SECURITY'
) {
    throw 'Unexpected endpoint investigation type.'
}

$endpointBoundary = Get-RequiredProperty `
    -Object $endpoint `
    -Name 'investigation_boundary' `
    -Context 'Endpoint summary'

Assert-BooleanFalse `
    -Object $endpointBoundary `
    -Property 'endpoint_response_action' `
    -Context 'Endpoint summary'

Assert-BooleanFalse `
    -Object $endpointBoundary `
    -Property 'tenant_remediation_execution' `
    -Context 'Endpoint summary'

$endpointPrivacy = Get-RequiredProperty `
    -Object $endpoint `
    -Name 'privacy' `
    -Context 'Endpoint summary'

foreach (
    $field in @(
        'raw_alert_ids_retained',
        'raw_incident_ids_retained',
        'raw_device_ids_retained',
        'raw_device_names_retained',
        'raw_user_ids_retained',
        'raw_upns_retained',
        'raw_ip_addresses_retained',
        'raw_mac_addresses_retained',
        'raw_file_names_retained',
        'raw_file_paths_retained',
        'raw_file_hashes_retained',
        'raw_urls_retained',
        'raw_titles_or_descriptions_retained',
        'raw_graph_payloads_retained'
    )
) {
    Assert-BooleanFalse `
        -Object $endpointPrivacy `
        -Property $field `
        -Context 'Endpoint summary'
}

$identitySignIns = @(
    Get-RequiredProperty `
        -Object $identity `
        -Name 'sign_ins' `
        -Context 'Identity summary'
)

$identityAudits = @(
    Get-RequiredProperty `
        -Object $identity `
        -Name 'directory_audits' `
        -Context 'Identity summary'
)

$identityRisks = @(
    Get-RequiredProperty `
        -Object $identity `
        -Name 'risk_detections' `
        -Context 'Identity summary'
)

$applicationSignIns = @(
    Get-RequiredProperty `
        -Object $application `
        -Name 'sign_ins' `
        -Context 'Application summary'
)

$applicationAudits = @(
    Get-RequiredProperty `
        -Object $application `
        -Name 'directory_audits' `
        -Context 'Application summary'
)

$endpointIncidents = @(
    Get-RequiredProperty `
        -Object $endpoint `
        -Name 'incidents' `
        -Context 'Endpoint summary'
)

$endpointAlerts = @(
    Get-RequiredProperty `
        -Object $endpoint `
        -Name 'alerts' `
        -Context 'Endpoint summary'
)

$knownSubjects = @{
    IDENTITY = @{}
    APPLICATION = @{}
    ENDPOINT = @{}
}

function Add-KnownSubject {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('IDENTITY', 'APPLICATION', 'ENDPOINT')]
        [string]$Domain,

        [AllowNull()]
        [object]$Alias
    )

    if ($null -eq $Alias) {
        return
    }

    $text = [string]$Alias

    if ($text -eq 'SUBJECT-UNKNOWN') {
        return
    }

    if (
        -not (
            Test-NumberedAlias `
                -Value $text `
                -Prefix 'SUBJECT'
        )
    ) {
        throw "Malformed subject alias in $Domain sanitized input."
    }

    $knownSubjects[$Domain][$text] = $true
}

foreach ($entry in $identitySignIns) {
    if ($null -eq $entry) {
        continue
    }

    Add-KnownSubject `
        -Domain 'IDENTITY' `
        -Alias (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'subject_alias' `
                -Context 'Identity sign-in'
        )
}

foreach ($entry in $identityAudits) {
    if ($null -eq $entry) {
        continue
    }

    Add-KnownSubject `
        -Domain 'IDENTITY' `
        -Alias (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'actor_alias' `
                -Context 'Identity directory audit'
        )

    Add-KnownSubject `
        -Domain 'IDENTITY' `
        -Alias (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'target_alias' `
                -Context 'Identity directory audit'
        )
}

foreach ($entry in $identityRisks) {
    if ($null -eq $entry) {
        continue
    }

    Add-KnownSubject `
        -Domain 'IDENTITY' `
        -Alias (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'subject_alias' `
                -Context 'Identity risk detection'
        )
}

foreach ($entry in $applicationSignIns) {
    if ($null -eq $entry) {
        continue
    }

    Add-KnownSubject `
        -Domain 'APPLICATION' `
        -Alias (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'subject_alias' `
                -Context 'Application sign-in'
        )
}

foreach ($entry in $applicationAudits) {
    if ($null -eq $entry) {
        continue
    }

    Add-KnownSubject `
        -Domain 'APPLICATION' `
        -Alias (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'actor_alias' `
                -Context 'Application directory audit'
        )
}

foreach ($alert in $endpointAlerts) {
    if ($null -eq $alert) {
        continue
    }

    foreach (
        $evidence in @(
            Get-RequiredProperty `
                -Object $alert `
                -Name 'evidence' `
                -Context 'Endpoint alert'
        )
    ) {
        if ($null -eq $evidence) {
            continue
        }

        $subjectAlias = Get-PropertyValue `
            -Object $evidence `
            -Name 'subject_alias'

        if ($null -ne $subjectAlias) {
            Add-KnownSubject `
                -Domain 'ENDPOINT' `
                -Alias $subjectAlias
        }
    }
}

$bindingLookup = @{}
$bindingAliases = @{}
$memberAssignments = @{}
$bindingSummaries = @()

if (
    -not [string]::IsNullOrWhiteSpace($BindingsPath)
) {
    $bindingsDocument = Read-JsonDocument `
        -Path $BindingsPath `
        -Label 'Cross-domain bindings'

    if (
        [int](
            Get-RequiredProperty `
                -Object $bindingsDocument `
                -Name 'schema_version' `
                -Context 'Cross-domain bindings'
        ) -ne 1
    ) {
        throw 'Unsupported cross-domain binding schema.'
    }

    if (
        [string](
            Get-RequiredProperty `
                -Object $bindingsDocument `
                -Name 'case_id' `
                -Context 'Cross-domain bindings'
        ) -ne $caseId
    ) {
        throw 'Cross-domain binding case ID does not match incident case.'
    }

    foreach (
        $binding in @(
            Get-RequiredProperty `
                -Object $bindingsDocument `
                -Name 'bindings' `
                -Context 'Cross-domain bindings'
        )
    ) {
        if ($null -eq $binding) {
            continue
        }

        $bindingAlias = [string](
            Get-RequiredProperty `
                -Object $binding `
                -Name 'binding_alias' `
                -Context 'Cross-domain binding'
        )

        if (
            $bindingAlias -notmatch '^CORR-SUBJECT-[0-9]{3}$'
        ) {
            throw 'Cross-domain binding alias is malformed.'
        }

        if ($bindingAliases.ContainsKey($bindingAlias)) {
            throw 'Duplicate cross-domain binding alias detected.'
        }

        $bindingAliases[$bindingAlias] = $true

        $relationshipType = [string](
            Get-RequiredProperty `
                -Object $binding `
                -Name 'relationship_type' `
                -Context 'Cross-domain binding'
        )

        if ($relationshipType -ne 'SAME_SUBJECT') {
            throw 'Unsupported cross-domain relationship type.'
        }

        $members = @(
            Get-RequiredProperty `
                -Object $binding `
                -Name 'members' `
                -Context 'Cross-domain binding'
        )

        if ($members.Count -lt 2) {
            throw 'Cross-domain subject binding needs at least two members.'
        }

        $domains = @{}

        foreach ($member in $members) {
            if ($null -eq $member) {
                throw 'Cross-domain binding contains null member.'
            }

            $domain = [string](
                Get-RequiredProperty `
                    -Object $member `
                    -Name 'domain' `
                    -Context 'Cross-domain binding member'
            )

            if (
                $domain -notin @(
                    'IDENTITY',
                    'APPLICATION',
                    'ENDPOINT'
                )
            ) {
                throw 'Cross-domain binding member domain is unsupported.'
            }

            $alias = [string](
                Get-RequiredProperty `
                    -Object $member `
                    -Name 'alias' `
                    -Context 'Cross-domain binding member'
            )

            if (
                -not (
                    Test-NumberedAlias `
                        -Value $alias `
                        -Prefix 'SUBJECT'
                )
            ) {
                throw 'Cross-domain binding member must use SUBJECT-NNN.'
            }

            if (-not $knownSubjects[$domain].ContainsKey($alias)) {
                throw 'Cross-domain binding references unknown sanitized alias.'
            }

            $memberKey = "$domain|$alias"

            if ($memberAssignments.ContainsKey($memberKey)) {
                throw 'Sanitized subject alias is assigned to multiple bindings.'
            }

            $memberAssignments[$memberKey] = $bindingAlias
            $bindingLookup[$memberKey] = $bindingAlias
            $domains[$domain] = $true
        }

        if ($domains.Count -lt 2) {
            throw 'Cross-domain subject binding must span at least two domains.'
        }

        $bindingSummaries += [pscustomobject][ordered]@{
            binding_alias = $bindingAlias
            relationship_type = 'SAME_SUBJECT'
            member_count = $members.Count
            domains = @(
                $domains.Keys |
                Sort-Object
            )
        }
    }
}

$script:TimelineEvents = @()

$domainPriority = @{
    IDENTITY = 1
    APPLICATION = 2
    ENDPOINT = 3
}

function Get-SubjectBindings {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('IDENTITY', 'APPLICATION', 'ENDPOINT')]
        [string]$Domain,

        [object[]]$SubjectReferences
    )

    $result = @()

    foreach ($reference in @($SubjectReferences)) {
        if ($null -eq $reference) {
            continue
        }

        $role = [string]$reference.role
        $alias = [string]$reference.alias

        if ($alias -eq 'SUBJECT-UNKNOWN') {
            continue
        }

        $key = "$Domain|$alias"

        if ($bindingLookup.ContainsKey($key)) {
            $result += [pscustomobject][ordered]@{
                role = $role
                binding_alias = $bindingLookup[$key]
            }
        }
    }

    return @(
        $result |
        Sort-Object role, binding_alias -Unique
    )
}

function Add-TimelineEvent {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Timestamp,

        [Parameter(Mandatory = $true)]
        [ValidateSet('IDENTITY', 'APPLICATION', 'ENDPOINT')]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$EventType,

        [Parameter(Mandatory = $true)]
        [int]$SourceIndex,

        [Parameter(Mandatory = $true)]
        [object]$LocalReferences,

        [Parameter(Mandatory = $true)]
        [object]$Attributes,

        [object[]]$SubjectReferences = @()
    )

    $normalizedTimestamp = ConvertTo-NormalizedUtcTimestamp `
        -Value $Timestamp

    $subjectBindings = @(
        Get-SubjectBindings `
            -Domain $Domain `
            -SubjectReferences $SubjectReferences
    )

    $script:TimelineEvents += [pscustomobject][ordered]@{
        timestamp_utc = $normalizedTimestamp
        domain = $Domain
        domain_priority = $domainPriority[$Domain]
        event_type = $EventType
        source_index = $SourceIndex
        local_references = $LocalReferences
        subject_bindings = @($subjectBindings)
        attributes = $Attributes
    }
}

for ($index = 0; $index -lt $identitySignIns.Count; $index++) {
    $entry = $identitySignIns[$index]

    if ($null -eq $entry) {
        continue
    }

    $subjectAlias = Assert-LocalAlias `
        -Value (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'subject_alias' `
                -Context 'Identity sign-in'
        ) `
        -Prefix 'SUBJECT' `
        -Context 'Identity sign-in'

    Add-TimelineEvent `
        -Timestamp (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'timestamp_utc' `
                -Context 'Identity sign-in'
        ) `
        -Domain 'IDENTITY' `
        -EventType 'IDENTITY_SIGN_IN' `
        -SourceIndex $index `
        -LocalReferences ([ordered]@{
            subject_alias = $subjectAlias
        }) `
        -SubjectReferences @(
            [pscustomobject]@{
                role = 'SUBJECT'
                alias = $subjectAlias
            }
        ) `
        -Attributes ([ordered]@{
            outcome = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'outcome'
            )
            risk_level = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'risk_level'
            )
        })
}

for ($index = 0; $index -lt $identityAudits.Count; $index++) {
    $entry = $identityAudits[$index]

    if ($null -eq $entry) {
        continue
    }

    $actorAlias = Assert-LocalAlias `
        -Value (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'actor_alias' `
                -Context 'Identity directory audit'
        ) `
        -Prefix 'SUBJECT' `
        -Context 'Identity directory audit'

    $targetAlias = Assert-LocalAlias `
        -Value (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'target_alias' `
                -Context 'Identity directory audit'
        ) `
        -Prefix 'SUBJECT' `
        -Context 'Identity directory audit'

    Add-TimelineEvent `
        -Timestamp (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'timestamp_utc' `
                -Context 'Identity directory audit'
        ) `
        -Domain 'IDENTITY' `
        -EventType 'IDENTITY_DIRECTORY_AUDIT' `
        -SourceIndex $index `
        -LocalReferences ([ordered]@{
            actor_alias = $actorAlias
            target_alias = $targetAlias
        }) `
        -SubjectReferences @(
            [pscustomobject]@{
                role = 'ACTOR'
                alias = $actorAlias
            },
            [pscustomobject]@{
                role = 'TARGET'
                alias = $targetAlias
            }
        ) `
        -Attributes ([ordered]@{
            category = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'category'
            )
            result = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'result'
            )
        })
}

for ($index = 0; $index -lt $identityRisks.Count; $index++) {
    $entry = $identityRisks[$index]

    if ($null -eq $entry) {
        continue
    }

    $subjectAlias = Assert-LocalAlias `
        -Value (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'subject_alias' `
                -Context 'Identity risk detection'
        ) `
        -Prefix 'SUBJECT' `
        -Context 'Identity risk detection'

    Add-TimelineEvent `
        -Timestamp (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'timestamp_utc' `
                -Context 'Identity risk detection'
        ) `
        -Domain 'IDENTITY' `
        -EventType 'IDENTITY_RISK_DETECTION' `
        -SourceIndex $index `
        -LocalReferences ([ordered]@{
            subject_alias = $subjectAlias
        }) `
        -SubjectReferences @(
            [pscustomobject]@{
                role = 'SUBJECT'
                alias = $subjectAlias
            }
        ) `
        -Attributes ([ordered]@{
            risk_event_type = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'risk_event_type'
            )
            risk_level = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'risk_level'
            )
            risk_state = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'risk_state'
            )
        })
}

for ($index = 0; $index -lt $applicationSignIns.Count; $index++) {
    $entry = $applicationSignIns[$index]

    if ($null -eq $entry) {
        continue
    }

    $appAlias = Assert-LocalAlias `
        -Value (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'app_alias' `
                -Context 'Application sign-in'
        ) `
        -Prefix 'APP' `
        -Context 'Application sign-in'

    $subjectAlias = Assert-LocalAlias `
        -Value (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'subject_alias' `
                -Context 'Application sign-in'
        ) `
        -Prefix 'SUBJECT' `
        -Context 'Application sign-in'

    Add-TimelineEvent `
        -Timestamp (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'timestamp_utc' `
                -Context 'Application sign-in'
        ) `
        -Domain 'APPLICATION' `
        -EventType 'APPLICATION_SIGN_IN' `
        -SourceIndex $index `
        -LocalReferences ([ordered]@{
            app_alias = $appAlias
            subject_alias = $subjectAlias
        }) `
        -SubjectReferences @(
            [pscustomobject]@{
                role = 'SUBJECT'
                alias = $subjectAlias
            }
        ) `
        -Attributes ([ordered]@{
            outcome = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'outcome'
            )
            risk_level = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'risk_level'
            )
        })
}

for ($index = 0; $index -lt $applicationAudits.Count; $index++) {
    $entry = $applicationAudits[$index]

    if ($null -eq $entry) {
        continue
    }

    $appAlias = Assert-LocalAlias `
        -Value (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'app_alias' `
                -Context 'Application directory audit'
        ) `
        -Prefix 'APP' `
        -Context 'Application directory audit'

    $actorAlias = Assert-LocalAlias `
        -Value (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'actor_alias' `
                -Context 'Application directory audit'
        ) `
        -Prefix 'SUBJECT' `
        -Context 'Application directory audit'

    Add-TimelineEvent `
        -Timestamp (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'timestamp_utc' `
                -Context 'Application directory audit'
        ) `
        -Domain 'APPLICATION' `
        -EventType 'APPLICATION_DIRECTORY_AUDIT' `
        -SourceIndex $index `
        -LocalReferences ([ordered]@{
            app_alias = $appAlias
            actor_alias = $actorAlias
        }) `
        -SubjectReferences @(
            [pscustomobject]@{
                role = 'ACTOR'
                alias = $actorAlias
            }
        ) `
        -Attributes ([ordered]@{
            operation = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'operation'
            )
            result = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'result'
            )
            permission_change_observed = [bool](
                Get-PropertyValue `
                    -Object $entry `
                    -Name 'permission_change_observed'
            )
        })
}

for ($index = 0; $index -lt $endpointIncidents.Count; $index++) {
    $entry = $endpointIncidents[$index]

    if ($null -eq $entry) {
        continue
    }

    $incidentAlias = Assert-LocalAlias `
        -Value (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'incident_alias' `
                -Context 'Endpoint incident'
        ) `
        -Prefix 'INCIDENT' `
        -Context 'Endpoint incident'

    Add-TimelineEvent `
        -Timestamp (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'created_at_utc' `
                -Context 'Endpoint incident'
        ) `
        -Domain 'ENDPOINT' `
        -EventType 'ENDPOINT_INCIDENT' `
        -SourceIndex $index `
        -LocalReferences ([ordered]@{
            incident_alias = $incidentAlias
        }) `
        -Attributes ([ordered]@{
            severity = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'severity'
            )
            status = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'status'
            )
            classification = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'classification'
            )
            determination = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'determination'
            )
            correlated_alert_count = [int](
                Get-PropertyValue `
                    -Object $entry `
                    -Name 'correlated_alert_count'
            )
        })
}

for ($index = 0; $index -lt $endpointAlerts.Count; $index++) {
    $entry = $endpointAlerts[$index]

    if ($null -eq $entry) {
        continue
    }

    $alertAlias = Assert-LocalAlias `
        -Value (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'alert_alias' `
                -Context 'Endpoint alert'
        ) `
        -Prefix 'ALERT' `
        -Context 'Endpoint alert'

    $incidentAlias = Assert-LocalAlias `
        -Value (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'incident_alias' `
                -Context 'Endpoint alert'
        ) `
        -Prefix 'INCIDENT' `
        -Context 'Endpoint alert'

    $subjectReferences = @()
    $subjectAliases = @()
    $deviceAliases = @()

    $evidenceRecords = @(
        Get-RequiredProperty `
            -Object $entry `
            -Name 'evidence' `
            -Context 'Endpoint alert'
    )

    foreach ($evidence in $evidenceRecords) {
        if ($null -eq $evidence) {
            continue
        }

        $subjectAlias = Get-PropertyValue `
            -Object $evidence `
            -Name 'subject_alias'

        if ($null -ne $subjectAlias) {
            $safeSubjectAlias = Assert-LocalAlias `
                -Value $subjectAlias `
                -Prefix 'SUBJECT' `
                -Context 'Endpoint alert evidence'

            $subjectAliases += $safeSubjectAlias

            $subjectReferences += [pscustomobject]@{
                role = 'USER_EVIDENCE'
                alias = $safeSubjectAlias
            }
        }

        $deviceAlias = Get-PropertyValue `
            -Object $evidence `
            -Name 'device_alias'

        if ($null -ne $deviceAlias) {
            $deviceAliases += (
                Assert-LocalAlias `
                    -Value $deviceAlias `
                    -Prefix 'DEVICE' `
                    -Context 'Endpoint alert evidence'
            )
        }
    }

    Add-TimelineEvent `
        -Timestamp (
            Get-RequiredProperty `
                -Object $entry `
                -Name 'created_at_utc' `
                -Context 'Endpoint alert'
        ) `
        -Domain 'ENDPOINT' `
        -EventType 'ENDPOINT_ALERT' `
        -SourceIndex $index `
        -LocalReferences ([ordered]@{
            alert_alias = $alertAlias
            incident_alias = $incidentAlias
            subject_aliases = @(
                $subjectAliases |
                Sort-Object -Unique
            )
            device_aliases = @(
                $deviceAliases |
                Sort-Object -Unique
            )
        }) `
        -SubjectReferences $subjectReferences `
        -Attributes ([ordered]@{
            severity = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'severity'
            )
            status = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'status'
            )
            classification = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'classification'
            )
            determination = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'determination'
            )
            investigation_state = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'investigation_state'
            )
            service_source_category = ConvertTo-SafeCategory (
                Get-PropertyValue -Object $entry -Name 'service_source_category'
            )
            endpoint_associated = [bool](
                Get-PropertyValue `
                    -Object $entry `
                    -Name 'endpoint_associated'
            )
            mitre_technique_count = [int](
                Get-PropertyValue `
                    -Object $entry `
                    -Name 'mitre_technique_count'
            )
            evidence_record_count = $evidenceRecords.Count
        })
}

$sortedEvents = @(
    $script:TimelineEvents |
    Sort-Object `
        timestamp_utc,
        domain_priority,
        event_type,
        source_index
)

$timeline = @()
$sequence = 1

foreach ($event in $sortedEvents) {
    $timeline += [pscustomobject][ordered]@{
        sequence = $sequence
        timestamp_utc = $event.timestamp_utc
        domain = $event.domain
        event_type = $event.event_type
        source_index = $event.source_index
        local_references = $event.local_references
        subject_bindings = @($event.subject_bindings)
        attributes = $event.attributes
    }

    $sequence++
}

$identityEventCount = @(
    $timeline |
    Where-Object {
        $_.domain -eq 'IDENTITY'
    }
).Count

$applicationEventCount = @(
    $timeline |
    Where-Object {
        $_.domain -eq 'APPLICATION'
    }
).Count

$endpointEventCount = @(
    $timeline |
    Where-Object {
        $_.domain -eq 'ENDPOINT'
    }
).Count

$boundEventCount = @(
    $timeline |
    Where-Object {
        @($_.subject_bindings).Count -gt 0
    }
).Count

$unboundEventCount = (
    $timeline.Count -
    $boundEventCount
)

$output = [ordered]@{
    schema_version = 1
    feature = 7
    case_id = $caseId
    correlation_type = 'CROSS_SIGNAL'
    deterministic_output = $true
    privacy = [ordered]@{
        raw_identifiers_retained = $false
        raw_graph_payloads_retained = $false
        local_aliases_domain_scoped = $true
        cross_domain_alias_equality_join = $false
        explicit_sanitized_binding_required = $true
    }
    safety_boundary = [ordered]@{
        graph_authentication_required = $false
        graph_requests = 0
        tenant_reads = 0
        tenant_writes = 0
        endpoint_actions = 0
        response_actions = 0
    }
    counts = [ordered]@{
        total_events = $timeline.Count
        identity_events = $identityEventCount
        application_events = $applicationEventCount
        endpoint_events = $endpointEventCount
        explicit_subject_bindings = $bindingSummaries.Count
        bound_events = $boundEventCount
        unbound_events = $unboundEventCount
    }
    bindings = @(
        $bindingSummaries |
        Sort-Object binding_alias
    )
    timeline = @($timeline)
}

$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$outputParent = Split-Path -Parent $outputFullPath

if (
    -not [string]::IsNullOrWhiteSpace($outputParent) -and
    -not (Test-Path -LiteralPath $outputParent)
) {
    New-Item `
        -ItemType Directory `
        -Path $outputParent `
        -Force |
        Out-Null
}

$json = $output |
    ConvertTo-Json -Depth 24

[IO.File]::WriteAllText(
    $outputFullPath,
    $json + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)

Write-Output 'CROSS_SIGNAL_CORRELATION=PASS'
Write-Output 'DETERMINISTIC_TIMELINE=PASS'
Write-Output 'CROSS_DOMAIN_ALIAS_EQUALITY_JOIN=NO'
Write-Output 'EXPLICIT_SANITIZED_BINDING_REQUIRED=YES'
Write-Output 'RAW_IDENTIFIER_RETENTION=NO'
Write-Output 'RAW_GRAPH_PAYLOAD_RETENTION=NO'
Write-Output 'TENANT_WRITE=NO'
Write-Output 'ENDPOINT_ACTION=NO'
