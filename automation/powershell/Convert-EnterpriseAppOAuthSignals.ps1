[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CasePath,

    [Parameter(Mandatory = $true)]
    [string]$SignInsPath,

    [Parameter(Mandatory = $true)]
    [string]$DirectoryAuditsPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
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

function ConvertTo-NormalizedUtcTimestamp {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $parsed = [DateTimeOffset]::MinValue

    if (
        -not [DateTimeOffset]::TryParse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal,
            [ref]$parsed
        )
    ) {
        return $null
    }

    return $parsed.UtcDateTime.ToString(
        'yyyy-MM-ddTHH:mm:ss.fffffffZ',
        [Globalization.CultureInfo]::InvariantCulture
    )
}

function ConvertTo-SafeCategoricalValue {
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

    if ($text.Length -gt 80) {
        return 'REDACTED_CATEGORY'
    }

    if ($text -notmatch '^[A-Za-z0-9._ -]+$') {
        return 'REDACTED_CATEGORY'
    }

    return $text
}

function Get-ControlledAuditOperation {
    param(
        [AllowNull()]
        [object]$Value
    )

    $text = ([string]$Value).ToLowerInvariant()

    if ($text -match 'consent') {
        return 'CONSENT'
    }

    if (
        $text -match 'permission' -or
        $text -match 'oauth'
    ) {
        return 'PERMISSION_CHANGE'
    }

    if ($text -match 'service principal') {
        return 'SERVICE_PRINCIPAL_CHANGE'
    }

    if ($text -match 'application') {
        return 'APPLICATION_CHANGE'
    }

    return 'OTHER_APPLICATION_MANAGEMENT'
}

function Test-PermissionChangePresence {
    param(
        [AllowNull()]
        [object]$TargetResources
    )

    foreach ($target in @($TargetResources)) {
        if ($null -eq $target) {
            continue
        }

        $modifiedProperties = Get-PropertyValue `
            -Object $target `
            -Name 'modifiedProperties'

        foreach ($property in @($modifiedProperties)) {
            if ($null -eq $property) {
                continue
            }

            $displayName = [string](
                Get-PropertyValue `
                    -Object $property `
                    -Name 'displayName'
            )

            if (
                $displayName -match '(?i)permission' -or
                $displayName -match '(?i)scope' -or
                $displayName -match '(?i)consent' -or
                $displayName -match '(?i)oauth'
            ) {
                return $true
            }
        }
    }

    return $false
}

$script:AppAliases = @{}
$script:SubjectAliases = @{}
$script:NextAppAlias = 1
$script:NextSubjectAlias = 1

function Get-AppAlias {
    param(
        [AllowNull()]
        [object]$Key
    )

    $keyText = ([string]$Key).Trim()

    if ([string]::IsNullOrWhiteSpace($keyText)) {
        return 'APP-000'
    }

    if (-not $script:AppAliases.ContainsKey($keyText)) {
        $script:AppAliases[$keyText] = (
            'APP-{0:D3}' -f $script:NextAppAlias
        )

        $script:NextAppAlias++
    }

    return $script:AppAliases[$keyText]
}

function Get-SubjectAlias {
    param(
        [AllowNull()]
        [object]$Key
    )

    $keyText = ([string]$Key).Trim()

    if ([string]::IsNullOrWhiteSpace($keyText)) {
        return 'SUBJECT-000'
    }

    if (-not $script:SubjectAliases.ContainsKey($keyText)) {
        $script:SubjectAliases[$keyText] = (
            'SUBJECT-{0:D3}' -f $script:NextSubjectAlias
        )

        $script:NextSubjectAlias++
    }

    return $script:SubjectAliases[$keyText]
}

function Get-AppKeyFromSignIn {
    param(
        [AllowNull()]
        [object]$Record
    )

    foreach ($name in @(
        'appId',
        'servicePrincipalId',
        'resourceServicePrincipalId',
        'appDisplayName',
        'resourceDisplayName'
    )) {
        $value = Get-PropertyValue `
            -Object $Record `
            -Name $name

        if (
            $null -ne $value -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$value
            )
        ) {
            return [string]$value
        }
    }

    return $null
}

function Get-SubjectKeyFromSignIn {
    param(
        [AllowNull()]
        [object]$Record
    )

    foreach ($name in @(
        'userId',
        'userPrincipalName'
    )) {
        $value = Get-PropertyValue `
            -Object $Record `
            -Name $name

        if (
            $null -ne $value -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$value
            )
        ) {
            return [string]$value
        }
    }

    return $null
}

function Get-AppKeyFromAudit {
    param(
        [AllowNull()]
        [object]$TargetResources
    )

    foreach ($target in @($TargetResources)) {
        if ($null -eq $target) {
            continue
        }

        $type = [string](
            Get-PropertyValue `
                -Object $target `
                -Name 'type'
        )

        if (
            $type -notmatch '(?i)application' -and
            $type -notmatch '(?i)serviceprincipal' -and
            $type -notmatch '(?i)service principal'
        ) {
            continue
        }

        foreach ($name in @(
            'id',
            'displayName'
        )) {
            $value = Get-PropertyValue `
                -Object $target `
                -Name $name

            if (
                $null -ne $value -and
                -not [string]::IsNullOrWhiteSpace(
                    [string]$value
                )
            ) {
                return [string]$value
            }
        }
    }

    return $null
}

$caseFile = Join-Path `
    -Path $CasePath `
    -ChildPath 'case.json'

if (-not (Test-Path -LiteralPath $caseFile -PathType Leaf)) {
    throw 'Case metadata file not found.'
}

foreach ($inputFile in @(
    $SignInsPath,
    $DirectoryAuditsPath
)) {
    if (-not (Test-Path -LiteralPath $inputFile -PathType Leaf)) {
        throw 'Required local input file not found.'
    }
}

$case = Get-Content `
    -LiteralPath $caseFile `
    -Raw |
    ConvertFrom-Json

$caseId = [string](
    Get-PropertyValue `
        -Object $case `
        -Name 'case_id'
)

if ([string]::IsNullOrWhiteSpace($caseId)) {
    throw 'Case ID unavailable.'
}

$signInInput = Get-Content `
    -LiteralPath $SignInsPath `
    -Raw |
    ConvertFrom-Json

$auditInput = Get-Content `
    -LiteralPath $DirectoryAuditsPath `
    -Raw |
    ConvertFrom-Json

$signInRecords = @(
    Get-PropertyValue `
        -Object $signInInput `
        -Name 'value'
)

$auditRecords = @(
    Get-PropertyValue `
        -Object $auditInput `
        -Name 'value'
)

$safeSignIns = @()
$safeAudits = @()

$failedSignInCount = 0
$riskySignInCount = 0
$consentEventCount = 0
$permissionChangeEventCount = 0

foreach ($record in $signInRecords) {
    if ($null -eq $record) {
        continue
    }

    $appAlias = Get-AppAlias `
        -Key (
            Get-AppKeyFromSignIn `
                -Record $record
        )

    $subjectAlias = Get-SubjectAlias `
        -Key (
            Get-SubjectKeyFromSignIn `
                -Record $record
        )

    $status = Get-PropertyValue `
        -Object $record `
        -Name 'status'

    $errorCode = Get-PropertyValue `
        -Object $status `
        -Name 'errorCode'

    $outcome = 'UNKNOWN'

    if ($null -ne $errorCode) {
        if ([long]$errorCode -eq 0) {
            $outcome = 'SUCCESS'
        }
        else {
            $outcome = 'FAILURE'
            $failedSignInCount++
        }
    }

    $riskLevel = ConvertTo-SafeCategoricalValue `
        -Value (
            Get-PropertyValue `
                -Object $record `
                -Name 'riskLevelAggregated'
        )

    if (
        $riskLevel -notin @(
            'none',
            'hidden',
            'UNKNOWN'
        )
    ) {
        $riskySignInCount++
    }

    $safeSignIns += [ordered]@{
        app_alias = $appAlias
        subject_alias = $subjectAlias
        timestamp_utc = ConvertTo-NormalizedUtcTimestamp `
            -Value (
                Get-PropertyValue `
                    -Object $record `
                    -Name 'createdDateTime'
            )
        outcome = $outcome
        risk_level = $riskLevel
    }
}

foreach ($record in $auditRecords) {
    if ($null -eq $record) {
        continue
    }

    $targetResources = Get-PropertyValue `
        -Object $record `
        -Name 'targetResources'

    $appAlias = Get-AppAlias `
        -Key (
            Get-AppKeyFromAudit `
                -TargetResources $targetResources
        )

    $initiatedBy = Get-PropertyValue `
        -Object $record `
        -Name 'initiatedBy'

    $initiatingUser = Get-PropertyValue `
        -Object $initiatedBy `
        -Name 'user'

    $actorKey = Get-PropertyValue `
        -Object $initiatingUser `
        -Name 'id'

    $actorAlias = Get-SubjectAlias `
        -Key $actorKey

    $operation = Get-ControlledAuditOperation `
        -Value (
            Get-PropertyValue `
                -Object $record `
                -Name 'activityDisplayName'
        )

    $permissionChangeObserved = (
        Test-PermissionChangePresence `
            -TargetResources $targetResources
    )

    if ($operation -eq 'CONSENT') {
        $consentEventCount++
    }

    if (
        $permissionChangeObserved -or
        $operation -eq 'PERMISSION_CHANGE'
    ) {
        $permissionChangeEventCount++
    }

    $safeAudits += [ordered]@{
        app_alias = $appAlias
        actor_alias = $actorAlias
        timestamp_utc = ConvertTo-NormalizedUtcTimestamp `
            -Value (
                Get-PropertyValue `
                    -Object $record `
                    -Name 'activityDateTime'
            )
        operation = $operation
        result = ConvertTo-SafeCategoricalValue `
            -Value (
                Get-PropertyValue `
                    -Object $record `
                    -Name 'result'
            )
        permission_change_observed = $permissionChangeObserved
    }
}

$output = [ordered]@{
    schema_version = 1
    feature = 5
    case_id = $caseId
    generated_at_utc = [DateTime]::UtcNow.ToString(
        'yyyy-MM-ddTHH:mm:ss.fffffffZ',
        [Globalization.CultureInfo]::InvariantCulture
    )
    investigation_type = 'ENTERPRISE_APPLICATION_OAUTH'
    privacy = [ordered]@{
        application_alias_mode = 'IN_MEMORY_ONLY'
        subject_alias_mode = 'IN_MEMORY_ONLY'
        raw_application_ids_retained = $false
        raw_service_principal_ids_retained = $false
        raw_user_ids_retained = $false
        raw_upns_retained = $false
        raw_ip_addresses_retained = $false
        raw_grant_values_retained = $false
        raw_graph_payloads_retained = $false
    }
    counts = [ordered]@{
        sign_in_records = $safeSignIns.Count
        directory_audit_records = $safeAudits.Count
        application_alias_count = $script:AppAliases.Count
        subject_alias_count = $script:SubjectAliases.Count
        failed_sign_ins = $failedSignInCount
        risky_sign_ins = $riskySignInCount
        consent_events = $consentEventCount
        permission_change_events = $permissionChangeEventCount
    }
    sign_ins = @($safeSignIns)
    directory_audits = @($safeAudits)
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
    ConvertTo-Json -Depth 12

[IO.File]::WriteAllText(
    $outputFullPath,
    $json + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)

Write-Output 'ENTERPRISE_APP_OAUTH_SIGNAL_CONVERSION=PASS'
Write-Output 'RAW_APPLICATION_IDENTIFIER_RETENTION=NO'
Write-Output 'RAW_SUBJECT_IDENTIFIER_RETENTION=NO'
Write-Output 'RAW_OAUTH_GRANT_VALUE_RETENTION=NO'
