[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CasePath,

    [Parameter(Mandatory)]
    [string]$SignInsPath,

    [Parameter(Mandatory)]
    [string]$DirectoryAuditsPath,

    [Parameter(Mandatory)]
    [string]$RiskDetectionsPath,

    [Parameter(Mandatory)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PropertyValue {
    param(
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory)]
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
        [Parameter(Mandatory)]
        [object]$Value
    )

    try {
        if ($Value -is [DateTimeOffset]) {
            $utc = ([DateTimeOffset]$Value).UtcDateTime
        }
        elseif ($Value -is [DateTime]) {
            $dateTime = [DateTime]$Value

            if ($dateTime.Kind -eq [DateTimeKind]::Unspecified) {
                $dateTime = [DateTime]::SpecifyKind(
                    $dateTime,
                    [DateTimeKind]::Utc
                )
            }

            $utc = $dateTime.ToUniversalTime()
        }
        else {
            $parsed = [DateTime]::Parse(
                [string]$Value,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            )

            if ($parsed.Kind -eq [DateTimeKind]::Unspecified) {
                $parsed = [DateTime]::SpecifyKind(
                    $parsed,
                    [DateTimeKind]::Utc
                )
            }

            $utc = $parsed.ToUniversalTime()
        }
    }
    catch {
        throw 'Signal timestamp could not be normalized safely.'
    }

    return $utc.ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
        [Globalization.CultureInfo]::InvariantCulture
    )
}

function ConvertTo-SafeCategoricalValue {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return 'UNKNOWN'
    }

    $text = ([string]$Value).Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        return 'UNKNOWN'
    }

    if (
        $text.Length -gt 80 -or
        $text -match '[@\r\n]' -or
        $text -notmatch '^[A-Za-z0-9._ -]+$'
    ) {
        return 'REDACTED_CATEGORY'
    }

    return $text
}

$subjectMap = @{}
$nextSubject = 1

function Get-SubjectAlias {
    param(
        [AllowNull()]
        [object]$UserId,

        [AllowNull()]
        [object]$UserPrincipalName
    )

    $key = $null

    if (
        $null -ne $UserId -and
        -not [string]::IsNullOrWhiteSpace([string]$UserId)
    ) {
        $key = 'ID:' + ([string]$UserId).ToLowerInvariant()
    }
    elseif (
        $null -ne $UserPrincipalName -and
        -not [string]::IsNullOrWhiteSpace(
            [string]$UserPrincipalName
        )
    ) {
        $key = 'UPN:' + (
            [string]$UserPrincipalName
        ).ToLowerInvariant()
    }

    if ($null -eq $key) {
        return 'SUBJECT-UNKNOWN'
    }

    if (-not $script:subjectMap.ContainsKey($key)) {
        $script:subjectMap[$key] = (
            'SUBJECT-{0:D3}' -f $script:nextSubject
        )

        $script:nextSubject++
    }

    return [string]$script:subjectMap[$key]
}

$caseRoot = [IO.Path]::GetFullPath($CasePath)

if (-not (Test-Path -LiteralPath $caseRoot -PathType Container)) {
    throw 'CasePath does not exist.'
}

$caseFile = Join-Path $caseRoot 'case.json'

if (-not (Test-Path -LiteralPath $caseFile -PathType Leaf)) {
    throw 'case.json is missing.'
}

foreach ($inputPath in @(
    $SignInsPath,
    $DirectoryAuditsPath,
    $RiskDetectionsPath
)) {
    if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) {
        throw 'A required signal input file is missing.'
    }
}

$case = (
    Get-Content `
        -LiteralPath $caseFile `
        -Raw |
    ConvertFrom-Json
)

$caseId = [string]$case.case_id

if ([string]::IsNullOrWhiteSpace($caseId)) {
    throw 'Case identifier is missing.'
}

$signInsDocument = (
    Get-Content `
        -LiteralPath $SignInsPath `
        -Raw |
    ConvertFrom-Json
)

$directoryAuditsDocument = (
    Get-Content `
        -LiteralPath $DirectoryAuditsPath `
        -Raw |
    ConvertFrom-Json
)

$riskDetectionsDocument = (
    Get-Content `
        -LiteralPath $RiskDetectionsPath `
        -Raw |
    ConvertFrom-Json
)

$signIns = @(
    Get-PropertyValue `
        -Object $signInsDocument `
        -Name 'value'
)

$directoryAudits = @(
    Get-PropertyValue `
        -Object $directoryAuditsDocument `
        -Name 'value'
)

$riskDetections = @(
    Get-PropertyValue `
        -Object $riskDetectionsDocument `
        -Name 'value'
)

$sanitizedSignIns = @()

foreach ($entry in $signIns) {
    if ($null -eq $entry) {
        continue
    }

    $timestamp = Get-PropertyValue `
        -Object $entry `
        -Name 'createdDateTime'

    if ($null -eq $timestamp) {
        throw 'Sign-in record is missing createdDateTime.'
    }

    $userId = Get-PropertyValue `
        -Object $entry `
        -Name 'userId'

    $upn = Get-PropertyValue `
        -Object $entry `
        -Name 'userPrincipalName'

    $status = Get-PropertyValue `
        -Object $entry `
        -Name 'status'

    $errorCode = Get-PropertyValue `
        -Object $status `
        -Name 'errorCode'

    $outcome = if ($null -eq $errorCode) {
        'UNKNOWN'
    }
    elseif ([long]$errorCode -eq 0) {
        'SUCCESS'
    }
    else {
        'FAILURE'
    }

    $riskLevel = Get-PropertyValue `
        -Object $entry `
        -Name 'riskLevelAggregated'

    $sanitizedSignIns += [pscustomobject][ordered]@{
        subject_alias = (
            Get-SubjectAlias `
                -UserId $userId `
                -UserPrincipalName $upn
        )
        timestamp_utc = (
            ConvertTo-NormalizedUtcTimestamp `
                -Value $timestamp
        )
        outcome = $outcome
        risk_level = (
            ConvertTo-SafeCategoricalValue `
                -Value $riskLevel
        )
    }
}

$sanitizedDirectoryAudits = @()

foreach ($entry in $directoryAudits) {
    if ($null -eq $entry) {
        continue
    }

    $timestamp = Get-PropertyValue `
        -Object $entry `
        -Name 'activityDateTime'

    if ($null -eq $timestamp) {
        throw 'Directory-audit record is missing activityDateTime.'
    }

    $initiatedBy = Get-PropertyValue `
        -Object $entry `
        -Name 'initiatedBy'

    $initiatingUser = Get-PropertyValue `
        -Object $initiatedBy `
        -Name 'user'

    $actorId = Get-PropertyValue `
        -Object $initiatingUser `
        -Name 'id'

    $actorUpn = Get-PropertyValue `
        -Object $initiatingUser `
        -Name 'userPrincipalName'

    $actorAlias = Get-SubjectAlias `
        -UserId $actorId `
        -UserPrincipalName $actorUpn

    $targetAlias = 'SUBJECT-UNKNOWN'

    $targetResources = @(
        Get-PropertyValue `
            -Object $entry `
            -Name 'targetResources'
    )

    if ($targetResources.Count -gt 0) {
        $target = $targetResources[0]

        $targetType = Get-PropertyValue `
            -Object $target `
            -Name 'type'

        if (
            $null -eq $targetType -or
            [string]$targetType -eq 'User'
        ) {
            $targetId = Get-PropertyValue `
                -Object $target `
                -Name 'id'

            $targetUpn = Get-PropertyValue `
                -Object $target `
                -Name 'userPrincipalName'

            $targetAlias = Get-SubjectAlias `
                -UserId $targetId `
                -UserPrincipalName $targetUpn
        }
    }

    $category = Get-PropertyValue `
        -Object $entry `
        -Name 'category'

    $result = Get-PropertyValue `
        -Object $entry `
        -Name 'result'

    $sanitizedDirectoryAudits += [pscustomobject][ordered]@{
        actor_alias = $actorAlias
        target_alias = $targetAlias
        timestamp_utc = (
            ConvertTo-NormalizedUtcTimestamp `
                -Value $timestamp
        )
        category = (
            ConvertTo-SafeCategoricalValue `
                -Value $category
        )
        result = (
            ConvertTo-SafeCategoricalValue `
                -Value $result
        )
    }
}

$sanitizedRiskDetections = @()

foreach ($entry in $riskDetections) {
    if ($null -eq $entry) {
        continue
    }

    $timestamp = Get-PropertyValue `
        -Object $entry `
        -Name 'detectedDateTime'

    if ($null -eq $timestamp) {
        throw 'Risk-detection record is missing detectedDateTime.'
    }

    $userId = Get-PropertyValue `
        -Object $entry `
        -Name 'userId'

    $upn = Get-PropertyValue `
        -Object $entry `
        -Name 'userPrincipalName'

    $eventType = Get-PropertyValue `
        -Object $entry `
        -Name 'riskEventType'

    $riskLevel = Get-PropertyValue `
        -Object $entry `
        -Name 'riskLevel'

    $riskState = Get-PropertyValue `
        -Object $entry `
        -Name 'riskState'

    $sanitizedRiskDetections += [pscustomobject][ordered]@{
        subject_alias = (
            Get-SubjectAlias `
                -UserId $userId `
                -UserPrincipalName $upn
        )
        timestamp_utc = (
            ConvertTo-NormalizedUtcTimestamp `
                -Value $timestamp
        )
        risk_event_type = (
            ConvertTo-SafeCategoricalValue `
                -Value $eventType
        )
        risk_level = (
            ConvertTo-SafeCategoricalValue `
                -Value $riskLevel
        )
        risk_state = (
            ConvertTo-SafeCategoricalValue `
                -Value $riskState
        )
    }
}

$failureCount = @(
    $sanitizedSignIns |
    Where-Object {
        $_.outcome -eq 'FAILURE'
    }
).Count

$riskySignInCount = @(
    $sanitizedSignIns |
    Where-Object {
        $_.risk_level -notin @(
            'none',
            'hidden',
            'UNKNOWN'
        )
    }
).Count

$riskDetectionCount = $sanitizedRiskDetections.Count

$generatedAt = [DateTime]::UtcNow.ToString(
    "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
    [Globalization.CultureInfo]::InvariantCulture
)

$summary = [ordered]@{
    schema_version = 1
    case_id = $caseId
    generated_at_utc = $generatedAt
    investigation_type = 'IDENTITY_SECURITY'
    privacy_mode = 'SUBJECT_ALIAS_ONLY'
    raw_identifiers_retained = $false
    raw_graph_payload_retained = $false
    source_counts = [ordered]@{
        sign_ins = $sanitizedSignIns.Count
        directory_audits = $sanitizedDirectoryAudits.Count
        risk_detections = $sanitizedRiskDetections.Count
    }
    finding_counts = [ordered]@{
        failed_sign_ins = $failureCount
        risky_sign_ins = $riskySignInCount
        risk_detections = $riskDetectionCount
        unique_subjects = $subjectMap.Count
    }
    sign_ins = @($sanitizedSignIns)
    directory_audits = @($sanitizedDirectoryAudits)
    risk_detections = @($sanitizedRiskDetections)
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
        $summary |
        ConvertTo-Json -Depth 12
    ),
    $utf8NoBom
)

Write-Output 'IDENTITY_SIGNAL_SANITIZATION=PASS'
Write-Output 'SUBJECT_ALIASING=PASS'
Write-Output 'RAW_IDENTIFIERS_RETAINED=NO'
Write-Output 'RAW_GRAPH_PAYLOAD_RETAINED=NO'
