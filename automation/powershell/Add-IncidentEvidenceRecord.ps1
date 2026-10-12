[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CasePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^EVID-[A-Z0-9]{4,16}$')]
    [string]$EvidenceId,

    [Parameter(Mandatory)]
    [ValidateSet(
        'MICROSOFT_GRAPH',
        'PORTAL_EXPORT',
        'OPERATOR_NOTE',
        'LOCAL_FILE',
        'OTHER_SANITIZED'
    )]
    [string]$SourceType,

    [Parameter(Mandatory)]
    [string]$SanitizedLabel,

    [Parameter(Mandatory)]
    [string]$SourceFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-CanonicalCustodyField {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ('{0}:-1:' -f $Name)
    }

    $text = [string]$Value

    $byteCount = (
        [Text.Encoding]::UTF8.GetByteCount($text)
    )

    return (
        '{0}:{1}:{2}' -f
        $Name,
        $byteCount,
        $text
    )
}

function ConvertTo-CanonicalUtcTimestamp {
    param(
        [Parameter(Mandatory)]
        [object]$Value
    )

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

    return $utc.ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
        [Globalization.CultureInfo]::InvariantCulture
    )
}

function Get-CanonicalCustodyPayload {
    param(
        [Parameter(Mandatory)]
        [int]$Sequence,

        [Parameter(Mandatory)]
        [string]$CaseId,

        [Parameter(Mandatory)]
        [string]$EvidenceId,

        [Parameter(Mandatory)]
        [string]$RecordedAtUtc,

        [AllowNull()]
        [object]$PreviousRecordSha256,

        [Parameter(Mandatory)]
        [string]$EvidenceSha256,

        [Parameter(Mandatory)]
        [long]$EvidenceSizeBytes,

        [Parameter(Mandatory)]
        [string]$SourceType,

        [Parameter(Mandatory)]
        [string]$SanitizedLabel
    )

    $canonicalRecordedAtUtc = (
        ConvertTo-CanonicalUtcTimestamp `
            -Value $RecordedAtUtc
    )

    $fields = @(
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'schema_version' `
                -Value 1
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'sequence' `
                -Value $Sequence
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'event_type' `
                -Value 'EVIDENCE_REGISTERED'
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'case_id' `
                -Value $CaseId
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'evidence_id' `
                -Value $EvidenceId
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'recorded_at_utc' `
                -Value $canonicalRecordedAtUtc
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'previous_record_sha256' `
                -Value $PreviousRecordSha256
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'evidence_sha256' `
                -Value $EvidenceSha256
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'evidence_size_bytes' `
                -Value $EvidenceSizeBytes
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'source_type' `
                -Value $SourceType
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'sanitized_label' `
                -Value $SanitizedLabel
        )
    )

    return (
        [string]::Join(
            "`n",
            [string[]]$fields
        )
    )
}

function Get-StringSha256 {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $sha = [Security.Cryptography.SHA256]::Create()

    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        $digest = $sha.ComputeHash($bytes)

        return (
            (
                $digest |
                ForEach-Object {
                    $_.ToString('x2')
                }
            ) -join ''
        )
    }
    finally {
        $sha.Dispose()
    }
}

if (
    [string]::IsNullOrWhiteSpace($SanitizedLabel) -or
    $SanitizedLabel.Length -gt 120 -or
    $SanitizedLabel -match '[\r\n]'
) {
    throw 'SanitizedLabel must contain 1-120 characters and no line breaks.'
}

$caseRoot = [IO.Path]::GetFullPath($CasePath)
$source = [IO.Path]::GetFullPath($SourceFile)

if (-not (Test-Path -LiteralPath $caseRoot -PathType Container)) {
    throw 'CasePath does not exist.'
}

if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw 'SourceFile does not exist.'
}

$caseFile = Join-Path $caseRoot 'case.json'
$indexFile = Join-Path $caseRoot 'evidence-index.json'
$custodyFile = Join-Path $caseRoot 'custody.ndjson'

foreach ($required in @(
    $caseFile,
    $indexFile,
    $custodyFile
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw 'Incident case workspace is incomplete.'
    }
}

$case = (
    Get-Content `
        -LiteralPath $caseFile `
        -Raw |
    ConvertFrom-Json
)

$index = (
    Get-Content `
        -LiteralPath $indexFile `
        -Raw |
    ConvertFrom-Json
)

if ([string]$case.case_id -ne [string]$index.case_id) {
    throw 'Case and evidence-index identifiers do not match.'
}

$existingEvidence = @($index.evidence)

if (
    $existingEvidence |
    Where-Object {
        [string]$_.evidence_id -eq $EvidenceId
    }
) {
    throw 'EvidenceId already exists in this case.'
}

$registeredAt = [DateTime]::UtcNow.ToString('o')

$fileInfo = Get-Item `
    -LiteralPath $source

$evidenceSha = (
    Get-FileHash `
        -LiteralPath $source `
        -Algorithm SHA256
).Hash.ToLowerInvariant()

$sizeBytes = [long]$fileInfo.Length

$custodyLines = @(
    Get-Content `
        -LiteralPath $custodyFile |
    Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    }
)

$sequence = $custodyLines.Count + 1
$previousHash = $null

if ($custodyLines.Count -gt 0) {
    $previousRecord = (
        $custodyLines[-1] |
        ConvertFrom-Json
    )

    $previousHash = [string]$previousRecord.record_sha256

    if (
        $previousHash -notmatch '^[0-9a-f]{64}$'
    ) {
        throw 'Existing custody chain contains an invalid record hash.'
    }
}

$canonicalPayload = Get-CanonicalCustodyPayload `
    -Sequence $sequence `
    -CaseId ([string]$case.case_id) `
    -EvidenceId $EvidenceId `
    -RecordedAtUtc $registeredAt `
    -PreviousRecordSha256 $previousHash `
    -EvidenceSha256 $evidenceSha `
    -EvidenceSizeBytes $sizeBytes `
    -SourceType $SourceType `
    -SanitizedLabel $SanitizedLabel

$recordHash = Get-StringSha256 `
    -Value $canonicalPayload

$custodyRecord = [ordered]@{
    schema_version = 1
    sequence = $sequence
    event_type = 'EVIDENCE_REGISTERED'
    case_id = [string]$case.case_id
    evidence_id = $EvidenceId
    recorded_at_utc = $registeredAt
    previous_record_sha256 = $previousHash
    evidence_sha256 = $evidenceSha
    evidence_size_bytes = $sizeBytes
    source_type = $SourceType
    sanitized_label = $SanitizedLabel
    record_sha256 = $recordHash
}

$newEvidence = [pscustomobject][ordered]@{
    evidence_id = $EvidenceId
    registered_at_utc = $registeredAt
    source_type = $SourceType
    sanitized_label = $SanitizedLabel
    sha256 = $evidenceSha
    size_bytes = $sizeBytes
    raw_content_retained = $false
}

$updatedEvidence = @(
    $existingEvidence +
    $newEvidence
)

$index.evidence = $updatedEvidence
$case.evidence_count = $updatedEvidence.Count
$case.custody_event_count = $sequence

$utf8NoBom = [Text.UTF8Encoding]::new($false)

$caseTemp = "$caseFile.$PID.tmp"
$indexTemp = "$indexFile.$PID.tmp"
$custodyTemp = "$custodyFile.$PID.tmp"

try {
    [IO.File]::WriteAllText(
        $indexTemp,
        (
            $index |
            ConvertTo-Json -Depth 10
        ),
        $utf8NoBom
    )

    [IO.File]::WriteAllText(
        $caseTemp,
        (
            $case |
            ConvertTo-Json -Depth 10
        ),
        $utf8NoBom
    )

    $newCustodyLines = @(
        $custodyLines +
        (
            $custodyRecord |
            ConvertTo-Json `
                -Compress `
                -Depth 8
        )
    )

    [IO.File]::WriteAllLines(
        $custodyTemp,
        $newCustodyLines,
        $utf8NoBom
    )

    Move-Item `
        -LiteralPath $indexTemp `
        -Destination $indexFile `
        -Force

    Move-Item `
        -LiteralPath $caseTemp `
        -Destination $caseFile `
        -Force

    Move-Item `
        -LiteralPath $custodyTemp `
        -Destination $custodyFile `
        -Force
}
finally {
    foreach ($temp in @(
        $caseTemp,
        $indexTemp,
        $custodyTemp
    )) {
        if (Test-Path -LiteralPath $temp) {
            Remove-Item `
                -LiteralPath $temp `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
}

Write-Output 'EVIDENCE_RECORD_ADDED=YES'
Write-Output 'RAW_EVIDENCE_COPIED=NO'
Write-Output 'SOURCE_PATH_RETAINED=NO'
Write-Output 'SOURCE_FILENAME_RETAINED=NO'
