[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CasePath
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
        [object]$Record
    )

    $previousRecordSha256 = if (
        $null -eq $Record.previous_record_sha256
    ) {
        $null
    }
    else {
        [string]$Record.previous_record_sha256
    }

    $canonicalRecordedAtUtc = (
        ConvertTo-CanonicalUtcTimestamp `
            -Value $Record.recorded_at_utc
    )

    $fields = @(
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'schema_version' `
                -Value ([int]$Record.schema_version)
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'sequence' `
                -Value ([int]$Record.sequence)
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'event_type' `
                -Value ([string]$Record.event_type)
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'case_id' `
                -Value ([string]$Record.case_id)
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'evidence_id' `
                -Value ([string]$Record.evidence_id)
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'recorded_at_utc' `
                -Value $canonicalRecordedAtUtc
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'previous_record_sha256' `
                -Value $previousRecordSha256
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'evidence_sha256' `
                -Value ([string]$Record.evidence_sha256)
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'evidence_size_bytes' `
                -Value ([long]$Record.evidence_size_bytes)
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'source_type' `
                -Value ([string]$Record.source_type)
        ),
        (
            ConvertTo-CanonicalCustodyField `
                -Name 'sanitized_label' `
                -Value ([string]$Record.sanitized_label)
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

$root = [IO.Path]::GetFullPath($CasePath)

$caseFile = Join-Path $root 'case.json'
$indexFile = Join-Path $root 'evidence-index.json'
$custodyFile = Join-Path $root 'custody.ndjson'

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

$evidence = @($index.evidence)

$custodyLines = @(
    Get-Content `
        -LiteralPath $custodyFile |
    Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    }
)

if ([int]$case.evidence_count -ne $evidence.Count) {
    throw 'Case evidence_count does not match evidence index.'
}

if ([int]$case.custody_event_count -ne $custodyLines.Count) {
    throw 'Case custody_event_count does not match custody log.'
}

if ($evidence.Count -ne $custodyLines.Count) {
    throw 'Evidence index and custody event count differ.'
}

$previousHash = $null

for ($i = 0; $i -lt $custodyLines.Count; $i++) {
    $record = (
        $custodyLines[$i] |
        ConvertFrom-Json
    )

    $expectedSequence = $i + 1

    if ([int]$record.sequence -ne $expectedSequence) {
        throw 'Custody sequence is invalid.'
    }

    if ([string]$record.case_id -ne [string]$case.case_id) {
        throw 'Custody case identifier mismatch.'
    }

    if ($i -eq 0) {
        if ($null -ne $record.previous_record_sha256) {
            throw 'First custody record must not have a previous hash.'
        }
    }
    else {
        if (
            [string]$record.previous_record_sha256 -ne
            [string]$previousHash
        ) {
            throw 'Custody previous-record hash chain is invalid.'
        }
    }

    $canonical = Get-CanonicalCustodyPayload `
        -Record $record

    $computedHash = Get-StringSha256 `
        -Value $canonical

    if (
        $computedHash -ne
        [string]$record.record_sha256
    ) {
        throw 'Custody record hash validation failed.'
    }

    $matchingEvidence = @(
        $evidence |
        Where-Object {
            [string]$_.evidence_id -eq
            [string]$record.evidence_id
        }
    )

    if ($matchingEvidence.Count -ne 1) {
        throw 'Custody record does not map to exactly one evidence item.'
    }

    if (
        [string]$matchingEvidence[0].sha256 -ne
        [string]$record.evidence_sha256
    ) {
        throw 'Evidence hash does not match custody record.'
    }

    if (
        [long]$matchingEvidence[0].size_bytes -ne
        [long]$record.evidence_size_bytes
    ) {
        throw 'Evidence size does not match custody record.'
    }

    if ($matchingEvidence[0].raw_content_retained -ne $false) {
        throw 'Evidence index claims raw content was retained.'
    }

    $previousHash = [string]$record.record_sha256
}

if ($case.raw_tenant_data_retained -ne $false) {
    throw 'Case metadata claims raw tenant data was retained.'
}

Write-Output 'INCIDENT_CASE_INTEGRITY=PASS'
Write-Output 'CUSTODY_HASH_CHAIN=PASS'
Write-Output 'RAW_EVIDENCE_RETENTION=NO'
