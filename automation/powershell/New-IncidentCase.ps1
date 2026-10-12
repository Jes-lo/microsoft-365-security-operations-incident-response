[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^IR-[0-9]{8}-[A-Z0-9]{4,12}$')]
    [string]$CaseId,

    [Parameter(Mandatory)]
    [ValidateSet('SEV0', 'SEV1', 'SEV2', 'SEV3', 'SEV4')]
    [string]$Severity,

    [Parameter(Mandatory)]
    [string]$TitleSanitized,

    [Parameter(Mandatory)]
    [string]$RootPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (
    [string]::IsNullOrWhiteSpace($TitleSanitized) -or
    $TitleSanitized.Length -gt 120 -or
    $TitleSanitized -match '[\r\n]'
) {
    throw 'TitleSanitized must contain 1-120 characters and no line breaks.'
}

$root = [IO.Path]::GetFullPath($RootPath)

if (-not (Test-Path -LiteralPath $root)) {
    New-Item `
        -ItemType Directory `
        -Path $root `
        -Force |
        Out-Null
}

$casePath = Join-Path $root $CaseId

if (Test-Path -LiteralPath $casePath) {
    throw 'Incident case already exists.'
}

New-Item `
    -ItemType Directory `
    -Path $casePath |
    Out-Null

$openedAt = [DateTime]::UtcNow.ToString('o')

$case = [ordered]@{
    schema_version = 1
    case_id = $CaseId
    title_sanitized = $TitleSanitized
    severity = $Severity
    status = 'OPEN'
    opened_at_utc = $openedAt
    evidence_count = 0
    custody_event_count = 0
    raw_tenant_data_retained = $false
}

$evidenceIndex = [ordered]@{
    schema_version = 1
    case_id = $CaseId
    evidence = @()
}

$utf8NoBom = [Text.UTF8Encoding]::new($false)

[IO.File]::WriteAllText(
    (Join-Path $casePath 'case.json'),
    ($case | ConvertTo-Json -Depth 8),
    $utf8NoBom
)

[IO.File]::WriteAllText(
    (Join-Path $casePath 'evidence-index.json'),
    ($evidenceIndex | ConvertTo-Json -Depth 8),
    $utf8NoBom
)

[IO.File]::WriteAllText(
    (Join-Path $casePath 'custody.ndjson'),
    '',
    $utf8NoBom
)

Write-Output 'INCIDENT_CASE_CREATED=YES'
Write-Output 'RAW_TENANT_DATA_RETAINED=NO'
