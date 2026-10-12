[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CasePath,

    [Parameter(Mandatory = $true)]
    [string]$AlertsPath,

    [Parameter(Mandatory = $true)]
    [string]$IncidentsPath,

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

function ConvertTo-SafeEnumLikeValue {
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

    if ($text.Length -gt 64) {
        return $Fallback
    }

    if ($text -notmatch '^[A-Za-z0-9._-]+$') {
        return $Fallback
    }

    return $text
}

function Get-ServiceSourceCategory {
    param(
        [AllowNull()]
        [object]$Value
    )

    $text = ([string]$Value).Trim().ToLowerInvariant()

    switch ($text) {
        'microsoftdefenderforendpoint' {
            return 'MDE'
        }

        'microsoftdefenderforidentity' {
            return 'MDI'
        }

        'microsoftdefenderforoffice365' {
            return 'MDO'
        }

        'microsoftcloudappsecurity' {
            return 'MDCA'
        }

        'microsoftdefenderforcloudapps' {
            return 'MDCA'
        }

        'microsoftdefenderforcloud' {
            return 'MDFC'
        }

        'appgovernance' {
            return 'APP_GOVERNANCE'
        }

        'datalossprevention' {
            return 'DLP'
        }

        default {
            return 'OTHER_OR_UNKNOWN'
        }
    }
}

function Get-EvidenceTypeCategory {
    param(
        [AllowNull()]
        [object]$Value
    )

    $text = ([string]$Value).Trim().ToLowerInvariant()

    if ($text -match 'deviceevidence$') {
        return 'DEVICE'
    }

    if ($text -match 'userevidence$') {
        return 'USER'
    }

    if ($text -match 'filehashevidence$') {
        return 'FILE_HASH'
    }

    if ($text -match 'fileevidence$') {
        return 'FILE'
    }

    if ($text -match 'processevidence$') {
        return 'PROCESS'
    }

    if ($text -match 'ipevidence$') {
        return 'IP'
    }

    if ($text -match 'urlevidence$') {
        return 'URL'
    }

    if ($text -match 'registrykeyevidence$') {
        return 'REGISTRY_KEY'
    }

    if ($text -match 'registryvalueevidence$') {
        return 'REGISTRY_VALUE'
    }

    if ($text -match 'hostlogonsessionevidence$') {
        return 'HOST_LOGON_SESSION'
    }

    if ($text -match 'cloudapplicationevidence$') {
        return 'CLOUD_APPLICATION'
    }

    return 'OTHER'
}

function Get-OsFamily {
    param(
        [AllowNull()]
        [object]$Value
    )

    $text = ([string]$Value).Trim().ToLowerInvariant()

    if ($text -match '^windows') {
        return 'WINDOWS'
    }

    if (
        $text -match '^linux' -or
        $text -match 'ubuntu' -or
        $text -match 'debian' -or
        $text -match 'redhat' -or
        $text -match 'centos'
    ) {
        return 'LINUX'
    }

    if (
        $text -match 'macos' -or
        $text -match 'darwin'
    ) {
        return 'MACOS'
    }

    if ([string]::IsNullOrWhiteSpace($text)) {
        return 'UNKNOWN'
    }

    return 'OTHER'
}

function Get-ControlledRoleValues {
    param(
        [AllowNull()]
        [object]$Values
    )

    $result = @()

    foreach ($value in @($Values)) {
        $safe = ConvertTo-SafeEnumLikeValue `
            -Value $value

        if (
            $safe -ne 'UNKNOWN' -and
            $safe -notin $result
        ) {
            $result += $safe
        }
    }

    return @($result)
}

$script:IncidentAliases = @{}
$script:AlertAliases = @{}
$script:DeviceAliases = @{}
$script:SubjectAliases = @{}

$script:NextIncidentAlias = 1
$script:NextAlertAlias = 1
$script:NextDeviceAlias = 1
$script:NextSubjectAlias = 1

function Get-IncidentAlias {
    param(
        [AllowNull()]
        [object]$Key
    )

    $keyText = ([string]$Key).Trim()

    if ([string]::IsNullOrWhiteSpace($keyText)) {
        return 'INCIDENT-000'
    }

    if (-not $script:IncidentAliases.ContainsKey($keyText)) {
        $script:IncidentAliases[$keyText] = (
            'INCIDENT-{0:D3}' -f
            $script:NextIncidentAlias
        )

        $script:NextIncidentAlias++
    }

    return $script:IncidentAliases[$keyText]
}

function Get-AlertAlias {
    param(
        [AllowNull()]
        [object]$Key
    )

    $keyText = ([string]$Key).Trim()

    if ([string]::IsNullOrWhiteSpace($keyText)) {
        return 'ALERT-000'
    }

    if (-not $script:AlertAliases.ContainsKey($keyText)) {
        $script:AlertAliases[$keyText] = (
            'ALERT-{0:D3}' -f
            $script:NextAlertAlias
        )

        $script:NextAlertAlias++
    }

    return $script:AlertAliases[$keyText]
}

function Get-DeviceAlias {
    param(
        [AllowNull()]
        [object]$Key
    )

    $keyText = ([string]$Key).Trim()

    if ([string]::IsNullOrWhiteSpace($keyText)) {
        return 'DEVICE-000'
    }

    if (-not $script:DeviceAliases.ContainsKey($keyText)) {
        $script:DeviceAliases[$keyText] = (
            'DEVICE-{0:D3}' -f
            $script:NextDeviceAlias
        )

        $script:NextDeviceAlias++
    }

    return $script:DeviceAliases[$keyText]
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
            'SUBJECT-{0:D3}' -f
            $script:NextSubjectAlias
        )

        $script:NextSubjectAlias++
    }

    return $script:SubjectAliases[$keyText]
}

function Get-DeviceKeyFromEvidence {
    param(
        [AllowNull()]
        [object]$Evidence
    )

    foreach ($name in @(
        'mdeDeviceId',
        'azureAdDeviceId',
        'deviceDnsName',
        'hostName'
    )) {
        $value = Get-PropertyValue `
            -Object $Evidence `
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

function Get-SubjectKeyFromEvidence {
    param(
        [AllowNull()]
        [object]$Evidence
    )

    $userAccount = Get-PropertyValue `
        -Object $Evidence `
        -Name 'userAccount'

    foreach ($name in @(
        'azureAdUserId',
        'userSid',
        'userPrincipalName',
        'accountName'
    )) {
        $value = Get-PropertyValue `
            -Object $userAccount `
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

$caseFile = Join-Path `
    -Path $CasePath `
    -ChildPath 'case.json'

if (-not (Test-Path -LiteralPath $caseFile -PathType Leaf)) {
    throw 'Case metadata file not found.'
}

foreach ($inputFile in @(
    $AlertsPath,
    $IncidentsPath
)) {
    if (-not (Test-Path -LiteralPath $inputFile -PathType Leaf)) {
        throw 'Required local endpoint investigation input file not found.'
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

$alertInput = Get-Content `
    -LiteralPath $AlertsPath `
    -Raw |
    ConvertFrom-Json

$incidentInput = Get-Content `
    -LiteralPath $IncidentsPath `
    -Raw |
    ConvertFrom-Json

$alertRecords = @(
    Get-PropertyValue `
        -Object $alertInput `
        -Name 'value'
)

$incidentRecords = @(
    Get-PropertyValue `
        -Object $incidentInput `
        -Name 'value'
)

$safeAlerts = @()
$safeIncidents = @()

$incidentAlertCounts = @{}

$totalEvidenceCount = 0
$deviceEvidenceCount = 0
$userEvidenceCount = 0
$maliciousEvidenceCount = 0
$suspiciousEvidenceCount = 0
$endpointAssociatedAlertCount = 0

foreach ($alert in $alertRecords) {
    if ($null -eq $alert) {
        continue
    }

    $rawAlertId = Get-PropertyValue `
        -Object $alert `
        -Name 'id'

    $rawIncidentId = Get-PropertyValue `
        -Object $alert `
        -Name 'incidentId'

    $alertAlias = Get-AlertAlias `
        -Key $rawAlertId

    $incidentAlias = Get-IncidentAlias `
        -Key $rawIncidentId

    if (-not $incidentAlertCounts.ContainsKey($incidentAlias)) {
        $incidentAlertCounts[$incidentAlias] = 0
    }

    $incidentAlertCounts[$incidentAlias]++

    $serviceSourceCategory = Get-ServiceSourceCategory `
        -Value (
            Get-PropertyValue `
                -Object $alert `
                -Name 'serviceSource'
        )

    $evidenceSummary = @()
    $alertHasEndpointEvidence = $false

    foreach (
        $evidence in @(
            Get-PropertyValue `
                -Object $alert `
                -Name 'evidence'
        )
    ) {
        if ($null -eq $evidence) {
            continue
        }

        $evidenceType = Get-EvidenceTypeCategory `
            -Value (
                Get-PropertyValue `
                    -Object $evidence `
                    -Name '@odata.type'
            )

        $totalEvidenceCount++

        if ($evidenceType -eq 'DEVICE') {
            $deviceEvidenceCount++
            $alertHasEndpointEvidence = $true
        }

        if ($evidenceType -eq 'USER') {
            $userEvidenceCount++
        }

        if (
            $evidenceType -in @(
                'FILE',
                'FILE_HASH',
                'PROCESS',
                'REGISTRY_KEY',
                'REGISTRY_VALUE',
                'HOST_LOGON_SESSION'
            )
        ) {
            $alertHasEndpointEvidence = $true
        }

        $verdict = ConvertTo-SafeEnumLikeValue `
            -Value (
                Get-PropertyValue `
                    -Object $evidence `
                    -Name 'verdict'
            )

        if ($verdict -eq 'malicious') {
            $maliciousEvidenceCount++
        }

        if ($verdict -eq 'suspicious') {
            $suspiciousEvidenceCount++
        }

        $item = [ordered]@{
            evidence_type = $evidenceType
            verdict = $verdict
            remediation_status = ConvertTo-SafeEnumLikeValue `
                -Value (
                    Get-PropertyValue `
                        -Object $evidence `
                        -Name 'remediationStatus'
                )
            roles = @(
                Get-ControlledRoleValues `
                    -Values (
                        Get-PropertyValue `
                            -Object $evidence `
                            -Name 'roles'
                    )
            )
        }

        if ($evidenceType -eq 'DEVICE') {
            $deviceAlias = Get-DeviceAlias `
                -Key (
                    Get-DeviceKeyFromEvidence `
                        -Evidence $evidence
                )

            $item['device_alias'] = $deviceAlias

            $item['os_family'] = Get-OsFamily `
                -Value (
                    Get-PropertyValue `
                        -Object $evidence `
                        -Name 'osPlatform'
                )
        }

        if ($evidenceType -eq 'USER') {
            $subjectAlias = Get-SubjectAlias `
                -Key (
                    Get-SubjectKeyFromEvidence `
                        -Evidence $evidence
                )

            $item['subject_alias'] = $subjectAlias
        }

        $evidenceSummary += $item
    }

    $endpointAssociated = (
        $serviceSourceCategory -eq 'MDE' -or
        $alertHasEndpointEvidence
    )

    if ($endpointAssociated) {
        $endpointAssociatedAlertCount++
    }

    $mitreValues = @(
        Get-PropertyValue `
            -Object $alert `
            -Name 'mitreTechniques'
    )

    $safeAlerts += [ordered]@{
        alert_alias = $alertAlias
        incident_alias = $incidentAlias
        created_at_utc = ConvertTo-NormalizedUtcTimestamp `
            -Value (
                Get-PropertyValue `
                    -Object $alert `
                    -Name 'createdDateTime'
            )
        last_update_at_utc = ConvertTo-NormalizedUtcTimestamp `
            -Value (
                Get-PropertyValue `
                    -Object $alert `
                    -Name 'lastUpdateDateTime'
            )
        severity = ConvertTo-SafeEnumLikeValue `
            -Value (
                Get-PropertyValue `
                    -Object $alert `
                    -Name 'severity'
            )
        status = ConvertTo-SafeEnumLikeValue `
            -Value (
                Get-PropertyValue `
                    -Object $alert `
                    -Name 'status'
            )
        classification = ConvertTo-SafeEnumLikeValue `
            -Value (
                Get-PropertyValue `
                    -Object $alert `
                    -Name 'classification'
            )
        determination = ConvertTo-SafeEnumLikeValue `
            -Value (
                Get-PropertyValue `
                    -Object $alert `
                    -Name 'determination'
            )
        investigation_state = ConvertTo-SafeEnumLikeValue `
            -Value (
                Get-PropertyValue `
                    -Object $alert `
                    -Name 'investigationState'
            )
        service_source_category = $serviceSourceCategory
        endpoint_associated = $endpointAssociated
        mitre_technique_count = $mitreValues.Count
        evidence = @($evidenceSummary)
    }
}

foreach ($incident in $incidentRecords) {
    if ($null -eq $incident) {
        continue
    }

    $incidentAlias = Get-IncidentAlias `
        -Key (
            Get-PropertyValue `
                -Object $incident `
                -Name 'id'
        )

    $correlatedAlertCount = 0

    if ($incidentAlertCounts.ContainsKey($incidentAlias)) {
        $correlatedAlertCount = [int]$incidentAlertCounts[$incidentAlias]
    }

    $safeIncidents += [ordered]@{
        incident_alias = $incidentAlias
        created_at_utc = ConvertTo-NormalizedUtcTimestamp `
            -Value (
                Get-PropertyValue `
                    -Object $incident `
                    -Name 'createdDateTime'
            )
        last_update_at_utc = ConvertTo-NormalizedUtcTimestamp `
            -Value (
                Get-PropertyValue `
                    -Object $incident `
                    -Name 'lastUpdateDateTime'
            )
        severity = ConvertTo-SafeEnumLikeValue `
            -Value (
                Get-PropertyValue `
                    -Object $incident `
                    -Name 'severity'
            )
        status = ConvertTo-SafeEnumLikeValue `
            -Value (
                Get-PropertyValue `
                    -Object $incident `
                    -Name 'status'
            )
        classification = ConvertTo-SafeEnumLikeValue `
            -Value (
                Get-PropertyValue `
                    -Object $incident `
                    -Name 'classification'
            )
        determination = ConvertTo-SafeEnumLikeValue `
            -Value (
                Get-PropertyValue `
                    -Object $incident `
                    -Name 'determination'
            )
        correlated_alert_count = $correlatedAlertCount
    }
}

$output = [ordered]@{
    schema_version = 1
    feature = 6
    case_id = $caseId
    generated_at_utc = [DateTime]::UtcNow.ToString(
        'yyyy-MM-ddTHH:mm:ss.fffffffZ',
        [Globalization.CultureInfo]::InvariantCulture
    )
    investigation_type = 'ENDPOINT_SECURITY'
    investigation_boundary = [ordered]@{
        unified_security_alert_and_incident_analysis = $true
        direct_endpoint_inventory_query = $false
        endpoint_response_action = $false
        tenant_remediation_execution = $false
    }
    privacy = [ordered]@{
        incident_alias_mode = 'IN_MEMORY_ONLY'
        alert_alias_mode = 'IN_MEMORY_ONLY'
        device_alias_mode = 'IN_MEMORY_ONLY'
        subject_alias_mode = 'IN_MEMORY_ONLY'
        raw_alert_ids_retained = $false
        raw_incident_ids_retained = $false
        raw_device_ids_retained = $false
        raw_device_names_retained = $false
        raw_user_ids_retained = $false
        raw_upns_retained = $false
        raw_ip_addresses_retained = $false
        raw_mac_addresses_retained = $false
        raw_file_names_retained = $false
        raw_file_paths_retained = $false
        raw_file_hashes_retained = $false
        raw_urls_retained = $false
        raw_titles_or_descriptions_retained = $false
        raw_graph_payloads_retained = $false
    }
    counts = [ordered]@{
        incident_records = $safeIncidents.Count
        alert_records = $safeAlerts.Count
        incident_alias_count = $script:IncidentAliases.Count
        alert_alias_count = $script:AlertAliases.Count
        device_alias_count = $script:DeviceAliases.Count
        subject_alias_count = $script:SubjectAliases.Count
        evidence_records = $totalEvidenceCount
        device_evidence_records = $deviceEvidenceCount
        user_evidence_records = $userEvidenceCount
        malicious_evidence_records = $maliciousEvidenceCount
        suspicious_evidence_records = $suspiciousEvidenceCount
        endpoint_associated_alerts = $endpointAssociatedAlertCount
    }
    incidents = @($safeIncidents)
    alerts = @($safeAlerts)
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
    ConvertTo-Json -Depth 20

[IO.File]::WriteAllText(
    $outputFullPath,
    $json + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)

Write-Output 'ENDPOINT_SECURITY_SIGNAL_CONVERSION=PASS'
Write-Output 'RAW_ENDPOINT_IDENTIFIER_RETENTION=NO'
Write-Output 'RAW_SUBJECT_IDENTIFIER_RETENTION=NO'
Write-Output 'RAW_FILE_NETWORK_ARTIFACT_RETENTION=NO'
Write-Output 'ENDPOINT_RESPONSE_ACTION=NO'
