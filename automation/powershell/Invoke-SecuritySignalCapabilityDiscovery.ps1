[CmdletBinding()]
param(
    [Parameter()]
    [string]$CapabilityConfigPath = (
        Join-Path $PSScriptRoot "../../configs/security-signal-capabilities.json"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-HttpStatusCodeFromException {
    param(
        [Parameter(Mandatory)]
        [System.Exception]$Exception
    )

    $statusCode = $null

    if ($null -ne $Exception.Response) {
        try {
            $statusCode = [int]$Exception.Response.StatusCode
        }
        catch {
            $statusCode = $null
        }
    }

    return $statusCode
}

if (-not (Test-Path -LiteralPath $CapabilityConfigPath -PathType Leaf)) {
    throw "Capability configuration file was not found."
}

if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
    throw "Microsoft Graph PowerShell context command is unavailable."
}

if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
    throw "Microsoft Graph request command is unavailable."
}

$config = Get-Content `
    -LiteralPath $CapabilityConfigPath `
    -Raw |
    ConvertFrom-Json

if ($config.discovery_mode -ne "read-only") {
    throw "Capability configuration is not read-only."
}

if ($config.tenant_write_allowed -ne $false) {
    throw "Tenant writes are prohibited for Feature 2 discovery."
}

$context = Get-MgContext

if ($null -eq $context) {
    throw "No Microsoft Graph session is active. This script does not authenticate automatically."
}

$currentScopes = @(
    $context.Scopes |
        ForEach-Object { [string]$_ }
)

$results = foreach ($capability in $config.capabilities) {

    if ($capability.method -ne "GET") {
        throw "Non-GET capability found in read-only discovery configuration."
    }

    if ($capability.tenant_write_allowed -ne $false) {
        throw "Write-enabled capability found in read-only discovery configuration."
    }

    $requiredPermission = [string]$capability.least_privileged_delegated_permission

    $permissionPresent = $currentScopes -contains $requiredPermission

    if (-not $permissionPresent) {
        [pscustomobject]@{
            CapabilityId       = [string]$capability.id
            Domain             = [string]$capability.domain
            RequiredPermission = $requiredPermission
            PermissionPresent  = $false
            HttpStatus         = $null
            RecordCount        = $null
            Classification     = "PERMISSION_REQUIRED"
        }

        continue
    }

    try {
        $response = Invoke-MgGraphRequest `
            -Method GET `
            -Uri ([string]$capability.endpoint) `
            -OutputType PSObject

        $recordCount = 0

        if ($null -ne $response.value) {
            $recordCount = @($response.value).Count
        }

        [pscustomobject]@{
            CapabilityId       = [string]$capability.id
            Domain             = [string]$capability.domain
            RequiredPermission = $requiredPermission
            PermissionPresent  = $true
            HttpStatus         = 200
            RecordCount        = $recordCount
            Classification     = "AVAILABLE"
        }
    }
    catch {
        $statusCode = Get-HttpStatusCodeFromException `
            -Exception $_.Exception

        $classification = switch ($statusCode) {
            401 { "AUTHENTICATION_REQUIRED" }
            403 { "ROLE_OR_ACCESS_DENIED" }
            404 { "LICENSE_OR_PRODUCT_DEFERRED" }
            default { "QUERY_FAILED" }
        }

        [pscustomobject]@{
            CapabilityId       = [string]$capability.id
            Domain             = [string]$capability.domain
            RequiredPermission = $requiredPermission
            PermissionPresent  = $true
            HttpStatus         = $statusCode
            RecordCount        = $null
            Classification     = $classification
        }
    }
}

$results |
    Sort-Object CapabilityId |
    Format-Table `
        CapabilityId,
        Domain,
        RequiredPermission,
        PermissionPresent,
        HttpStatus,
        RecordCount,
        Classification `
        -AutoSize
