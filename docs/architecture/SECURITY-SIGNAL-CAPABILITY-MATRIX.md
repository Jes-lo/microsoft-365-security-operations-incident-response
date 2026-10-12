# Security Signal Capability Matrix

## Purpose

Feature 2 discovers which Microsoft 365 security investigation surfaces are actually available in the controlled lab environment.

Availability is never assumed from product documentation alone.

The project separates:

- API existence;
- delegated permission requirements;
- Microsoft Entra role requirements;
- product or license requirements;
- signal availability;
- tenant data retention;
- actual live validation.

## Initial signal surfaces

| Capability | Microsoft Graph surface | Least-privileged delegated permission | Initial licensing boundary |
| --- | --- | --- | --- |
| Entra directory audit | `/auditLogs/directoryAudits` | `AuditLog.Read.All` | No explicit premium requirement recorded for the list API |
| Entra sign-ins | `/auditLogs/signIns` | `AuditLog.Read.All` | Microsoft Entra ID P1 or P2 for Graph sign-in-log access |
| Defender alerts | `/security/alerts_v2` | `SecurityAlert.Read.All` | Product and available-signal dependent |
| Defender incidents | `/security/incidents` | `SecurityIncident.Read.All` | Product and available-signal dependent |
| Entra risky users | `/identityProtection/riskyUsers` | `IdentityRiskyUser.Read.All` | Microsoft Entra ID P2 |
| Entra risk detections | `/identityProtection/riskDetections` | `IdentityRiskEvent.Read.All` | Microsoft Entra ID P1 or P2 |

## Discovery classifications

Live discovery may produce only sanitized classifications:

- `AVAILABLE`
- `PERMISSION_REQUIRED`
- `ROLE_OR_ACCESS_DENIED`
- `LICENSE_OR_PRODUCT_DEFERRED`
- `ENVIRONMENT_DEFERRED`
- `AUTHENTICATION_REQUIRED`
- `QUERY_FAILED`

A zero-result response is not equivalent to an unavailable capability.

For example, an API can be available while the tenant currently contains zero matching alerts or incidents.

## Privacy boundary

The capability probe must not emit:

- tenant IDs;
- user IDs;
- object IDs;
- alert IDs;
- incident IDs;
- device IDs;
- IP addresses;
- user principal names;
- email addresses;
- access tokens;
- raw Microsoft Graph responses.

Only capability names, permission names, HTTP classifications, and sanitized record counts may be emitted.

## Mutation boundary

Every capability in the Feature 2 matrix is GET-only.

Feature 2 does not:

- acknowledge or modify incidents;
- update alerts;
- mark users compromised or safe;
- revoke sessions;
- disable accounts;
- modify enterprise applications;
- perform endpoint response actions.

Those operations require later explicit response safety gates.

## Feature 2C — Dedicated read-only Graph application

Live Microsoft Graph discovery uses a dedicated project application rather than relying on the shared Microsoft Graph PowerShell consent context.

For the AuditLog stage, the validated authorization boundary was delegated `AuditLog.Read.All` with:

- zero write-capable scopes;
- zero unexpected scopes;
- two GET requests;
- zero investigation-time tenant writes.

Directory audit and sign-in investigation surfaces both returned successful HTTP responses and are classified as `AVAILABLE`.

The dedicated application is intentionally extensible only through later explicit read-only authorization gates.

Microsoft Defender alerts, Microsoft Defender incidents, risky users, and risk detections remain outside the Feature 2C authorization boundary.

## Feature 2 completion — Remaining security signals

The dedicated project Graph application provides one isolated authentication boundary for all six modeled Feature 2 investigation surfaces.

The functional delegated read-permission set is:

- `AuditLog.Read.All`
- `SecurityAlert.Read.All`
- `SecurityIncident.Read.All`
- `IdentityRiskyUser.Read.All`
- `IdentityRiskEvent.Read.All`

No Graph write permission belongs to capability discovery.

Final sanitized live classifications:

- Microsoft Entra directory audit — `AVAILABLE`
- Microsoft Entra sign-ins — `AVAILABLE`
- Microsoft Defender alerts — `AVAILABLE`
- Microsoft Defender incidents — `AVAILABLE`
- Microsoft Entra risk detections — `AVAILABLE`
- Microsoft Entra risky users — `ACCESS_OR_LICENSE_DENIED`

Live capability state is distinct from configured permissions so that licensing, role restrictions, product availability, and empty datasets are not misrepresented.

Feature 2 is complete when every modeled capability has a sanitized live classification; universal availability is not required.
