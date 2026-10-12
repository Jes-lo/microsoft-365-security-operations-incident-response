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
