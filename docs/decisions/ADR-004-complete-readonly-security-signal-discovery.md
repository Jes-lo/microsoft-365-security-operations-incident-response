# ADR-004 — Complete Read-Only Security Signal Discovery

## Status

Accepted.

## Context

Feature 2 established a dedicated single-tenant Microsoft Graph application so security-operations discovery permissions remain isolated from unrelated administrative consent.

Microsoft Entra directory-audit and sign-in discovery had already been validated with delegated `AuditLog.Read.All`.

The remaining modeled investigation surfaces were:

- Microsoft Defender alerts;
- Microsoft Defender incidents;
- Microsoft Entra risky users;
- Microsoft Entra risk detections.

## Decision

The dedicated project application uses these functional delegated read permissions:

- `AuditLog.Read.All`
- `SecurityAlert.Read.All`
- `SecurityIncident.Read.All`
- `IdentityRiskyUser.Read.All`
- `IdentityRiskEvent.Read.All`

No Graph write permission belongs to the Feature 2 capability-discovery boundary.

## Runtime boundary

The remaining-signal probe validated:

- all five expected functional read scopes;
- zero write-capable scopes;
- zero unexpected scopes;
- four bounded Microsoft Graph GET requests;
- zero investigation-time tenant write requests;
- no retention of raw Graph responses.

## Capability interpretation

Feature 2 distinguishes configured authorization from runtime service availability.

Valid sanitized outcomes are:

- `AVAILABLE`
- `ACCESS_OR_LICENSE_DENIED`
- `ENDPOINT_OR_PRODUCT_UNAVAILABLE`

A denied surface is not bypassed by enabling a trial, purchasing a license, assigning an additional role, or broadening permissions.

## Observed boundary

The live probe classified:

- Microsoft Defender alerts as `AVAILABLE`;
- Microsoft Defender incidents as `AVAILABLE`;
- Microsoft Entra risk detections as `AVAILABLE`;
- Microsoft Entra risky users as `ACCESS_OR_LICENSE_DENIED`.

The project does not infer a more specific cause for the risky-user HTTP 403 without additional evidence.

## Administrative configuration distinction

Adding delegated permissions and granting admin consent are controlled tenant configuration changes.

Those changes are separate from the GET-only investigation-time probes.

## Privacy

The repository does not retain:

- Application client ID;
- Tenant ID;
- service-principal Object ID;
- operator UPN;
- access or refresh tokens;
- raw Graph responses;
- alert or incident identifiers;
- user identifiers;
- risk-event identifiers.

## Consequence

Feature 2 closes with evidence-based live classifications for all six modeled security-signal surfaces without privilege escalation.
