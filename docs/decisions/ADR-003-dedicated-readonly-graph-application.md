# ADR-003 — Dedicated Read-Only Microsoft Graph Application

## Status

Accepted.

## Context

The default Microsoft Graph PowerShell enterprise application can contain delegated permissions previously authorized for unrelated administrative workflows.

Using that shared consent context would make it difficult to prove that this security-operations project operates with a narrowly bounded permission set.

Feature 2 therefore requires an independently controlled authentication boundary for live security-signal discovery.

## Decision

The project uses a dedicated single-tenant application named:

`PLAB-SecOps-Graph-ReadOnly`

For Feature 2C, its Graph authorization boundary is limited to delegated:

`AuditLog.Read.All`

The application identifiers are operational tenant data and are not retained in the repository.

The dedicated application was validated at runtime with:

- zero Graph write-capable scopes;
- zero unexpected Graph scopes;
- delegated authentication;
- two bounded Microsoft Graph GET requests;
- zero tenant write requests during the discovery probe.

## Microsoft Graph investigation surfaces

Feature 2C validated only:

- `GET /v1.0/auditLogs/directoryAudits?$top=1`
- `GET /v1.0/auditLogs/signIns?$top=1`

The project did not request `Directory.Read.All`.

## Configuration-write distinction

Creation and configuration of the dedicated application and delegated consent are controlled administrative configuration changes.

They are distinct from the security-signal discovery probe itself.

The live investigation probe performed no tenant write request.

## Assignment boundary

No claim is made that a user-to-enterprise-application assignment was successfully created.

The evidence for Feature 2C is the successfully authenticated dedicated application context and its validated runtime permission boundary.

## Privacy boundary

The repository does not retain:

- Application client ID;
- Tenant ID;
- service-principal Object ID;
- operator UPN;
- access tokens;
- refresh tokens;
- raw Graph responses;
- audit event identifiers;
- sign-in event identifiers.

## Consequences

Future Microsoft Graph security-signal permissions can be evaluated independently on this dedicated application.

Read-only permissions must continue to be added only through explicit feature-specific authorization gates.

Write-capable Graph permissions remain prohibited during capability discovery.
