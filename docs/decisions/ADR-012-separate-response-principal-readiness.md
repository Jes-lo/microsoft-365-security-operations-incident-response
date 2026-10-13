# ADR-012 — Keep Investigation and Response Principals Separate

## Status

Accepted for Feature 8C.

## Context

The project already has a read-only investigation boundary.

Containment and eradication require permissions that can invalidate sessions, disable access, change credentials, remove grants, isolate endpoints, or quarantine files.

Adding those capabilities to the same principal used for investigation would materially increase blast radius.

## Decision

The existing read-only investigation principal will not be upgraded into a live-response principal by Feature 8C.

Any future live response capability requires a separate response application or equivalent independently governed principal.

## Permission discovery

Feature 8C records documented public permission names required by the modeled response actions.

Discovery is not consent.

Discovery is not a permission grant.

Discovery is not proof that a capability is currently licensed or available in the tenant.

Discovery is not authorization to execute.

## API separation

Microsoft Graph and Microsoft Defender for Endpoint are modeled as separate permission surfaces.

Defender endpoint-response permissions are not assumed to be covered by Microsoft Graph security-read scopes.

## Fail-closed state

Every response capability remains:

`live_execution_readiness = BLOCKED`

Every discovered permission remains:

`permission_grant_status = NOT_GRANTED_BY_FEATURE_8C`

The global execution state remains:

`NOT_RELEASED`

## Future review

Before any permission is granted, current Microsoft documentation must be reviewed again because API permissions, licensing, roles, and operational prerequisites can change.

A later feature must explicitly define the separate response principal and present the exact permission/role changes for human approval before any tenant mutation.
