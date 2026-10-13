# ADR-013 — Provider- and Domain-Separated Response Principals

## Status

Accepted for Feature 8D.

## Context

Feature 8C established that the existing read-only investigation principal is intentionally insufficient for live response.

The modeled response actions span three materially different privilege domains:

- identity controls in Microsoft Graph;
- application and OAuth controls in Microsoft Graph;
- endpoint remediation controls in Microsoft Defender for Endpoint.

Combining all response privileges into one principal would increase blast radius and weaken separation of duties.

## Decision

Design three separate future response principals.

- Graph identity response principal;
- Graph application and OAuth response principal;
- Defender endpoint response principal.

The current read-only investigation principal is not reused.

## Authentication design

Application context is the target runtime model for future unattended response automation.

Credential selection follows this preference:

1. managed identity where compatible;
2. workload identity federation where compatible;
3. certificate credential otherwise.

Production client secrets are prohibited by this design.

## Permission design

Feature 8D records candidate application permissions only for architectural planning.

Candidate permission names are not permission grants.

Ownership-sensitive application permissions remain unresolved until the exact response target is known.

No broader permission may be selected automatically.

## Role and consent design

Directory roles, Defender role requirements, admin consent, and target-specific privilege constraints are not assigned by this feature.

They must be explicitly resolved and authorized at a later provisioning gate.

## Consequences

The project gains a concrete least-privilege response identity architecture without creating a live destructive path.

Every planned response principal remains uncreated, unauthenticated, unconsented, unprivileged, and unable to execute response actions.
