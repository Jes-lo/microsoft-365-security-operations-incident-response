# ADR-001 — Security Operations Safety and Evidence Boundaries

## Status

Accepted.

## Context

Security operations and incident-response work can require elevated permissions, sensitive evidence, and high-impact containment actions.

A portfolio lab must demonstrate realistic operational discipline without introducing unnecessary tenant risk or publishing sensitive information.

## Decision

The project adopts the following boundaries:

1. Discovery and investigation are read-only by default.
2. Permissions are granted only when a specific feature demonstrates necessity.
3. Tenant-wide response actions are prohibited by default.
4. Controlled write operations require an explicit safety gate.
5. Destructive endpoint response actions are outside the default project boundary.
6. Sensitive raw evidence remains outside Git.
7. Public evidence is sanitized and minimized.
8. Missing licensed capabilities are classified rather than fabricated.
9. Environment-dependent runtime validation remains explicitly environment-dependent.
10. Security conclusions distinguish observed evidence from inference.

## Consequences

Some incident scenarios may remain partially validated when the existing tenant cannot expose a required signal.

This is preferred over enabling unnecessary licenses, privileges, or unsafe actions solely to create portfolio evidence.
