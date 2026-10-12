# ADR-006 — Privacy-Preserving Identity Investigation

## Status

Accepted for Feature 4 foundation.

## Context

Identity incident investigation commonly requires correlating sign-in activity, directory changes, and identity-risk signals around the same user.

Persisting user principal names, object IDs, IP addresses, or full Graph responses would unnecessarily expose tenant information.

## Decision

Identity signals are correlated transiently in memory and emitted using session-local subject aliases.

The sanitized investigation output retains only the minimum categories required to demonstrate investigation logic.

Raw identifiers are not included in the generated investigation summary.

## Signal boundary

Feature 4 uses only the Feature 2 surfaces already classified as `AVAILABLE`:

- sign-ins;
- directory audit;
- risk detections.

The risky-user surface remains excluded because its Feature 2 classification is `ACCESS_OR_LICENSE_DENIED`.

## Evidence boundary

Only the sanitized investigation summary is eligible for registration through the Feature 3 evidence interface.

Its SHA-256 and custody metadata may be retained in the local incident case.

The underlying raw security payload is not copied into the portfolio repository.

## Authorization boundary

Feature 4A introduces no authentication or tenant API request.

A later live-validation phase may use existing approved delegated read permissions only.

No Graph write permission, new role assignment, paid license, or trial activation is authorized by this ADR.

## Consequence

The portfolio can demonstrate meaningful identity-security correlation while preserving tenant privacy and existing least-privilege boundaries.

## Live validation confirmation

The privacy-preserving design was subsequently validated against the live tenant.

The dedicated application successfully accessed the three authorized identity investigation surfaces using delegated read-only permissions.

No write-capable or unexpected scopes were present.

No raw tenant identifiers, raw Graph payloads, or live activity counts are committed as portfolio artifacts.

The risky-users access/license boundary remains unchanged.
