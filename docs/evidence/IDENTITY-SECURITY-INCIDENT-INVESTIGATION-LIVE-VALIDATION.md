# Identity Security Incident Investigation — Live Validation Evidence

## Validation status

Feature 4 live validation completed successfully against the dedicated read-only Microsoft Graph application.

The validation used delegated authentication and the existing approved read-only permission boundary.

## Validated investigation surfaces

The following Microsoft Entra investigation surfaces were successfully queried:

- sign-ins;
- directory audit;
- risk detections.

Each query used HTTP `GET`.

## Query boundary

The live validation was bounded to:

- a 24-hour lookback window;
- a maximum of 25 returned records per investigation surface;
- three Graph GET requests in total.

The returned tenant activity counts are intentionally not persisted in Git.

A returned result reaching the configured maximum must not be interpreted as the complete event population for the lookback window.

## Permission boundary

The functional delegated permissions required for this validation were:

- `AuditLog.Read.All`;
- `IdentityRiskEvent.Read.All`.

The authenticated context contained:

- zero missing required functional scopes;
- zero unexpected scopes;
- zero write-capable scopes.

No new permission grant was introduced by Feature 4.

## Excluded surface

The `entra-risky-users` surface was not queried.

Its previously established `ACCESS_OR_LICENSE_DENIED` boundary remains unchanged.

No privilege escalation, role assignment, paid license, or trial activation was performed to bypass that boundary.

## Privacy boundary

The repository does not retain:

- user principal names;
- Microsoft Entra user object IDs;
- IP addresses;
- event IDs;
- correlation IDs;
- access tokens;
- raw Microsoft Graph responses;
- live tenant activity counts.

Only sanitized validation facts required to demonstrate the investigation capability are retained.

## Tenant modification boundary

Feature 4 live validation performed:

- three GET requests;
- zero tenant write requests;
- zero destructive actions.

## Authentication lifecycle

The dedicated application and tenant context were validated before querying.

The authentication context was disconnected after validation.

The temporary Microsoft Graph SDK WAM setting change used for the custom application flow was restored to its original value after the session.

## Evidence interpretation

This document demonstrates that the identity investigation workflow can safely reach the three authorized identity-security surfaces under least-privilege, bounded, read-only conditions.

It does not represent a complete export of tenant activity and contains no raw tenant evidence.
