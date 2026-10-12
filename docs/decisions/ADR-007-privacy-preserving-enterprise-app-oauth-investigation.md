# ADR-007: Privacy-Preserving Enterprise Application and OAuth Investigation

## Status

Accepted for Feature 5 foundation.

## Context

Enterprise-application and OAuth investigations commonly expose tenant-specific application IDs, service-principal IDs, user identifiers, consent payloads, permission values, sign-in metadata, and other data that should not be committed to a public-facing portfolio artifact.

The investigation still needs enough correlation context to demonstrate realistic incident-analysis capability.

## Decision

Feature 5 uses ephemeral in-memory correlation aliases.

Application identities are transformed to `APP-NNN`.

Human subjects are transformed to `SUBJECT-NNN`.

The repository does not retain raw client IDs, service-principal IDs, user IDs, UPNs, IP addresses, event IDs, correlation IDs, OAuth grant values, or raw Microsoft Graph responses.

Consent and permission-change activity is represented through controlled categories and Boolean presence signals instead of raw grant payloads.

## Permission decision

Feature 5A reuses the already validated `AuditLog.Read.All` delegated scope.

No additional directory or application permission is introduced by the foundation.

Current application permission-grant inventory is not queried in this phase.

Any future requirement for an additional Graph permission requires an explicit least-privilege review before implementation.

## Evidence decision

Only sanitized summaries may enter the Feature 3 evidence workflow.

The evidence record stores a SHA-256 fingerprint and custody metadata while raw evidence copying remains disabled by default.

## Consequences

The portfolio can demonstrate enterprise-application and OAuth incident-investigation logic without publishing tenant identifiers or consent/grant content.

The trade-off is that some current-state application inventory questions remain outside the foundation until a justified permission boundary is approved.

## Live validation confirmation

The privacy-preserving enterprise-application and OAuth investigation design was subsequently validated against the live tenant.

The dedicated Microsoft Graph application successfully accessed the authorized sign-in and directory-audit surfaces using only the existing `AuditLog.Read.All` functional permission.

The session contained no unexpected or write-capable scopes and performed zero tenant writes.

Application-management events were isolated locally after the bounded directory-audit read.

The resulting live data passed the APP/SUBJECT alias transformation and Feature 3 evidence/custody workflow without retaining raw tenant identifiers, OAuth grant values, Graph responses, or live activity counts.

Current application permission-grant inventory remains deliberately outside the validated scope and was not queried.
