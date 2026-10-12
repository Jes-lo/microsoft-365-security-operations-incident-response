# Enterprise Application & OAuth Incident Investigation — Live Validation Evidence

## Validation status

Feature 5 live validation completed successfully using the dedicated read-only Microsoft Graph application.

The session used delegated authentication and the already approved `AuditLog.Read.All` permission.

No additional Microsoft Graph permission was introduced.

## Validated investigation surfaces

The live workflow successfully validated:

- Microsoft Entra sign-ins used for application-activity correlation;
- Microsoft Entra directory audit used for application-management and OAuth-related investigation.

Both surfaces were accessed through HTTP `GET`.

Application-management events were isolated locally after the bounded directory-audit read.

## Query boundary

The live validation used:

- a 24-hour lookback window;
- a maximum of 25 returned records per source;
- two Microsoft Graph GET requests in total.

No current application permission-grant inventory query was performed.

Live tenant activity counts are intentionally not retained in Git.

A response reaching the configured maximum must not be interpreted as a complete export of all events in the lookback period.

## Permission boundary

The required functional delegated permission was:

- `AuditLog.Read.All`.

The authenticated context contained:

- zero missing required scopes;
- zero unexpected scopes;
- zero write-capable scopes.

No new permission grant, directory role assignment, paid license, or trial activation was performed.

## Investigation transformation

The live responses were transformed using the Feature 5 privacy-preserving converter.

Application identities were represented only by ephemeral aliases of the form `APP-NNN`.

Human subjects were represented only by ephemeral aliases of the form `SUBJECT-NNN`.

Consent and permission-change activity was reduced to controlled classifications and Boolean presence indicators.

## Privacy boundary

The repository does not retain:

- application client IDs;
- service-principal IDs;
- Microsoft Entra user IDs;
- user principal names;
- IP addresses;
- event IDs;
- correlation IDs;
- raw OAuth grant values;
- raw modified-property values;
- raw Microsoft Graph responses;
- live tenant activity counts.

## Evidence and custody

The sanitized live investigation result was validated through the Feature 3 evidence workflow.

The validation confirmed:

- SHA-256 evidence fingerprinting;
- custody hash-chain integrity;
- no raw evidence retention.

The temporary raw live inputs and temporary sanitized investigation case were not committed to Git.

## Tenant modification boundary

Feature 5 live validation performed:

- two Graph GET requests;
- zero tenant write requests;
- zero destructive actions.

## Authentication lifecycle

The dedicated application and tenant context were validated before querying.

The Graph authentication context was disconnected after the live investigation.

The temporary WAM setting change used for the custom client authentication flow was restored to its original value.

## Evidence interpretation

This document demonstrates that the project can perform bounded, least-privilege, privacy-preserving enterprise-application and OAuth incident investigation against live Microsoft Entra audit data.

It is not a raw tenant export and contains no tenant-specific identifiers or live activity counts.
