# Enterprise Application & OAuth Incident Investigation

## Purpose

Feature 5 provides a privacy-preserving investigation workflow for enterprise-application and OAuth-related security activity.

The foundation intentionally reuses the already validated `AuditLog.Read.All` delegated permission and does not introduce new Microsoft Graph permissions.

## Investigation surfaces

Feature 5A models two read-only sources:

- Microsoft Entra sign-ins associated with application activity;
- Microsoft Entra directory-audit events associated with application management and OAuth consent.

Both surfaces use existing audit-log access.

## Correlation model

Raw tenant application and subject identifiers are used only as ephemeral in-memory correlation keys.

Applications are represented in sanitized outputs as:

`APP-NNN`

Human subjects are represented as:

`SUBJECT-NNN`

The alias maps are not persisted.

## OAuth and permission-change handling

The converter does not retain raw OAuth grant values, permission payload values, client IDs, service-principal IDs, or Graph payloads.

Application-management activity is reduced to controlled categories such as:

- consent;
- permission change;
- service-principal change;
- application change;
- other application-management activity.

Modified-property names may be inspected only to determine whether a permission-, scope-, consent-, or OAuth-related change was present. Raw old/new property values are not retained.

## Evidence model

The sanitized investigation summary can be registered through the Feature 3 evidence workflow.

Evidence registration requires:

- SHA-256 fingerprinting;
- custody-chain integrity;
- no raw source copy by default.

## Live-validation boundary

Feature 5A performs no authentication or live Graph requests.

A later live phase may query only the two already-authorized audit surfaces under a bounded GET-only session.

Current enterprise-application permission-grant inventory is deliberately outside Feature 5A because querying additional directory or application inventory must not silently expand the Graph permission boundary.

If a later investigation genuinely requires an additional Graph permission, that requirement must be reviewed as a separate least-privilege gate rather than automatically granted.
