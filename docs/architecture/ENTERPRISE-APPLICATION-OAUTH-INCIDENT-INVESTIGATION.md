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

## Live validation outcome

Feature 5 was validated against the live tenant through the dedicated Microsoft Graph application using delegated read-only authentication.

The session used only `AuditLog.Read.All` as its required functional permission.

The validated surfaces were:

- application-related Microsoft Entra sign-ins;
- Microsoft Entra directory audit for application-management and OAuth-related activity.

Each source was bounded to a 24-hour lookback and a maximum of 25 returned records.

The validation performed exactly two Graph GET requests and zero tenant write requests.

Application-management events were isolated locally after the bounded directory-audit read.

The authenticated context contained zero missing required scopes, zero unexpected scopes, and zero write-capable scopes.

No current permission-grant inventory query was performed and no additional directory/application permission was introduced.

The live data was transformed through the Feature 5 privacy-preserving converter and validated through the Feature 3 SHA-256 and custody workflow.

Raw tenant identifiers, raw OAuth grant values, raw Graph responses, temporary live inputs, and live activity counts are intentionally not committed to Git.
