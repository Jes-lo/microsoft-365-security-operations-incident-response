# Cross-Signal Correlation — Live Validation

## Classification

This document contains sanitized, repository-safe validation facts only.

It contains no raw Microsoft Graph response, tenant identifier, application identifier, user identifier, device identifier, network indicator, file artifact, access token, account name, or raw cross-domain correlation identifier.

Exact live activity counts are intentionally not retained in the repository.

## Validation objective

Feature 7B validated that the privacy-preserving cross-signal correlation workflow can consume fresh sanitized outputs from the previously validated identity, enterprise-application/OAuth, and endpoint-security investigation layers and produce a deterministic incident timeline.

The validation reused only previously authorized delegated read-only Microsoft Graph permissions.

No new Graph permission, role assignment, trial activation, tenant write, endpoint action, or response action was performed.

## Live read boundary

The validation used:

- delegated read-only authentication;
- a bounded 24-hour lookback;
- five Microsoft Graph GET requests;
- a maximum of 25 records per queried surface;
- no pagination following;
- no persistent execution-policy change;
- no device-code authentication.

The five observed surface states were:

- Entra sign-ins: `NONZERO`;
- Entra directory audit: `NONZERO`;
- Entra risk detections: `ZERO`;
- Defender alerts: `ZERO`;
- Defender incidents: `ZERO`.

These values are state classifications only. Exact live tenant activity counts are not committed.

## Sanitization result

The live inputs were passed through the existing Feature 4, Feature 5, and Feature 6 sanitization layers before Feature 7 correlation.

The sanitized domain states were:

- identity investigation summary: `NONZERO`;
- enterprise-application/OAuth investigation summary: `NONZERO`;
- endpoint-security investigation summary: `ZERO`;
- cross-signal timeline: `NONZERO`.

The endpoint zero-signal state was preserved truthfully. No endpoint alert or incident was fabricated.

## Correlation result

The Feature 7 correlator successfully processed the live sanitized summaries.

The same sanitized inputs produced byte-identical correlation output across repeated conversion, validating deterministic timeline generation.

No explicit live cross-domain entity binding was attempted.

Equal domain-local alias text was not used as an entity join.

All live events remained unbound unless an explicit sanitized binding existed.

Temporal correlation therefore remained independent from entity identity.

## Zero-signal regression

Live validation exposed an implementation defect in the original Feature 7A correlator: a required JSON property containing an empty array could be collapsed to a null-like result by PowerShell pipeline semantics.

The correlator was corrected with a required-array accessor that distinguishes:

- a missing required property;
- a null property;
- a non-array property;
- a valid empty array.

A dedicated all-zero regression test now verifies that valid empty investigation collections are accepted without fabricating events or aliases.

## Privacy validation

The sanitized live outputs passed repository-side scans for:

- GUID-like identifiers;
- email or user-principal-name-like values;
- URL-like values;
- IPv4-like values;
- MAC-address-like values;
- common hash-like values.

Raw Graph payloads were not retained.

Temporary raw live inputs, sanitized summaries, correlation outputs, and the temporary incident case were destroyed after validation.

## Feature 3 evidence integrity

The sanitized Feature 7 correlation result was registered through the Feature 3 incident evidence workflow in an ephemeral incident case.

Validation confirmed:

- incident-case integrity;
- SHA-256 evidence binding;
- custody hash-chain integrity;
- raw evidence retention disabled.

The ephemeral case and evidence material were removed after validation.

## Safety outcome

Feature 7B completed with:

- five successful read-only Graph GET requests;
- zero tenant writes;
- zero endpoint actions;
- zero response actions;
- zero new permission grants;
- zero role assignments;
- zero trial activations;
- no raw Graph payload committed;
- no live identifiers committed.

Feature 7 is therefore live-validated and ready for closure.
