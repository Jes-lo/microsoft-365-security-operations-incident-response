# Identity Security Incident Investigation

## Purpose

Feature 4 adds an identity-focused investigation workflow on top of the incident case and evidence foundation established by Feature 3.

Feature 4A builds the investigation and privacy model locally before any new live Microsoft Graph session is performed.

## Investigation surfaces

The identity investigation uses only Feature 2 surfaces already classified as available:

- Microsoft Entra sign-ins;
- Microsoft Entra directory audit;
- Microsoft Entra risk detections.

Microsoft Entra risky users remains outside the active investigation path because Feature 2 recorded that surface as `ACCESS_OR_LICENSE_DENIED`.

The project does not escalate privileges or licensing to bypass that boundary.

## Privacy-preserving correlation

Raw tenant identity values are useful during transient investigation but are not appropriate portfolio artifacts.

The transformation layer therefore performs in-memory correlation and emits deterministic session-local aliases such as:

`SUBJECT-001`

The sanitized investigation summary does not retain:

- user principal names;
- Microsoft Entra user object IDs;
- source event IDs;
- correlation IDs;
- IP addresses;
- raw Graph responses.

## Sanitized investigation content

The local investigation summary may retain:

- case ID;
- generated UTC timestamp;
- subject aliases;
- sign-in success/failure outcome;
- bounded risk level;
- directory-audit category/result;
- risk-detection event type, level and state;
- aggregate counts.

## Evidence integration

A sanitized investigation summary can be registered through the Feature 3 evidence interface.

Feature 3 then records:

- SHA-256;
- byte size;
- sanitized evidence label;
- tamper-evident custody event.

The raw source Graph payload is not copied into the case workspace by this workflow.

## Live validation boundary

Feature 4A performs no Graph authentication.

The later live-validation phase will reuse only already-approved read permissions required by the available Feature 2 surfaces.

The live phase remains:

- GET-only;
- bounded in lookback duration;
- bounded in record count;
- free of automatic role assignments;
- free of license or trial activation;
- free of investigation-time tenant writes.

## Separation of concerns

Feature 2 answered:

> Which security signal surfaces are available?

Feature 3 answered:

> How are cases and evidence integrity represented?

Feature 4 answers:

> How can identity signals be safely correlated and investigated without retaining tenant identifiers in the portfolio repository?
