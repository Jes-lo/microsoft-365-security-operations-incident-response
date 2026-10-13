# ADR-008: Privacy-Preserving Endpoint Security Investigation

## Status

Accepted for Feature 6 foundation.

## Context

Endpoint-security alerts can expose sensitive operational data including device identifiers, hostnames, users, network addresses, file paths, filenames, hashes, process details, URLs, free-form descriptions, and remediation metadata.

A portfolio implementation should demonstrate realistic security investigation without publishing tenant- or endpoint-specific evidence.

## Decision

Feature 6 uses the Microsoft Graph unified security alert and incident surfaces strictly for investigation.

Raw incident, alert, device, and subject identifiers are transformed into ephemeral aliases.

The repository does not retain raw device names, user identifiers, IP or MAC addresses, filenames, paths, hashes, URLs, alert titles, descriptions, or Graph payloads.

Evidence is reduced to controlled categorical metadata.

## Endpoint-response decision

Feature 6A does not implement endpoint actions.

The following remain outside the foundation:

- device isolation;
- device offboarding;
- endpoint remediation execution;
- file quarantine;
- file submission;
- alert or incident mutation.

A later feature may model containment only behind an explicit authorization and safety gate.

## Permission decision

Feature 6A uses the existing read-only permissions:

- `SecurityAlert.Read.All`;
- `SecurityIncident.Read.All`.

No write-capable Graph permission is introduced.

## Evidence decision

Only sanitized summaries may be registered through the Feature 3 evidence workflow.

Feature 3 provides SHA-256 integrity and custody-chain validation without copying raw evidence into the repository.

## Consequences

The project can demonstrate endpoint-oriented alert and incident correlation while preserving a strict separation between investigation and containment.

Direct endpoint telemetry or response capabilities must not be claimed unless they are separately validated in a supported environment.

## Live validation confirmation

The privacy-preserving endpoint-security investigation design was subsequently validated against the live tenant.

The dedicated Microsoft Graph application successfully accessed both authorized unified security investigation surfaces using only the existing `SecurityAlert.Read.All` and `SecurityIncident.Read.All` delegated permissions.

The authentication context contained no missing, unexpected, or write-capable scopes.

The bounded live validation performed exactly two GET requests with a 24-hour lookback, a maximum of 25 records per surface, and no pagination.

Both authorized surfaces were available and returned zero matching records during the bounded window.

The zero-result condition was preserved as the truthful live result. No synthetic alert, incident, device, subject, or endpoint activity was introduced to make the validation appear populated.

The Feature 6 converter accepted the corresponding zero-signal control path without creating aliases, and the sanitized observation passed the Feature 3 SHA-256 and custody workflow.

No raw Graph payload, raw tenant identifier, raw endpoint identifier, network artifact, file artifact, alert title, or incident description was retained.

No tenant write, endpoint write, response action, alert mutation, incident mutation, new permission grant, role assignment, paid license, or trial activation was performed.

Direct endpoint inventory and endpoint response actions remain outside the validated Feature 6 boundary.
