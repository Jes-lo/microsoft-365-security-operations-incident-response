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
