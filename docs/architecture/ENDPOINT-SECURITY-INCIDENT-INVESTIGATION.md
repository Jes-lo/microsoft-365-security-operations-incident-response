# Endpoint Security Incident Investigation

## Purpose

Feature 6 provides a privacy-preserving endpoint-security investigation workflow using the Microsoft Graph unified security alert and incident surfaces.

The foundation focuses on investigation and correlation.

It does not perform direct endpoint response actions.

## Investigation surfaces

Feature 6A models:

- `/security/alerts_v2` using the existing delegated `SecurityAlert.Read.All` permission;
- `/security/incidents` using the existing delegated `SecurityIncident.Read.All` permission.

Both surfaces are read-only and were previously classified as available by the project capability-discovery phase.

## Endpoint investigation boundary

Security alerts may contain evidence associated with devices, users, files, file hashes, processes, network indicators, registry activity, cloud applications, and other entities.

Feature 6A reduces that evidence to controlled categories and aliases.

The foundation does not claim direct device inventory access.

It does not isolate devices, offboard endpoints, quarantine files, submit files, modify incidents or alerts, or execute remediation.

## Correlation model

Raw identifiers are used only as ephemeral local correlation keys.

The sanitized alias formats are:

- `INCIDENT-NNN`;
- `ALERT-NNN`;
- `DEVICE-NNN`;
- `SUBJECT-NNN`.

Alias maps are not persisted.

Alerts correlate to incidents through sanitized incident aliases.

Endpoint-associated alerts can be identified from Microsoft Defender for Endpoint service-source classification or endpoint-oriented evidence categories.

## Evidence reduction

The converter retains controlled security metadata such as:

- severity;
- status;
- classification;
- determination;
- investigation state;
- service-source category;
- evidence type;
- evidence verdict;
- remediation-status observation;
- evidence roles;
- coarse operating-system family;
- MITRE technique count.

The converter does not retain free-form alert titles, descriptions, recommendations, comments, tags, hostnames, raw device IDs, raw user identifiers, IP addresses, MAC addresses, filenames, paths, hashes, URLs, command lines, or Graph payloads.

## Evidence integration

Sanitized summaries can be registered through the Feature 3 evidence workflow.

Registration requires:

- SHA-256 fingerprinting;
- custody hash-chain integrity;
- no raw source copy by default.

## Live-validation boundary

Feature 6A performs no Microsoft Graph authentication or requests.

A later live phase may use bounded GET requests to the already authorized alert and incident surfaces.

No write-capable permission, endpoint action, new role, paid license, or trial may be introduced automatically.

## Live validation confirmation

Feature 6 was subsequently validated against the live tenant through the dedicated Microsoft Graph application using delegated read-only authentication.

The live gate used only the existing `SecurityAlert.Read.All` and `SecurityIncident.Read.All` permissions and confirmed that no unexpected or write-capable scopes were present.

Exactly two bounded GET requests were performed: one against `/security/alerts_v2` and one against `/security/incidents`.

The query boundary used a 24-hour lookback, a maximum of 25 records per surface, and no pagination.

Both surfaces returned successful responses with zero matching records during the validation window.

That zero-result condition is treated as an available empty dataset rather than an unavailable capability, and no live telemetry was fabricated.

The zero-signal converter control path was validated separately using derived empty envelopes representing the already observed zero-record result. It produced no INCIDENT, ALERT, DEVICE, or SUBJECT aliases and created no synthetic security signal.

A sanitized live-observation summary then passed the Feature 3 SHA-256 and custody workflow. Raw Graph payloads and tenant- or endpoint-specific identifiers were not retained.

Feature 6 performed zero tenant writes, zero endpoint writes, zero endpoint response actions, zero alert or incident mutations, zero role assignments, and zero trial activations.

Direct endpoint inventory and endpoint response capabilities remain outside the validated Feature 6 scope.
