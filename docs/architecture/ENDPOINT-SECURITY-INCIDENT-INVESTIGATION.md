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
