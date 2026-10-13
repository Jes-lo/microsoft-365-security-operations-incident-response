# Microsoft 365 Security Operations & Incident Response

A security operations and incident response portfolio project for Microsoft 365, designed as an independent controlled lab implementation.

The project focuses on detecting, investigating, correlating, containing, eradicating, recovering from, and documenting security incidents while preserving least privilege, evidence privacy, tenant safety, and reproducibility.

## Project status

Feature 8 — Containment & Eradication — simulation foundation complete. The project now models deterministic containment and eradication plans for sanitized SUBJECT, APP, DEVICE, and FILE aliases while keeping every response action in NOT_EXECUTED state. The planner is local-only, accepts SIMULATION_ONLY requests, rejects live authorization, uses controlled reason categories, defers exact write-capability resolution to a future explicit action gate, and integrates simulated plans with the Feature 3 SHA-256/custody workflow. No Microsoft Graph authentication or requests, tenant writes, endpoint actions, response actions, new permissions, role assignments, or trial activations are part of Feature 8A.

The repository is initially private while implementation and validation are in progress.

## Core technologies

- Microsoft 365
- Microsoft Entra ID
- Microsoft Defender
- Microsoft Graph
- PowerShell
- Bash
- JSON
- GitHub Actions
- Git

Additional Microsoft security capabilities are used only when they are available in the existing lab environment without requiring paid upgrades or trial activation.

## Security operations model

The project follows this lifecycle:

1. Signal collection and capability discovery.
2. Detection and triage.
3. Investigation and evidence normalization.
4. Cross-signal correlation.
5. Containment decision gate.
6. Controlled containment and eradication.
7. Recovery and validation.
8. Post-incident review and lessons learned.

## Planned incident domains

The implementation is designed to cover controlled scenarios involving:

- identity and authentication activity;
- suspicious sign-in investigation;
- account compromise indicators;
- enterprise applications and delegated permissions;
- OAuth and consent-related investigation;
- endpoint and Defender signals when available;
- cross-signal correlation;
- containment and session-control decisions;
- recovery and access restoration;
- incident timelines and postmortems.

## Safety boundaries

This is a controlled portfolio laboratory, not a production security operations center.

The project will not:

- claim production deployment;
- enable paid or trial services solely for demonstration;
- request unnecessary Microsoft Graph permissions;
- perform destructive endpoint actions;
- perform tenant-wide containment without a controlled safety gate;
- store access tokens, secrets, tenant identifiers, object identifiers, device codes, credentials, or raw sensitive evidence in Git;
- fabricate live telemetry where the environment cannot provide it.

Capabilities unavailable because of licensing or environment limitations are documented explicitly rather than simulated as completed live functionality. Unavailable licensed capabilities are classified as `LICENSE_DEFERRED`; runtime capabilities that cannot be validated in the current lab environment are classified as `ENVIRONMENT_DEFERRED`.

## Evidence model

Repository evidence is designed to preserve useful technical proof without publishing tenant-specific or identity-specific information.

Evidence may include:

- sanitized counts;
- security classifications;
- configuration state;
- redacted timelines;
- test outcomes;
- control decisions;
- incident lifecycle evidence;
- recovery verification.

Sensitive raw evidence remains outside version control.

## Project roadmap

### Feature 1 — Security Operations Project Foundation

Repository governance, architecture, evidence handling, validation, and safety boundaries.

### Feature 2 — Security Signal & Capability Discovery

Read-only discovery of available Microsoft 365 security signals, APIs, permissions, licensing boundaries, and investigation surfaces.

### Feature 3 — Incident Case & Evidence Foundation

Canonical incident model, normalized evidence records, correlation identifiers, severity classification, and privacy controls.

### Feature 4 — Identity Security Incident Investigation

Controlled identity and authentication investigation workflow including sign-in and account-risk evidence where supported.

### Feature 5 — Enterprise Application & OAuth Incident Investigation

Application permission, consent, and service-principal investigation with least-privilege evidence collection.

### Feature 6 — Endpoint Security Incident Investigation

Microsoft Defender endpoint investigation where available, with environment-dependent runtime evidence explicitly classified.

### Feature 7 — Cross-Signal Correlation

Correlation of identity, application, endpoint, and audit evidence into deterministic incident timelines.

### Feature 8 — Containment & Eradication

Safety-gated response workflows for controlled identities, sessions, application access, and supported endpoint actions.

### Feature 9 — Recovery & Validation

Controlled restoration, access verification, residual-risk checks, and recovery evidence.

### Feature 10 — Postmortem & Project Closure

Incident metrics, postmortems, adversarial validation, final architecture documentation, release verification, and public portfolio publication.

## Independence

This project is independently designed and implemented for portfolio and evaluation purposes.

Microsoft product names are used descriptively only. This repository is not affiliated with, endorsed by, or sponsored by Microsoft.
