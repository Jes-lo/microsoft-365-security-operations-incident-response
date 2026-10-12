# Security Operations Architecture

## Objective

The project models an evidence-driven Microsoft 365 security operations and incident-response workflow without assuming enterprise licensing that is not actually available.

## Logical flow

Security signals
→ capability-aware collection
→ sanitized evidence normalization
→ triage
→ investigation
→ cross-signal correlation
→ containment decision gate
→ controlled response
→ recovery validation
→ postmortem

## Signal domains

The architecture anticipates evidence from several domains:

- Microsoft Entra identity and authentication activity;
- directory and audit activity;
- enterprise applications and permissions;
- Microsoft Defender security information when available;
- endpoint security information when available;
- Microsoft Graph-supported security and directory evidence;
- operator-observed security state.

Availability is discovered rather than assumed.

## Investigation layer

Investigation automation must:

- operate read-only by default;
- minimize API permission scope;
- avoid printing identifiers unnecessarily;
- produce deterministic classifications;
- preserve a distinction between observed facts and analyst conclusions;
- fail closed when evidence is incomplete or malformed.

## Response layer

Response operations require an explicit decision gate.

Each future write operation must document:

- target scope;
- authorization;
- expected security effect;
- reversibility;
- validation method;
- rollback or recovery path;
- evidence retained after execution.

## Evidence boundary

Raw tenant evidence is not a repository artifact by default.

The repository stores sanitized technical evidence sufficient to demonstrate the investigation methodology without exposing unnecessary tenant-specific information.

## Environment limitations

A missing signal or unavailable response capability is recorded explicitly.

The project does not manufacture successful telemetry or pretend unavailable product capabilities were validated.
