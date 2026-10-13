# ADR-010 — Safety-Gated Containment and Eradication

## Status

Accepted for Feature 8A.

## Context

Containment and eradication actions can intentionally interrupt user access, application access, endpoint connectivity, credentials, sessions, permissions, or files.

That makes response automation materially different from the read-only investigation work completed in earlier features.

A portfolio implementation must demonstrate response engineering without turning local validation into implicit authorization to change a real Microsoft 365 tenant or endpoint.

## Decision

Feature 8 begins with a local deterministic simulation layer.

The response planner accepts only sanitized aliases and controlled action categories.

The planner produces action intent and operational metadata, but every action remains `NOT_EXECUTED`.

Live execution is prohibited.

The dedicated read-only Microsoft Graph application remains unchanged.

No write-capable permission is requested or inferred by this feature.

Exact live permissions are not resolved during Feature 8A.

They must be resolved from current authoritative product documentation only if a later explicit live-action gate is approved.

## Explicit action gate

Any future live action requires a separate gate that establishes all of the following:

1. exact response action;
2. target class and sanitized case binding;
3. expected impact;
4. reversibility;
5. prerequisites;
6. current least-privilege permission or product capability;
7. verification plan;
8. rollback plan;
9. evidence handling;
10. explicit operator authorization.

Failure to satisfy any requirement means the action remains denied.

## Privacy decision

Raw tenant identifiers and raw target identifiers are unnecessary for repository-side planning.

The foundation accepts only controlled aliases.

Free-form reason text is prohibited to prevent accidental inclusion of identifying or sensitive incident data.

## Evidence decision

Simulation plans may be registered using the Feature 3 SHA-256 and custody workflow.

This proves response-plan integrity without claiming that a live action occurred.

## Consequences

The repository can demonstrate containment and eradication decision engineering, impact analysis, rollback planning, permission gating, and fail-closed behavior without performing a destructive or disruptive action.

A future live validation, if any, must be treated as a separate controlled phase rather than a continuation of the local simulator.
