# Incident Closure Authorization Gate

## Purpose

Feature 9C introduces an explicit authorization boundary after the Feature 9B recovery-closure review gate.

Feature 9B can establish `READY_FOR_CLOSURE_REVIEW`.

Feature 9C does not interpret that state as permission to close an incident.

## Exact source binding

Every authorization request is SHA-256 bound to the exact Feature 9B closure-gate output being reviewed.

A stale, modified, replaced, or mismatched source artifact is rejected.

## Required review controls

The authorization gate requires explicit review of:

- exact case identity;
- Feature 9B readiness;
- recovery evidence;
- residual risk;
- business-service validation;
- follow-up actions;
- postmortem handoff;
- explicit authorization for a separate closure-execution review.

Every review control is Boolean and must be explicitly true for the ready state.

## Authorization semantics

The only positive operator state is:

`AUTHORIZED_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW`

It authorizes review of a future, separate execution gate only.

It does not authorize:

- tenant writes;
- Graph or Defender actions;
- recovery execution;
- incident closure.

## Ready state

A fully approved local model reaches:

`READY_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW`

This state is not `CLOSED`.

It does not release incident-closure execution.

## Safety boundary

Feature 9C performs no authentication, tenant read, tenant write, endpoint action, recovery action, credential change, permission grant, role assignment, admin consent, incident-closure request, or incident closure.

`INCIDENT_CLOSURE_EXECUTION_RELEASE` remains `NOT_RELEASED`.
