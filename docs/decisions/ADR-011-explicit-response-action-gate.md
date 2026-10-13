# ADR-011 — Explicit Response Action Gate

## Status

Accepted for Feature 8B.

## Context

A deterministic response plan is not sufficient authority to perform a disruptive security action.

Containment and eradication may affect user access, applications, credentials, sessions, endpoints, files, or business operations.

The project therefore needs a separate decision boundary after planning and before any future execution mechanism.

## Decision

Feature 8B implements a local explicit-action gate model.

The gate consumes only a repository-safe Feature 8A simulation plan and a controlled review request.

It evaluates readiness for a later live-gate review.

It cannot release execution.

## Authorization semantics

The only accepted authorization decision is:

`AUTHORIZED_FOR_SEPARATE_LIVE_GATE_REVIEW`

This decision is deliberately narrower than authorization to execute.

It permits no tenant write, endpoint action, permission grant, role assignment, trial activation, or live response operation.

## Permission semantics

The gate confirms only symbolic capability requirements already attached to the simulation plan.

Concrete write-capable permissions remain unresolved.

Their state is:

`DEFERRED_TO_SEPARATE_LIVE_GATE`

A later feature must resolve current least-privilege requirements from authoritative product information before any live operation can be considered.

## Fail-closed decision

An action is locally ready only when every local action-review control is true and the request has the permitted operator-review authorization.

Otherwise the action is blocked.

Even a fully ready action remains `NOT_EXECUTED` and `NOT_RELEASED`.

## Privacy decision

The gate carries forward only sanitized aliases from the Feature 8A plan.

No raw tenant, user, application, device, file, network, credential, or token identifier is required.

Free-form authorization text is not accepted.

## Consequences

The project can demonstrate explicit approval boundaries, impact acknowledgement, rollback readiness, verification readiness, evidence planning, and permission separation without creating a path that automatically executes a real security response.
