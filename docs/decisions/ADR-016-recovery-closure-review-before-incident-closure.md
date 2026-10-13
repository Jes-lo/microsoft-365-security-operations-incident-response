# ADR-016 — Recovery Closure Review Before Incident Closure

## Status

Accepted for Feature 9B.

## Context

Feature 9A defines recovery strategies and verification requirements but intentionally leaves every recovery item pending separate validation.

A recovery plan alone is insufficient evidence that an incident can be closed.

## Decision

Introduce a deterministic local recovery-closure gate.

The gate is cryptographically bound to the exact Feature 9A recovery plan with SHA-256.

Every required verification check must be represented exactly once.

## Scenario outcomes

`PASS` requires sanitized evidence to be recorded.

`FAIL` blocks closure review.

`PENDING` blocks closure review.

Missing, duplicate, or unknown checks are rejected rather than interpreted.

## Human review

Even when every technical check passes, explicit human validation is required before the gate can reach `READY_FOR_CLOSURE_REVIEW`.

That state does not authorize or execute incident closure.

## Security boundary

Feature 9B performs no authentication, tenant mutation, endpoint action, recovery action, credential change, permission change, or incident closure.

Recovery release and incident-closure release remain `NOT_RELEASED`.
