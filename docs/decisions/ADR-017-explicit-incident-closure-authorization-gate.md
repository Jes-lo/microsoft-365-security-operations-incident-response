# ADR-017 — Explicit Incident Closure Authorization Gate

## Status

Accepted for Feature 9C.

## Context

A recovery scenario that passes all Feature 9B checks may be suitable for human closure review, but technical validation alone must not become authority to close an incident.

## Decision

Introduce a separate local authorization gate between recovery validation and any future incident-closure execution mechanism.

The gate is SHA-256 bound to the exact Feature 9B output and requires eight explicit review controls.

## Authorization

The positive operator authorization is:

`AUTHORIZED_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW`

This value authorizes only a later execution-review stage.

It does not authorize incident closure or tenant mutation.

## Fail-closed behavior

The gate blocks or rejects:

- incomplete review controls;
- negative operator authorization;
- unsupported authorization values;
- source hash mismatch;
- case mismatch;
- a non-ready Feature 9B source;
- a source that already claims closure;
- requests to execute incident closure;
- unexpected properties;
- non-Boolean review controls.

## Consequences

Feature 9C demonstrates separation of technical recovery validation, human closure authorization, and actual execution.

Incident-closure execution remains unreleased.
