# ADR-015 — Recovery Validation Before Incident Closure

## Status

Accepted for Feature 9A.

## Context

Containment and eradication reduce immediate risk but do not prove that normal service can be safely restored.

Automatically reversing response actions can recreate the original security condition.

## Decision

Require an explicit recovery-validation phase before incident closure.

Every modeled Feature 8 action receives a recovery strategy and verification checks.

No recovery strategy automatically restores the previous state.

## Sensitive recovery cases

The following actions require stronger recovery semantics:

- OAuth grant removal requires reapproval rather than automatic regrant;
- application credential remediation uses replacement credentials only;
- subject credential reset uses a new credential rather than restoring the previous credential;
- file quarantine requires benign reclassification before a restore decision.

## Closure

A recovery item remains pending until separately validated.

Unresolved or failed validation blocks incident closure.

Feature 9A does not authorize live recovery or automatic incident closure.

## Consequences

The portfolio demonstrates that incident response continues beyond containment and eradication into controlled restoration, validation, and closure evidence.
