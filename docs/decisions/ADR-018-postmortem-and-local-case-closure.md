# ADR-018 — Postmortem and Local Case Closure

## Status

Accepted for Feature 10A.

## Context

Feature 9 separates recovery validation, closure readiness, and explicit authorization from any external incident-closing operation.

The portfolio still requires a final lifecycle artifact describing lessons learned, follow-up work, and local case completion.

## Decision

Create a deterministic local postmortem and local case-closure record.

The record is SHA-256 bound to the exact Feature 9C authorization output.

Only a Feature 9C output ready for a separate closure-execution review may be used as the source.

## Local versus external closure

Local case closure is an internal workflow/documentation state.

It does not authorize or imply an external Microsoft 365 incident closure or tenant write.

External incident closure remains unreleased and unexecuted.

## Privacy

Automated free-form narrative is excluded from Feature 10A.

Postmortem data uses controlled, sanitized taxonomies and role-level ownership instead of names, UPNs, object identifiers, or raw evidence.

## Consequences

The project can demonstrate a complete incident-response lifecycle through postmortem and local closure without requiring privileged tenant mutation.
