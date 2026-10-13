# Postmortem and Local Case Closure

## Purpose

Feature 10A introduces a deterministic, sanitized postmortem and local case-closure record.

It closes the portfolio workflow record locally after the recovery and authorization stages have completed.

It does not close an incident in Microsoft 365.

## Source binding

Every postmortem request is SHA-256 bound to the exact Feature 9C incident-closure authorization output.

The Feature 9C source must be in:

`READY_FOR_SEPARATE_INCIDENT_CLOSURE_EXECUTION_REVIEW`

The source must still report:

`INCIDENT_CLOSURE_EXECUTION_RELEASE=NOT_RELEASED`

A stale, modified, mismatched, blocked, or already-closed source is rejected.

## Structured postmortem

Feature 10A intentionally avoids free-form automated narrative.

The record uses controlled taxonomies for:

- root-cause category;
- impact scope;
- contributing factors;
- lessons learned;
- follow-up categories;
- follow-up priorities;
- owner roles;
- due windows;
- follow-up status.

This keeps generated artifacts deterministic and reduces the risk of retaining raw tenant or personal data.

## Local closure semantics

`LOCAL_CASE_CLOSED_POSTMORTEM_COMPLETE` means only that the local portfolio incident record has completed its modeled lifecycle.

It does not mean that any Microsoft 365, Defender, Entra, or other external incident object was modified or closed.

## External closure boundary

Feature 10A never authorizes or performs:

- Graph writes;
- Defender writes;
- tenant mutations;
- endpoint response actions;
- credential changes;
- external incident closure requests;
- external incident closures.

External incident-closure execution remains `NOT_RELEASED`.
