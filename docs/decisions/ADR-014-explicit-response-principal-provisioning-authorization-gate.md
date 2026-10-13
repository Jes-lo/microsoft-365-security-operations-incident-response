# ADR-014 — Explicit Response Principal Provisioning Authorization Gate

## Status

Accepted for Feature 8E.

## Context

Feature 8D defines future response principals but deliberately does not create them.

Provisioning those identities would cross a major security boundary because subsequent configuration could include highly privileged application permissions and tenant-wide admin consent.

## Decision

Introduce an explicit local provisioning authorization-review gate before any provisioning implementation exists.

The gate is bound to the exact Feature 8D design with SHA-256.

A stale or modified design invalidates the authorization request.

## Fail-closed behavior

The gate rejects:

- live provisioning requests;
- unknown principals;
- duplicate or missing principal reviews;
- non-Boolean review controls;
- unexpected request properties;
- invalid operator authorization values;
- design-hash mismatches.

An incomplete review produces `BLOCKED`.

## Ready-state semantics

`READY_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW` is not a provisioning authorization.

It is only evidence that the local review requirements for a separate future execution decision have been satisfied.

The release remains `NOT_RELEASED`.

## Security boundary

Feature 8E creates no application, service principal, credential, grant, role assignment, admin consent, access token, tenant write, endpoint action, or response action.

Any later provisioning feature requires a separate explicit human authorization after current Microsoft documentation and tenant prerequisites are revalidated.
