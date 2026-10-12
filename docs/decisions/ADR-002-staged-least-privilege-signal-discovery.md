# ADR-002 — Staged Least-Privilege Security Signal Discovery

## Status

Accepted.

## Context

Security operations investigation can require several Microsoft Graph permission families.

Requesting every possible permission in advance would violate least privilege and make it difficult to distinguish licensing limitations from authorization limitations.

## Decision

Security signal discovery is staged.

### Stage A — Static capability model

Document:

- API surface;
- HTTP method;
- least-privileged delegated permission;
- documented licensing boundary;
- environment dependency.

No tenant authentication occurs.

### Stage B — Existing-access observation

Inspect the currently authenticated Microsoft Graph context without requesting additional permissions.

Capabilities for which the required permission is not already present are classified as `PERMISSION_REQUIRED` and are not queried.

### Stage C — Explicit permission decision

Only after reviewing Stage B may an additional delegated read permission be considered.

Each permission must have:

- a specific investigation use case;
- documented least-privilege justification;
- no write capability;
- explicit operator authorization.

## Prohibited behavior

Feature 2 must not:

- request `Directory.Read.All` merely for convenience;
- request any `ReadWrite` permission;
- automatically grant admin consent;
- activate a paid or trial license;
- perform tenant writes;
- use beta APIs when a v1.0 investigation surface is available;
- print raw tenant evidence.

## Consequences

Some capabilities may remain `PERMISSION_REQUIRED`, `LICENSE_DEFERRED`, or `ENVIRONMENT_DEFERRED`.

That is an intentional security outcome rather than an implementation failure.
