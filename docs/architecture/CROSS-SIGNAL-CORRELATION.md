# Cross-Signal Correlation

## Objective

Feature 7 correlates the sanitized outputs of the identity, enterprise-application/OAuth, and endpoint-security investigation layers into a deterministic incident timeline.

The feature consumes only already-sanitized investigation summaries.

It does not authenticate to Microsoft Graph and does not query the tenant.

## Input boundary

The required inputs are:

- Feature 4 identity-security sanitized summary;
- Feature 5 enterprise-application/OAuth sanitized summary;
- Feature 6 endpoint-security sanitized summary.

An optional sanitized binding document may explicitly associate subject aliases across domains.

All inputs must belong to the same Feature 3 incident case.

## Domain-scoped aliases

Aliases produced by Features 4, 5, and 6 are local to their individual transformation sessions.

For example, `SUBJECT-001` from the identity investigation is not assumed to represent the same subject as `SUBJECT-001` from the application or endpoint investigation.

Cross-domain correlation therefore never joins records merely because their alias strings are equal.

## Explicit subject bindings

Feature 7A supports one explicit cross-domain entity relationship:

`SAME_SUBJECT`

A binding uses a repository-safe correlation alias such as:

`CORR-SUBJECT-001`

Each binding must:

- contain only `SUBJECT-NNN` members;
- span at least two source domains;
- reference aliases that actually exist in the supplied sanitized summaries;
- assign each domain-local subject alias to at most one correlation binding.

Unknown or phantom aliases fail closed.

## Temporal correlation

All sanitized events can participate in the incident timeline even when they have no entity binding.

Unbound events remain timeline events.

A binding adds explicit relationship context but is not required for temporal ordering.

## Deterministic ordering

Timeline events are ordered by:

1. normalized UTC timestamp;
2. domain priority;
3. event type;
4. source-local record index.

The sequence begins at one.

For the same sanitized inputs and binding document, the timeline output is deterministic.

## Event domains

Identity events include:

- sign-ins;
- directory-audit activity;
- risk detections.

Application events include:

- application sign-ins;
- application-management and OAuth-related directory-audit activity.

Endpoint events include:

- unified security incidents;
- unified security alerts.

Only controlled sanitized categories and domain-local aliases are propagated.

## Privacy boundary

Feature 7 does not retain:

- raw tenant IDs;
- raw user IDs or UPNs;
- raw application IDs;
- raw device identifiers or hostnames;
- IP or MAC addresses;
- file paths or filenames;
- file hashes;
- URLs;
- Graph payloads;
- raw cross-domain correlation identifiers.

Feature 7 correlation aliases are synthetic repository-safe references.

Identifier-like values that unexpectedly appear in category fields are replaced with `REDACTED_CATEGORY` before they can enter the cross-signal output. This includes email/UPN-like values, URLs, IP or MAC addresses, GUIDs, common hash forms, credential markers, and path-like values.

## Safety boundary

Feature 7A performs:

- Graph authentication: none;
- Graph requests: zero;
- tenant reads: zero;
- tenant writes: zero;
- endpoint actions: zero;
- response actions: zero;
- new permission grants: zero;
- role assignments: zero;
- trial activations: zero.

Containment remains a separate Feature 8 decision gate.

## Feature 3 integration

The generated sanitized cross-signal timeline can be registered as `OTHER_SANITIZED` evidence through the Feature 3 interface.

Feature 3 then provides:

- SHA-256 integrity;
- evidence indexing;
- custody hash chaining;
- raw-evidence non-retention.

## Failure behavior

The converter fails closed when:

- source case IDs differ;
- a required source contract is malformed;
- a source indicates raw identifier or raw Graph-payload retention;
- a binding references an unknown alias;
- a binding uses an unsupported relationship type;
- one subject member is assigned to multiple bindings;
- a binding does not span at least two domains;
- an event timestamp cannot be normalized safely.

This prevents accidental cross-domain identity claims and preserves the distinction between observed sanitized evidence and explicit correlation decisions.
