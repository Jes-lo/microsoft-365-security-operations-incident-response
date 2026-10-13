# ADR-009 — Privacy-Preserving Cross-Signal Correlation

## Status

Accepted for Feature 7 foundation.

## Context

Features 4, 5, and 6 independently sanitize identity, application, and endpoint-security evidence.

Their aliases are generated locally within each transformation session.

The same alias text can therefore appear in more than one domain without representing the same real-world entity.

Automatically joining those aliases would create unsupported incident relationships.

## Decision

Feature 7 treats all source aliases as domain scoped.

String equality between aliases from different domains is not evidence of identity.

Cross-domain entity correlation requires an explicit sanitized binding.

Feature 7A supports `SAME_SUBJECT` bindings using synthetic `CORR-SUBJECT-NNN` references.

A binding must reference existing `SUBJECT-NNN` aliases from at least two domains.

## Timeline decision

Entity binding is independent from temporal correlation.

Every valid sanitized source event may appear in the deterministic incident timeline whether or not it has an explicit cross-domain binding.

This preserves observed chronology without inventing entity relationships.

## Determinism decision

Timeline order is based on normalized UTC timestamp followed by domain priority, event type, and source-local index.

The correlation output contains no generation timestamp so identical sanitized inputs produce identical output.

## Privacy decision

Only sanitized categories, domain-local aliases, and synthetic cross-domain binding aliases are eligible for output.

Raw identifiers, raw Microsoft Graph payloads, network indicators, file artifacts, tokens, and credentials remain prohibited.

Category fields are treated as untrusted even when their parent summary declares a sanitized privacy state. Identifier-like category values are therefore redacted before correlation output is written.

## Evidence decision

A completed cross-signal timeline may be registered through the Feature 3 evidence workflow.

The evidence index and custody chain retain integrity metadata while raw source evidence remains outside the repository.

## Authorization decision

Feature 7A is local only.

It requires no Graph authentication, tenant read, tenant write, endpoint response action, additional permission, role assignment, or trial activation.

## Consequences

The project can demonstrate deterministic SOC-style incident timelines across multiple Microsoft 365 security domains without claiming unsupported cross-domain identity relationships.

The trade-off is deliberate: an analyst or another trusted sanitization stage must provide an explicit binding before events are treated as referring to the same subject.
