# ADR-005 — Local-First Incident Case and Evidence Boundary

## Status

Accepted.

## Context

Security investigations require a durable case model and traceable evidence handling.

At the same time, committing tenant security payloads, user identifiers, tokens, or exported evidence into a portfolio repository would create unnecessary privacy and security risk.

## Decision

Incident case workspaces are operational local data rather than Git-tracked project content.

The repository contains only:

- schemas and contracts;
- local case tooling;
- validation logic;
- architecture documentation;
- synthetic tests.

Source evidence is not copied into a case by default.

Instead, evidence registration retains only:

- a sanitized label;
- a source classification;
- SHA-256;
- byte size;
- registration timestamp;
- evidence identifier.

Source path and source filename are excluded.

## Custody decision

Evidence-registration events use a SHA-256 hash chain.

Each custody event includes the SHA-256 of the previous custody event.

This provides tamper evidence while keeping raw source material outside the case metadata.

## Git boundary

Repository-local operational cases, if used, belong under:

`.local/incident-cases/`

The path is ignored by Git.

Raw Microsoft Graph responses and tenant identifiers remain prohibited from repository evidence.

## Failure behavior

Case tooling fails closed on:

- duplicate evidence IDs;
- missing case files;
- inconsistent case identifiers;
- malformed evidence IDs;
- malformed sanitized labels;
- missing source files;
- broken custody hashes;
- broken previous-record hash links;
- evidence/custody count mismatches.

## Consequence

Later investigation features can create case evidence records without requiring the portfolio repository to contain confidential tenant payloads.

The feature prioritizes evidence integrity, privacy, reproducibility, and least-data retention.

## Canonical hash representation

NDJSON remains the persisted custody-log format.

The SHA-256 digest is not computed from serialized JSON text because serialization and deserialization can normalize values differently across runtime boundaries.

Instead, the digest input is a deterministic length-prefixed UTF-8 field representation with explicit null semantics and fixed field ordering.

This keeps custody verification independent from JSON formatting while retaining human-readable NDJSON storage.

Custody timestamps are normalized to a fixed invariant UTC representation before hashing. This ensures that a JSON parser materializing an ISO timestamp as a `DateTime` object cannot change the canonical hash input when the custody event is later verified.
