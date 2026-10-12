# Incident Case & Evidence Model

## Purpose

Feature 3 establishes the local incident case and evidence-handling foundation used by later Microsoft 365 investigation features.

The model separates:

1. investigation metadata;
2. source evidence;
3. evidence fingerprints;
4. chain-of-custody events;
5. repository-safe documentation.

Raw tenant security payloads are not part of the Git repository.

## Case workspace

A generated incident case contains:

- `case.json`
- `evidence-index.json`
- `custody.ndjson`

Case workspaces are operational data and are local-only.

A repository-local operator may use:

`.local/incident-cases/`

That path is explicitly ignored by Git.

## Case metadata

`case.json` contains only bounded case metadata:

- case identifier;
- sanitized title;
- severity;
- lifecycle status;
- UTC opening timestamp;
- evidence count;
- custody-event count;
- raw-data retention assertion.

Feature 3 does not store tenant IDs, application IDs, UPNs, access tokens, or raw security payloads in case metadata.

## Evidence registration

Evidence is registered by metadata rather than copied into the case workspace.

For each source file, the evidence index records:

- operator-defined evidence identifier;
- UTC registration time;
- source type;
- sanitized label;
- SHA-256 digest;
- byte size;
- explicit `raw_content_retained=false`.

The source filename and source path are deliberately excluded.

## Chain of custody

Every evidence registration creates one NDJSON custody event.

Each event contains:

- monotonically increasing sequence;
- case identifier;
- evidence identifier;
- evidence SHA-256;
- evidence byte size;
- source type;
- sanitized label;
- UTC event time;
- previous custody-record SHA-256;
- current custody-record SHA-256.

The first event has no previous-record hash.

Every later event references the hash of the immediately preceding custody event.

This creates tamper-evident event semantics without embedding the evidence itself.

## Integrity validation

`Test-IncidentCaseIntegrity.ps1` verifies:

- case/index identifier consistency;
- evidence and custody counts;
- sequential custody numbering;
- previous-record hash chaining;
- custody-record SHA-256 values;
- evidence-to-custody hash matching;
- evidence byte-size matching;
- raw-content non-retention assertions.

Modification of an existing custody event causes integrity verification to fail.

## Security boundary

Feature 3 tooling:

- performs no Microsoft Graph authentication;
- performs no tenant reads;
- performs no tenant writes;
- requests no Graph permissions;
- does not copy source evidence into the case workspace;
- does not persist source paths or filenames.

Later investigation features can register sanitized evidence fingerprints against this foundation without changing these boundaries.

## Canonical custody hash material

The NDJSON custody record is the storage representation, but JSON serialization is not used directly as the SHA-256 input.

Custody hashes use a deterministic UTF-8 canonical representation with:

- a fixed field order;
- an explicit field name;
- UTF-8 byte length for each non-null value;
- `-1` as the explicit null-length marker;
- newline separation between canonical fields.

This prevents differences in JSON object deserialization, numeric representation, or null/string binding from changing the hash material.

The writer and integrity verifier independently reconstruct the same canonical field sequence before computing SHA-256.

Timestamp canonicalization uses a fixed UTC representation:

`yyyy-MM-ddTHH:mm:ss.fffffffZ`

This normalization occurs before the timestamp enters the length-prefixed SHA-256 material. It prevents runtime JSON date materialization from changing the canonical value after a custody record is reloaded.
