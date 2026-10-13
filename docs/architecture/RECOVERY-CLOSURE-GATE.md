# Recovery Closure Gate

## Purpose

Feature 9B introduces deterministic recovery-validation scenarios and a local incident-closure review gate.

It consumes a Feature 9A recovery plan and validates review results for every recovery item.

No recovery action or incident closure is performed.

## Exact-plan binding

Every closure-gate request must contain the SHA-256 digest of the exact Feature 9A recovery plan being reviewed.

The evaluator recomputes the digest and requires an exact match.

A gate request cannot be reused against a stale or modified recovery plan.

## Verification scenarios

Each recovery-plan check receives one of three states:

- `PASS`
- `FAIL`
- `PENDING`

A `PASS` requires the metadata state:

`SANITIZED_EVIDENCE_RECORDED`

The model stores only the evidence state, not raw tenant evidence.

A failed or pending check blocks closure review.

## Structural fail-closed rules

The gate rejects:

- missing recovery items;
- additional recovery items;
- action-type changes;
- target-alias changes;
- missing checks;
- duplicate checks;
- unknown checks;
- unsupported status values;
- plan-hash mismatch;
- case mismatch;
- live-recovery requests;
- incident-closure execution requests.

## Human validation

The gate supports an explicit local review state:

`VALIDATED_FOR_CLOSURE_REVIEW`

This is required before the gate can reach:

`READY_FOR_CLOSURE_REVIEW`

The ready state does not authorize incident closure.

## Closure boundary

Feature 9B can determine that a sanitized recovery scenario is ready for a later closure review.

It cannot close the incident.

Both recovery release and incident-closure release remain `NOT_RELEASED`.
