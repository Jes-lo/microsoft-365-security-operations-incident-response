# Containment & Eradication Explicit Action Gate

## Purpose

Feature 8B introduces a local explicit-action gate model between response planning and any possible future live execution mechanism.

It does not execute containment or eradication actions.

## Separation of concerns

Feature 8A answers:

> What response actions could be planned?

Feature 8B answers:

> Has each simulated action satisfied the local review requirements necessary before a separate live-execution gate may even be considered?

Feature 8B does not answer:

> May this action now execute?

That question remains outside this feature.

## Gate scope

The only supported scope is:

`LOCAL_MODEL_REVIEW_ONLY`

A valid operator authorization value is:

`AUTHORIZED_FOR_SEPARATE_LIVE_GATE_REVIEW`

That authorization allows progression to another review boundary only.

It does not authorize:

- tenant writes;
- endpoint actions;
- Microsoft Graph write operations;
- permission grants;
- role assignments;
- license or trial activation;
- credential reset;
- session revocation;
- account blocking;
- application disabling;
- device isolation;
- file quarantine.

## Review requirements

Each planned action is reviewed against:

1. exact action confirmation;
2. target-class confirmation;
3. impact acknowledgement;
4. reversibility acknowledgement;
5. prerequisite confirmation;
6. symbolic capability confirmation;
7. verification-plan confirmation;
8. rollback-plan confirmation;
9. evidence-handling confirmation;
10. explicit operator authorization for separate live-gate review.

The tenth requirement is global and narrowly scoped.

## Permission boundary

Feature 8B may confirm only the symbolic capability already present in the sanitized Feature 8A plan.

Concrete Microsoft Graph, Defender, Entra, or other product permissions are intentionally not resolved.

Concrete permission resolution is represented only as:

`DEFERRED_TO_SEPARATE_LIVE_GATE`

## Decisions

An action can have only one of two local gate states:

- `READY_FOR_SEPARATE_LIVE_GATE_REVIEW`;
- `BLOCKED`.

Neither state permits execution.

A globally ready result still has:

- `execution_release = NOT_RELEASED`;
- `live_execution_available = false`;
- zero tenant writes;
- zero endpoint actions;
- zero response actions.

## Fail-closed behavior

The gate rejects:

- live-execution requests;
- unsupported authorization values;
- concrete permission-resolution values;
- case mismatches;
- missing reviews;
- duplicate review sequences;
- reviews for nonexistent actions;
- unexpected properties;
- non-Boolean review controls;
- tampered plans that claim an action was executed.

Incomplete review requirements produce `BLOCKED`, not implicit approval.

## Determinism

The gate output contains no generated timestamp.

Actions are sorted by their existing plan sequence.

Identical valid plan and gate-review input produces identical output.

## Evidence integration

The local gate result may be registered through Feature 3.

Registration proves integrity of the review artifact; it does not prove or imply live action execution.
