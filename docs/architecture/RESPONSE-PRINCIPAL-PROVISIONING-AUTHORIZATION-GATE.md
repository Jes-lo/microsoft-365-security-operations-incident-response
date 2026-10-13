# Response Principal Provisioning Authorization Gate

## Purpose

Feature 8E introduces a deterministic local authorization-review gate between the Feature 8D response-principal architecture and any future provisioning activity.

It does not provision anything.

## Exact-design binding

Every gate request must contain the SHA-256 digest of the exact Feature 8D response-principal design artifact being reviewed.

The evaluator independently computes the digest of the supplied design and requires an exact match.

This prevents a review prepared for one design from being reused against a modified or stale design.

## Gate scope

The only supported gate scope is:

`LOCAL_PROVISIONING_AUTHORIZATION_REVIEW_ONLY`

A request that asks for live provisioning is rejected.

## Operator authorization

The only accepted local-review value is:

`AUTHORIZED_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW`

This means only that all local prerequisites may be reviewed for a separate future provisioning execution decision.

It does not authorize:

- application registration;
- service-principal creation;
- credential creation;
- permission grants;
- role assignments;
- admin consent;
- authentication;
- containment or eradication actions.

## Principal review requirements

Each of the three Feature 8D response principals must independently confirm:

1. exact principal;
2. exact response domain;
3. exact permission candidates;
4. role requirements;
5. tenant capability;
6. licensing requirements;
7. credential method;
8. admin-consent impact;
9. verification plan;
10. rollback plan.

Any false or missing requirement results in `BLOCKED`.

## Ready is not released

If all three principals satisfy all local review requirements, the status becomes:

`READY_FOR_SEPARATE_PROVISIONING_EXECUTION_REVIEW`

The provisioning release remains:

`NOT_RELEASED`

No tenant mutation is allowed by this state.

## Security properties

Feature 8E is deterministic, fail-closed, SHA-256 bound, alias-only, and contains no raw tenant identifiers or credentials.

The existing read-only investigation principal remains unchanged.
