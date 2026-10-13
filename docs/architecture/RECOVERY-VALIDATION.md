# Recovery & Validation

## Purpose

Feature 9 introduces the recovery and post-response validation phase.

Feature 9A establishes the local recovery-validation model only.

No recovery action is performed against Microsoft 365, Microsoft Graph, Microsoft Defender, an endpoint, an application, or an identity.

## Recovery is not reversal

Recovery does not mean blindly undoing containment or eradication.

Some response actions may be safely reversible only after a separate validation step.

Other actions must never restore the previous state.

Examples include:

- a removed OAuth grant requires a new approval decision;
- a remediated application credential must use a replacement credential rather than restore a compromised credential;
- a reset subject credential must not restore the previous credential;
- a quarantined file requires benign reclassification before any restore decision.

## Recovery validation plan

The local planner converts sanitized Feature 8 action types and sanitized aliases into deterministic recovery-validation items.

Each item contains:

- response action type;
- sanitized target alias;
- recovery strategy;
- explicit prohibition on automatic restoration;
- validation checks;
- pending validation status;
- `NOT_RELEASED` recovery state.

## Closure boundary

An incident is not considered recovered merely because containment or eradication completed.

Closure requires separate validation evidence and explicit human validation.

Any unresolved or failed recovery item blocks closure.

Feature 9A never closes an incident automatically.

## Privacy and execution boundary

Only sanitized aliases are accepted.

Raw tenant identifiers, credentials, tokens, Graph requests, Defender requests, recovery actions, endpoint actions, and tenant writes are outside Feature 9A.
