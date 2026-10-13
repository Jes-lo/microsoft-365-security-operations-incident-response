# Containment & Eradication

## Purpose

Feature 8 introduces the response-planning layer of the incident lifecycle.

The foundation is deliberately local and simulation-only.

It can transform sanitized incident-response decisions into deterministic containment and eradication plans, but it cannot execute those actions.

## Default response boundary

All live response actions are denied by default.

The Feature 8A planner:

- does not authenticate to Microsoft Graph;
- does not call Microsoft Graph;
- does not read the tenant;
- does not write the tenant;
- does not perform endpoint actions;
- does not grant permissions;
- does not assign roles;
- does not activate licenses or trials;
- does not invoke external administrative tools.

A proposed action is not an authorized action.

## Supported simulated action classes

The foundation models controlled response decisions for:

- subject session revocation;
- subject sign-in blocking;
- application access disabling;
- device isolation;
- OAuth grant removal;
- application credential remediation;
- subject credential reset;
- file quarantine.

These names describe response intent only.

No implementation for performing the live action exists in Feature 8A.

## Alias-only targets

Targets must use repository-safe aliases:

- `SUBJECT-NNN`;
- `APP-NNN`;
- `DEVICE-NNN`;
- `FILE-NNN`.

Raw tenant, user, application, device, file, network, credential, token, or object identifiers are not accepted as action targets.

Free-form reason text is also prohibited.

Reasons use a controlled category vocabulary.

## Action gate

Every simulated action records:

- response phase;
- target class;
- sanitized target alias;
- impact;
- reversibility;
- symbolic live capability requirement;
- permission resolution state;
- verification requirement;
- rollback requirement;
- evidence requirement.

Permission resolution is intentionally deferred.

Before any future live execution, a separate explicit action gate must resolve the exact current permission, product, licensing, API, operational impact, verification method, rollback procedure, evidence handling, and operator authorization.

Feature 8A does not satisfy that gate.

## Determinism

The request requires contiguous action sequence numbers beginning with one.

Output is sorted by sequence.

No generation timestamp is added.

Identical valid inputs therefore produce identical plan output.

## Evidence integration

A simulated response plan is repository-safe evidence and can be registered through the Feature 3 evidence workflow.

Feature 3 retains SHA-256 and custody metadata without embedding raw source evidence.

## Safety invariant

`SIMULATION_ONLY` is the only accepted execution mode.

`live_execution_authorized` must be `false`.

Any request that attempts to enable live execution, supplies an unsupported action, injects an unexpected property, uses a raw target value, or breaks case binding fails closed.
