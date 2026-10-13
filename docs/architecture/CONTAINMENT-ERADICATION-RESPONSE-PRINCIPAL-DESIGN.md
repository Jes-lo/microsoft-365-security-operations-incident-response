# Containment & Eradication Response Principal Design

## Purpose

Feature 8D defines the future response identity topology required before any live containment or eradication capability can be provisioned.

It is architecture only.

No Microsoft Entra application, service principal, credential, permission grant, directory role assignment, admin consent, token, tenant write, Defender action, or Graph action is created or executed.

## Existing investigation principal

The current investigation principal remains read-only.

It must not be upgraded with response permissions.

Investigation and response identities therefore remain separate security boundaries.

## Response topology

Feature 8D defines three independent future response principals.

### Graph identity response

`RESP-GRAPH-IDENTITY-001`

Scope:

- revoke subject sessions;
- block subject sign-in;
- reset subject credentials.

This principal must not contain application/OAuth-response or Defender endpoint-response permissions.

### Graph application and OAuth response

`RESP-GRAPH-APPLICATION-001`

Scope:

- disable application/service-principal access;
- remove OAuth delegated permission grants;
- remediate application credentials.

Ownership-sensitive application permissions must be re-evaluated against the exact target before provisioning.

A broader permission is never selected automatically.

### Defender endpoint response

`RESP-DEFENDER-ENDPOINT-001`

Scope:

- isolate device;
- stop and quarantine file.

The Defender API permission surface remains separate from Microsoft Graph.

## Runtime context

The target automation model is application context rather than an interactive user session.

This is a design target, not an authorization.

Every application permission, role requirement, product prerequisite, and tenant capability must be revalidated immediately before any future provisioning gate.

## Credential policy

Credential preference is:

1. managed identity when the future workload is Azure-hosted and compatible;
2. workload identity federation when the future platform supports it;
3. certificate credential when federation is unavailable.

Production client secrets are not allowed by this design.

No credential material may be stored in the repository.

Feature 8D creates no credential.

## Blast-radius controls

The design intentionally avoids one omnipotent response application.

Identity response, application/OAuth response, and endpoint response are isolated from one another.

A compromise of one planned principal should not automatically grant the permissions modeled for another response domain.

## Provisioning boundary

Feature 8D does not authorize principal creation.

Before any future principal is created, another explicit gate must resolve:

1. current Microsoft API documentation;
2. exact application versus delegated permission type;
3. ownership constraints;
4. directory-role requirements;
5. Defender prerequisites;
6. licensing and tenant capability;
7. exact credential method;
8. admin-consent requirements;
9. verification procedure;
10. rollback procedure;
11. target scope;
12. explicit human authorization.

Until then every principal remains `NOT_CREATED` and every execution release remains `NOT_RELEASED`.
