# Containment & Eradication Capability and Permission Readiness

## Purpose

Feature 8C identifies the documented capability, permission, role, and API-provider prerequisites associated with the eight response actions modeled by Feature 8A and reviewed by Feature 8B.

It does not grant those permissions and does not authenticate to Microsoft Graph or Microsoft Defender for Endpoint.

## Trust boundary

The existing security-operations application is intentionally treated as a read-only investigation principal.

Feature 8C does not convert that principal into a response principal.

Any future live response design must use a separately gated response identity.

## Discovery sources

The capability catalog is based on Microsoft Learn documentation reviewed on 2026-10-13.

The repository records only public permission names and sanitized capability metadata.

No tenant identifiers, object identifiers, user identifiers, application identifiers, device identifiers, access tokens, credentials, or raw API payloads are required.

## Provider separation

Six modeled actions use Microsoft Graph capability families:

- revoke user sessions;
- block user sign-in;
- disable application/service-principal access;
- remove an OAuth delegated permission grant;
- remediate application password credentials;
- reset a user password.

Two modeled actions use Microsoft Defender for Endpoint API capability families:

- isolate a device;
- stop and quarantine a file.

Defender for Endpoint permissions are not treated as interchangeable with Microsoft Graph permissions.

## Current readiness decision

The currently documented read-only investigation boundary does not contain any of the response permissions identified by Feature 8C.

That is considered the correct security posture.

The result is therefore:

`current_project_ready_for_live_execution = false`

and:

`execution_release = NOT_RELEASED`

## Separate response identity

A future live-response design must not silently add write/action scopes to the current read-only app.

Feature 8C requires:

`SEPARATE_RESPONSE_APP_REQUIRED`

before any future permission-grant design.

This allows:

- independent least-privilege review;
- clear investigation-versus-response separation;
- explicit consent and role gates;
- independent rollback;
- simpler audit evidence;
- no accidental privilege expansion of the existing investigation principal.

## Pre-live requirements

A future gate must separately determine:

1. exact target action;
2. exact API provider;
3. exact least-privileged permission set at that future date;
4. tenant licensing/capability availability;
5. operator or application role requirements;
6. target-specific privilege restrictions;
7. consent requirements;
8. verification procedure;
9. rollback procedure;
10. explicit operator authorization.

Feature 8C satisfies none of those future authorization gates automatically.
