# Security Policy

## Scope

This policy applies to the repository, project automation, security evidence, incident artifacts, and controlled Microsoft 365 lab interactions.

## Reporting a security issue

Do not publish credentials, tenant identifiers, authentication material, sensitive evidence, or exploit details in a public issue.

Security concerns should be reported privately to the repository owner.

## Credentials and secrets

Secrets must never be committed.

This includes:

- access and refresh tokens;
- passwords;
- private keys;
- client secrets;
- device codes;
- session material;
- certificate private keys;
- authentication exports;
- onboarding secrets or equivalent sensitive blobs.

Authentication must use interactive or otherwise approved secure mechanisms when live access is required.

## Tenant and evidence privacy

Repository artifacts must avoid publishing unnecessary:

- tenant identifiers;
- object identifiers;
- user principal names;
- email addresses;
- device identifiers;
- IP addresses tied to individuals;
- authentication artifacts;
- raw security evidence containing personal or confidential information.

Sanitized evidence should be preferred.

## Least privilege

Microsoft Graph and other APIs must use the minimum permission required for each validated operation.

A capability must not request broader permissions merely to simplify investigation or improve portfolio completeness.

## Incident-response safety

Containment and eradication actions must be safety-gated.

Destructive endpoint actions, tenant-wide changes, uncontrolled account disabling, broad session revocation, and other high-impact operations are prohibited unless a future feature explicitly defines a controlled and reversible lab boundary.

## Environment and licensing

Features unavailable in the existing environment must be classified as environment-deferred or license-deferred.

Paid subscriptions and trials must not be activated solely to satisfy project scope.

## Security findings

A detected security issue must be investigated before it is dismissed or suppressed.

Document the reason for any accepted limitation.

## Third-party vulnerabilities

Third-party vulnerability reports do not automatically imply a vulnerability in this project's original code.

Affected components, exploitability, reachability, and mitigation must be evaluated before classification.
