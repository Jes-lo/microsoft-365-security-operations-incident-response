# Privacy and Evidence Handling

## Purpose

Security evidence can reveal identities, tenant structure, authentication activity, device information, network information, and application relationships.

The project therefore treats evidence minimization as a security requirement.

## Repository-safe evidence

Preferred repository evidence includes:

- counts;
- status classifications;
- sanitized timestamps;
- control outcomes;
- pass/fail validation results;
- generalized incident timelines;
- redacted field structures;
- capability availability;
- permission requirements.

## Private evidence

The following should remain outside version control unless an explicit sanitization process proves they are safe:

- raw Microsoft Graph responses;
- tenant and object identifiers;
- full user principal names;
- email addresses;
- authentication or session information;
- device identifiers;
- IP addresses associated with individuals;
- security alert exports containing identifying data;
- token or credential material.

## Storage

Temporary private evidence must use restrictive local filesystem permissions.

Private evidence directories are excluded through .gitignore.

## Publication gate

Before the repository becomes public, current content and reachable Git history must be scanned for sensitive information.
