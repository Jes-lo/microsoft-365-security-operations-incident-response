# Validation Strategy

The project uses layered validation.

## Repository validation

Automated checks validate:

- required governance documents;
- expected project structure;
- JSON syntax;
- security-boundary documentation;
- workflow permission restrictions;
- SHA pinning of external GitHub Actions;
- absence of private-key material;
- absence of high-risk credential files;
- file-size guardrails.

## Adversarial validation

Tests intentionally remove or violate required controls and confirm that repository validation fails closed.

## Live Microsoft 365 validation

Future tenant-facing features must separately identify:

- local/static validation;
- authenticated read-only validation;
- controlled tenant-write validation;
- license-deferred validation;
- environment-deferred validation.

A local test passing is never treated as proof of tenant runtime behavior.
