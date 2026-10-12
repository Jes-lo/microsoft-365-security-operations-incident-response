# Feature 2C — AuditLog Read-Only Live Discovery

## Result

Feature 2C successfully validated both Microsoft Entra investigation surfaces associated with delegated `AuditLog.Read.All`.

## Authentication isolation

A dedicated single-tenant project application was used:

`PLAB-SecOps-Graph-ReadOnly`

The default Microsoft Graph PowerShell consent context was not used for the successful probe.

Runtime validation confirmed:

- delegated `AuditLog.Read.All` available;
- write-capable scope count: 0;
- unexpected scope count: 0.

No application, tenant, user, or object identifiers are retained in this evidence.

## Sanitized live results

| Capability | HTTP | Sample rows | Classification |
| --- | ---: | ---: | --- |
| Microsoft Entra directory audit | 200 | 1 | `AVAILABLE` |
| Microsoft Entra sign-ins | 200 | 1 | `AVAILABLE` |

Each request used `$top=1`.

The sample-row value is evidence of bounded API reachability and is not a count of all records in the tenant.

## Request boundary

- Graph GET requests: 2
- Graph tenant-write requests during probe: 0
- Raw Graph responses retained: no
- Graph write-capable scopes: 0
- Unexpected Graph scopes: 0
- `Directory.Read.All` requested: no

## Administrative configuration distinction

Creating and configuring the dedicated application and consenting `AuditLog.Read.All` were controlled tenant configuration actions required to establish the least-privilege authentication boundary.

Those configuration actions are not represented as investigation-time tenant writes.

The live capability probe itself was GET-only.

## Privacy

The repository does not contain:

- Application client ID;
- Tenant ID;
- Object IDs;
- UPNs;
- access or refresh tokens;
- IP addresses;
- raw audit events;
- raw sign-in events.

## Classification

`AUDITLOG_READ_VALIDATED`
