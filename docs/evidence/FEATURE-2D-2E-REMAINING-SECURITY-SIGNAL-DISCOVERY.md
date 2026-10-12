# Feature 2D/2E — Remaining Security Signal Discovery

## Authorization boundary

The dedicated project application used:

- `AuditLog.Read.All`
- `SecurityAlert.Read.All`
- `SecurityIncident.Read.All`
- `IdentityRiskyUser.Read.All`
- `IdentityRiskEvent.Read.All`

Runtime authorization validation:

- expected functional read scopes: 5
- write-capable scopes: 0
- unexpected scopes: 0
- Graph GET requests in this probe: 4
- investigation-time tenant writes: 0
- raw Graph responses retained: no

## Sanitized live results

| Capability | HTTP | Sample rows | Classification |
| --- | ---: | ---: | --- |
| Microsoft Defender alerts | 200 | 0 | `AVAILABLE` |
| Microsoft Defender incidents | 200 | 0 | `AVAILABLE` |
| Microsoft Entra risk detections | 200 | 1 | `AVAILABLE` |
| Microsoft Entra risky users | 403 | none | `ACCESS_OR_LICENSE_DENIED` |

The successful zero-row Defender responses demonstrate API reachability and do not claim that alerts or incidents existed in the tenant.

The one-row risk-detection sample demonstrates bounded API reachability and is not treated as a complete tenant record count.

## Denied risky-user boundary

The Microsoft Entra risky-user surface returned HTTP 403 under the approved least-privilege authorization boundary.

The project records this as `ACCESS_OR_LICENSE_DENIED`.

No trial, paid license, additional Entra role, or broader Graph permission was introduced to bypass the boundary.

## Feature 2 aggregate result

Across all six modeled capabilities:

- `AVAILABLE`: 5
- `ACCESS_OR_LICENSE_DENIED`: 1
- `ENDPOINT_OR_PRODUCT_UNAVAILABLE`: 0

All six surfaces therefore have explicit sanitized live classifications.

## Safety and privacy

- Graph write permissions requested: no
- investigation-time tenant writes: 0
- trial enabled: no
- paid license activated: no
- additional Entra role automatically assigned: no
- raw Graph responses retained: no
- tenant/application/user identifiers retained: no
