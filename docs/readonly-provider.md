# Read-only Entity Provider — backlog #3

The provider now implements Entity CRUD, durable metadata, attribute
definitions and HTTPS Location queries through the official Go SDK v1.1.0.
`NewReadOnlyHandler` returns an embeddable HTTP handler; it does not open a
listener. The hosting application must supply authenticated transport and
authorization before exposing it. No device transport is implemented here.

## Wiring

```go
cfg, err := provider.LoadReadOnlyConfig(configReader)
// Handle err before continuing.
store, err := provider.OpenEntityStore(absolutePrivateDatabasePath)
// Handle err and close store when the host shuts down.
handler, err := provider.NewReadOnlyHandler(store, cfg, inventoryReader)
// Handle err, then mount handler behind the host's authenticated transport.
```

`InventoryReader` is a narrow dependency with only `ReadHTTPS(ctx, DeviceAccess)`.
It receives the operator-approved literal target, credential reference and
host identity reference. [NETCONF/SSH transport libraries](readonly-transports.md)
are implemented in #4; [inventory parsing and the reader adapter](certificate-inventory.md)
are implemented in #5. Nil reader means unavailable,
not an empty inventory. The host owns the store and reader lifetimes.

Example configuration (all values are synthetic):

```json
{
  "devices": {
    "router-a": {
      "policy": {
        "target": "192.0.2.10",
        "activeTrustpoint": "HTTPS-ACTIVE",
        "stagingTrustpoints": ["HTTPS-STAGE-A"]
      },
      "credentialRef": "secret://devices/router-a",
      "hostKeyRef": "hostkey://devices/router-a"
    }
  }
}
```

These references are opaque lookup identifiers, not fetched URLs. The provider
does not load passwords, keys or host key contents. The loader rejects unknown
or duplicate fields, noncanonical field names, inline credential values and
oversized configuration; the constructor validates and copies the policy.
Reference resolution and actual host identity verification belong to the
device adapter. References themselves are not proof of successful authentication.

## Persistent entities and stable services

Entity metadata uses SQLite with WAL, `synchronous=FULL`, parameterized SQL,
schema/application identifiers and unique constraints on both device ID and
management address. The pure-Go driver is pinned to `modernc.org/sqlite`
v1.61.0; its libc dependency remains the version selected by that module.
Startup verifies the durability settings and refuses unsupported schema
versions, foreign databases and unreadable/corrupt files. It never silently
resets the database. Ownership is checked before enabling WAL; a regression
test compares a rejected foreign database byte for byte before/after opening.
This store is separate from the [operation journal](durable-journal.md):
it does not implement device intent, service locks or crash recovery of writes.

The caller supplies an absolute local database path. Newly created directories
and files request 0700/0600 permissions. Use a private local volume and an
owner-only ACL on Windows; Go mode bits do not configure a Windows ACL. Existing
parent directories and volume permissions remain the operator's responsibility.
Do not place SQLite WAL on a shared network filesystem. Backups must use a
SQLite-consistent procedure including the live WAL, rather than copying only
the main file while a writer is running. See the
[driver documentation](https://pkg.go.dev/modernc.org/sqlite) and
[SQLite WAL guidance](https://sqlite.org/wal.html).

Creation generates a new Entity UUID. Name updates cannot change the device ID
or target. Duplicate registration returns 409, including concurrent requests
using separate database handles. Startup checks every stored binding against
the new approved policy; a changed/missing target causes startup to fail.
Credential references can rotate without changing the Entity identity.

The Core-facing HTTPS Location identity is its Entity plus the fixed
`service=https` attribute, using the UUID introduced in #2. No Trustpoint name
is included in those Location attributes. `HTTPSLocationID(entityUUID)` also
provides a deterministic internal correlation UUID; it is **not** an invented
field in `LocationDetailResponseDto`. Renaming an Entity, changing its public
inventory or restarting preserves that service identity. Deleting an Entity
only deletes connector metadata; it does not invoke the reader or remove any
certificate, key or Trustpoint. Recreating a deleted Entity creates a new identity.

## Attributes and reported capabilities

The kind endpoint returns required `deviceId` and `targetAddress` v3 string
definitions; Entity responses include their actual values as read-only
definitions. The Location attribute is required, read-only `service=https`.
UUID/name pairs and request validation are unchanged from the boundary policy.
The approved values come from operator configuration, not from a network scan.

Definition `version` is numeric **3**, and `schemaVersion` is `v3`; request
attribute `version` is the string `v3`. This distinction is verified against
the pinned 2.19.0 `DataAttributeV3.java` and the SDK's actual discriminator
decoder. No field mapping, callback or value source is advertised. Entity
responses expose neither credential nor host identity references.

V1 Info reports Entity/attribute operations and the common Info/Health
endpoints. Location detail is advertised only when a reader is supplied.
CSR, push, removal and their attribute endpoints are omitted from Info and
explicitly return 501 if called with valid inputs. Invalid input still fails
the boundary policy first. Certificates carry no CSR/push attributes that
could invite Core to attempt native renewal.

On a complete observation, Location detail returns:

- `multipleEntries=true`: the Location can contain multiple public certificate
  entries. This says nothing about how many certificates HTTPS actively serves.
- `supportKeyManagement=false`: inventory observation does not enable key
  generation, key upload or key export.
- `withKey`: evidence supplied by the reader for that entry. The future adapter
  must establish the key association; certificate presence alone is insufficient.
- Explicit `certificateType="X.509"`, avoiding the SDK constructor's misleading
  `X509` default. Public DER is parsed before being encoded for Core.

Reader absence returns 503; read errors, incomplete observations or invalid
public DER return 502; context cancellation/deadline failures return 504.
Only an explicitly complete empty observation becomes a successful empty
inventory. The provider bounds entries and certificate bytes, preserves the
request context, and does not expose raw reader error/transcript details.
Health is process health; use the Location result for actual read availability.

## Acceptance evidence

The tests use the real SDK handler, real temporary SQLite files and generated
public certificates. They cover CRUD/reopen/rename/delete, immutability,
concurrent duplicates, approved reader bindings, changing inventory with a
stable service identity, v3 definition decoding, unsupported endpoint refusal,
incomplete/error/timeout observations, corruption/schema rejection, verified
WAL/FULL settings, database write denial and cancelled storage operations.
The inventory test double has no mutation methods.

Cases C-014–C-019, R-005 and R-006 are executable offline evidence. C-009 remains
planned: actual ILM 2.19.0 registration/form submission/synchronization and the
full native renewal lifecycle have not been exercised. Device transports,
real inventory roles, enrollment, staging and activation remain subsequent
backlog items. This milestone does not enable a production device connection.
