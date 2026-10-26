# External-CSR ACME workflow — backlog #10

`internal/acmeflow.Engine` uses the original device CSR already stored by the
journal, signs ACME requests with a separate host-supplied account signer and
passes the issued leaf/chain through the shared certificate-policy gate. A
successful attempt ends at CERT_READY. A [native AD DNS solver](ad-dns01.md)
now provides restricted GSS-TSIG updates and exact cleanup; its credential source
is supplied by the trusted host. Credential host wiring, actual router import,
scheduling and an authenticated executable host remain separate milestones.
The HTTP Provider continues to return 501 for CSR/push.

## Reviewed interfaces

The [immutable source reference](../contracts/acme-2.19.0-reference.json) records
ILM Core 2.19.0 at `eb5e9096fb0b7ff56c911184ff8601c615f83436` and interfaces
2.19.0 at `e62233777518296f70a151cf766dde5e1a6cea2d`.
[The ACME controller contract](https://github.com/OmniTrustILM/interfaces/blob/e62233777518296f70a151cf766dde5e1a6cea2d/src/main/java/com/otilm/api/interfaces/core/acme/AcmeController.java)
provides Directory, nonce, account, order, authorization, challenge, finalize and
certificate resources under `/v1/protocols/acme/{acmeProfileName}`. Configure the
observed Directory URL including any deployment context prefix; the client uses
returned resource URLs rather than assembling undocumented endpoints.

[The reviewed service](https://github.com/OmniTrustILM/core/blob/eb5e9096fb0b7ff56c911184ff8601c615f83436/src/main/java/com/otilm/core/service/acme/impl/AcmeServiceImpl.java)
sets `externalAccountRequired=false`, creates DNS-01 and HTTP-01 challenges and
parses the base64url CSR at finalize before moving the order to PROCESSING.
These are source observations, not a fresh capture from the private appliance.
Live Directory metadata, resolver behavior and request acceptance remain #15.

The implementation reuses the pinned `golang.org/x/crypto/acme` v0.58.0 for JWS,
nonce handling, account lookup and external-CSR calls. It does not use autocert,
generate a certificate private key, or construct a replacement CSR. The account
signer is a different credential from the device's non-exportable key.

## Trusted host wiring

Construct `acmeflow.New(config, store, certificateGate, accountSigner, solver,
httpClient)`. The host resolves private credentials and approves these inputs;
they are not Core attributes or new ILM API fields.

| Input | Required scope |
|---|---|
| Directory URL | Exact approved HTTPS origin and profile path ending in `/directory` |
| Account signer/reference | Existing RSA/ECDSA signing key; stable private reference; public-key digest persisted |
| TLS bundle reference/client | Reviewed server trust, hostname checks and TLS 1.2+; no verification bypass |
| Policy SHA-256 | Same digest as the journal's service and certificate gate |
| Terms URL | Explicit reviewed value if the server presents terms; no blanket acceptance |
| Solver | Trusted idempotent DNS-01 presentation/cleanup backend; `internal/dns01` provides native AD DNS |
| Limits/clock | Explicit per-run timeout, HTTP/nonce/attempt budgets and backoff; current UTC for resumption |

Account key bytes are never generated or stored here. The constructor freezes
configuration and TLS trust-pool copies; the host must not mutate signers or
rotate their backing key during unfinished work. Run checks the current public
key against the bound digest. Changing the key reference, public key, Directory,
TLS reference or effective settings cannot silently rebind an unfinished job.
The TLS reference must identify the actual approved client trust configuration;
a reference string alone does not authenticate its contents.

Each run looks up the same account using `onlyReturnExisting`. A missing account
can be registered only when the metadata allows the supported non-EAB flow and
the exact terms are approved. Account-response loss is recovered by lookup with
that same key. A previously recorded account that disappears is not replaced.
EAB-required new-account provisioning is outside this component and fails closed;
an already provisioned valid account can still be used. Disabling EAB never skips
account signing or domain authorization.

All Directory and subsequently requested resources stay inside one HTTPS origin
and profile prefix. Cross-profile/host URLs, userinfo, queries, fragments,
encoded/non-canonical paths and redirects are rejected. The default transport
does not inherit an environment proxy; a supplied reviewed transport may configure
one. The client has no cookie jar, bounded responses and a bounded request budget.

## Ownership, challenges and persistence

Only an `acme-worker` service with a valid recorded CSR can enter this workflow.
`BeginACME` atomically binds the account configuration and CSR hash, creates the
initial flow record and advances CSR_READY to AWAITING_ISSUANCE. Existing
operation correlation, service ownership and the certificate-policy digest remain
mandatory. Native Core renewal cannot run the ACME path for that Location.

Every order must contain exactly the recorded CSR's DNS identifiers. This initial
ILM adapter requires authorization coverage for every name, unique authorization
URLs and non-wildcard DNS identifiers. It checks the entire authorization set
before presenting a DNS value. Only an actually offered DNS-01 challenge with a
valid token is selected. HTTP-only offers, wrong identifiers and unsupported
profiles cannot cause a solver call or finalize. Existing valid authorizations
are accepted without fabricating a challenge or cleaning another operation's data.

Before calling the solver, persist the operation, identifier, authorization and
challenge URL plus token/TXT hashes. The backend must idempotently ensure its own
value and retain sufficient private ownership evidence to clean it by these
references, including an uncertain Present. Successful presentation and challenge
notification are recorded separately. Authorization success or known terminal
expiry/invalidity invokes cleanup only for recorded challenge intents; successful
cleanup is recorded. A failed cleanup remains retryable and retains ownership.
The separate AD DNS backend implements TXT mutation and concurrent-value
ownership; see [its packet/SQLite tests and private acceptance scope](ad-dns01.md).

Caller cancellation persists a monotonic `CancelRequested` intent before cleanup
with a fresh bounded context. A later run of that operation retries only cleanup
and returns `ErrCanceled`, including after restart or an earlier cleanup denial.
It does not resume issuance or create another order. Child network timeouts are
resumable and retain their original challenge intents instead. Cancellation does
not imply that an already submitted request was revoked at the CA.

Journal schema v3 adds `acme_accounts` and `acme_operations`, with foreign keys,
canonical bounded records and a separate CAS revision. Migration from v1/v2
preserves operation/history and original public CSR/SPKI artifacts. Missing or
inconsistent v3 data fails startup. Stored data includes public account/order
URLs, key/settings/CSR hashes, challenge progress, attempts and next retry time;
it contains no account private key, password, raw token or server diagnostics.
It remains private operational data on the protected local journal volume.

## Protocol progress and recovery

```mermaid
sequenceDiagram
    participant Host as Future host / worker
    participant E as ACME engine
    participant DB as SQLite v4
    participant CA as ILM ACME
    participant DNS as Trusted DNS backend
    participant V as Certificate gate
    Host->>E: Run authorized operation
    E->>DB: Bind recorded CSR + account configuration
    E->>CA: Discover; look up/register same account key
    E->>DB: Commit ORDER_CREATING intent
    E->>CA: New order for exact recorded DNS names
    E->>DB: Save original order/finalize/authorization URLs
    E->>CA: Inspect every authorization and actual offers
    E->>DB: Record owned challenge intent
    E->>DNS: Idempotently present DNS-01 proof
    E->>CA: Notify offered challenge
    E->>DB: Record progress + next attempt time
    Host->>E: Resume when due
    E->>CA: Read original order and authorizations
    E->>DNS: Clean recorded owned values after authorization
    E->>DB: Commit FINALIZE_SENT before dispatch
    E->>CA: Finalize using original device CSR bytes
    alt Response lost or issuance processing
        E->>DB: Retain original URLs/intent + retry time
        Host->>E: Resume / restart
        E->>CA: Read original order; fetch its issued certificate
    else Combined library call succeeds
        E->>CA: Recheck original order on the next due run
    end
    E->>V: Validate leaf/chain against saved CSR and current policy evidence
    V->>DB: CERT_READY + history
    E->>DB: Record ISSUED
```

The library combines finalize, polling and certificate download. Persist
FINALIZE_SENT first and bound that call by timeout, request and nonce budgets.
On any later run, query the recorded order first. PROCESSING defers; VALID fetches
that order's certificate and reuses the certificate gate. A transient download
error or lost completion write does not create another order or finalize again.
Even a successful combined call is followed by original-order validation before
acceptance. Same-certificate retries still check current certificate policy.

An explicit rejected 429 or badNonce can return to a safe retry stage before any
accepted mutation. badNonce retries use the response-provided fresh nonce and a
bounded delay; exhausted nonce retries stop. Generic 5xx, transport loss and
malformed success after new-order dispatch are ambiguous. If the original order
URL was lost, retain ORDER_CREATING and return `ErrReconcile`; matching only DNS
names or enumerating orders cannot prove which creation belongs to this job.
If FINALIZE_SENT is recorded but the original order still says READY, also require
reconciliation rather than automatically resubmitting. No automatic new order is
created for an invalid, expired, exhausted or uncertain job. See
[RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4) for order states.

Pending attempts persist exponentially increasing delay capped by configured
backoff. A server Retry-After in seconds or HTTP-date is a lower bound and is not
shortened by that cap; a long delay is saved for later rather than waited out in
the host call. Calls before NextAttemptAt perform no network I/O. Past/zero poll
delays cannot create a tight library loop. Maximum attempts retain the durable
service lock and require attention; elapsed time does not grant another worker
permission. There is no scheduler or jitter/release implementation in this item.

Overlapping runs on the same Store are rejected. Network jobs do not hold a
database read lock across I/O. If the journal closes while a request is in
flight, completion recording fails safely; already committed intents remain the
cross-instance recovery boundary. The backend must honor cancellation and its
own durable idempotency contract. Import/CSR callbacks retain their existing
stronger Close-waits-for-dispatch behavior. Closing the journal is not proof
that an ACME request never reached the server.

## Executable evidence and next stage

Loopback HTTPS tests verify real JWS signatures, KID/JWK form, nonce provenance,
POST-as-GET and byte-for-byte external CSR finalization. Real temporary SQLite
tests cover migration, CAS, intent failure, account/order restart and ownership.
Faults include badNonce, 429/date delays, pending/processing, zero poll delay,
account/new-order/finalize response loss, download throttling, budget exhaustion,
concurrency, unauthorized identities, foreign endpoints, TLS bypass and redirects.
An expired order cleans only the test backend's recorded intents. Tests generate
all keys/certificates at runtime and never contact a real ILM, CA, AD, DNS or router.

The restricted [AD DNS-01 backend](ad-dns01.md) supplies exact owned TXT cleanup.
Actual ILM/account/Directory/RA-template acceptance, time synchronization and
device staging remain private #15; real inactive import remains #12. No public
workflow obtains internal credentials or network access from these offline tests.
