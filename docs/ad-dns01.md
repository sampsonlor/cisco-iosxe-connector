# Microsoft AD DNS-01 backend — backlog #11

`internal/dns01.Provider` implements `acmeflow.Solver` using native Kerberos,
GSS-TSIG and RFC 2136 over TCP. It binds every DNS value to an existing approved
ACME operation in SQLite v4. This is a trusted host library; credential loading,
the runnable service and private AD/ILM acceptance remain #14/#15. Public CI uses
synthetic peers. The HTTP Provider still exposes no issuance or device writes.

## ILM 2.19.0 validation boundary

The pinned [ILM Core service](https://github.com/OmniTrustILM/core/blob/eb5e9096fb0b7ff56c911184ff8601c615f83436/src/main/java/com/otilm/core/service/acme/impl/AcmeServiceImpl.java#L999)
offers DNS-01. Its `validateDnsChallenge` enumerates JNDI attributes and calls
`Attribute.get()`, which returns one value of that attribute. It does not iterate
the TXT attribute's complete value set. [The JNDI contract](https://docs.oracle.com/en/java/javase/25/docs/api/java.naming/javax/naming/directory/Attribute.html#get())
does not promise which value an unordered attribute returns. Therefore a correct
multi-value DNS backend does not by itself prove that this ILM version can
validate concurrent TXT challenges.

`SingleTXT` is the default mode. It refuses to add alongside an existing challenge
TXT and rechecks the approved resolver view before returning success. It never
removes another value to accommodate the validator. `VerifiedMultiTXT` preserves
multiple values and uses full-set prerequisites to coordinate concurrent updates;
enable it only with private evidence of the actual server and resolver behavior.
The offline concurrent tests demonstrate backend ownership, not live ILM support.
Uncoordinated external writers can still change DNS after a check; keep the
approved challenge namespace under controlled ownership during validation.

Ownership markers deliberately use a separate DNS name:

| Purpose | Synthetic example |
|---|---|
| CA challenge TXT | `_acme-challenge.router.example.test.` |
| Per-operation marker TXT | `_ilm-acme-owner._acme-challenge.router.example.test.` |

The marker is a random persisted nonce, never an extra value in the CA challenge
RRset. Both names must belong to the same configured update zone. CNAME following,
discovered delegation targets and zone-wide transfers are unsupported.

## Trusted host inputs and permissions

Construct `dns01.New(config, journal, credentialSource)` and pass the resulting
solver to `acmeflow.New`. These inputs are approved host configuration, not ILM
Entity attributes or caller-supplied DNS authority.

| Input | Required binding |
|---|---|
| `Zone` | Exact lower-case absolute zone name, including final dot |
| `ServerName` | Approved absolute DNS server name; SPN is `DNS/<name without final dot>` |
| `ServerAddress` | Canonical literal IP and TCP port; no service discovery or address fallback |
| `Targets` | Canonical Location UUID, current service policy SHA-256 and exact non-wildcard identifier |
| `CredentialRef` | Stable private resolver reference; never a password or a public attribute |
| `ViewRef`, `Resolvers` | Private evidence reference and one to four pinned resolver addresses representing the ILM view |
| `Mode` | Default `single-txt`; multi-value mode needs explicit approval/evidence |
| Limits | Timeout up to 30 seconds per DNS exchange, TTL 30–3600, prerequisite retries 1–8 |

The constructor copies and hashes effective configuration. Changing a server,
view, target, mode, credential reference or limit cannot rebind unfinished work.
Each call also verifies the saved ACME operation's identifier, authorization URL,
challenge URL and token/value hashes, plus its Location, owner and policy. An
operation UUID alone grants no DNS permission.

The host's `CredentialSource.LoadDNS` returns an explicit realm, account name,
password and **raw krb5.conf contents**, rather than a filename. The accepted
configuration disables KDC/realm DNS lookup and weak crypto, declares one realm
and pins one to four literal KDC endpoints on port 88. Ticket, service and
permitted encryption sets contain only AES128/AES256. Ambient credentials,
Windows SSPI, NTLM, unsigned updates and ordinary HMAC-TSIG are not fallback
paths. Password/keytab provisioning and credential rotation orchestration are
outside this library; the initial implementation supports explicit passwords.
Credential string/JSON diagnostics are redacted and underlying errors are not
returned. The host remains responsible for protecting the source and memory.

Kerberos and MIC cryptography come from the pinned `bodgit/gssapi`/`gokrb5`
libraries. TKEY negotiation requests mutual authentication, replay protection
and integrity. The final response must contain a valid GSS TSIG over the original
packet after the AP-REP establishes the context. All subsequent authoritative
reads and UPDATE responses require verified GSS TSIG; unsigned replies cannot
prove permission, success or absence. See [RFC 3645](https://www.rfc-editor.org/rfc/rfc3645.html).

The upstream Kerberos login/service-ticket APIs have no context parameter.
Cancellation is checked before/after those calls and before any DNS mutation;
the configured DNS timeout does not bound KDC login. The host must account for
that limit when isolating credentials and scheduling workers. TKEY rounds and
DNS packets are bounded; cancellation closes active DNS/TKEY TCP connections.

For private AD setup, approve a dedicated principal with read/update rights on
only the two exact DNS nodes for each allowed identifier. Precreate/reserve those
nodes and review their effective AD ACLs, inheritance, owner, deny entries and
last-record deletion/recreation behavior with the AD administrator. Do not grant
DNSAdmins, Domain Admins or zone-wide update authority. AD ACLs operate on DNS
objects, not this operation's TXT value; the connector's scope/ownership rules
provide the value-level restriction. Also validate that updating one allowed
name cannot modify a sibling or create arbitrary zone children. Microsoft's
[secure dynamic update documentation](https://learn.microsoft.com/en-us/windows-server/networking/dns/dynamic-update)
describes the AD-integrated authentication/ACL model; the actual ACL evidence
belongs in #15. This repository does not change DNS ACLs automatically.

## Update, cleanup and recovery

```mermaid
sequenceDiagram
    participant Flow as ACME workflow
    participant Solver as AD DNS solver
    participant DB as SQLite journal v4
    participant DNS as Approved AD DNS
    participant View as Approved ILM resolver view
    Flow->>DB: Persist challenge references and hashes
    Flow->>Solver: Present exact operation challenge
    Solver->>DB: Check service scope; persist value and random marker
    Solver->>DNS: Kerberos mutual TKEY; verify final GSS signature
    Solver->>DNS: Signed reads of challenge and marker TXT sets
    Solver->>DB: Commit ADDING intent
    Solver->>DNS: Signed atomic UPDATE with full-set prerequisites
    DNS-->>Solver: Verified signed result
    Solver->>DB: Commit ACTIVE and confirmed ownership
    Solver->>DNS: Signed readback of exact value and marker
    Solver->>View: Require value through every approved resolver
    Solver-->>Flow: Presentation confirmed
    Note over Flow,View: CA validation still follows its actual resolver path
    Flow->>Solver: Cleanup using saved references and hashes
    Solver->>DB: Commit DELETING intent
    Solver->>DNS: Signed read; require operation marker
    Solver->>DNS: Atomic exact-RDATA delete of own value and marker
    Solver->>DNS: Signed absence readback
    Solver->>DB: Commit CLEANED
```

The [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136.html) request uses complete
value-dependent TXT prerequisites, or TXT nonexistence for an empty set, at both
names. It also requires no CNAME at those names. A changed prerequisite is a
known non-applied update and permits bounded reread/retry. ADD includes only the
new value and marker. DELETE uses class NONE with their exact RDATA, never class
ANY, whole-RRset deletion or a replacement set. Existing TXT chunks are retained;
an existing RRset's TTL is used for additions. Signed minimal UPDATE replies
with no echoed zone are accepted under section 3.8.

| Observed state | Action |
|---|---|
| Value already exists before this claim's ADD | Reject ownership; do not adopt or delete it |
| Signed permission refusal | Report `ErrDenied`; known rejection has no successful ADD |
| Signed prerequisite conflict | Reread and retry within the configured limit |
| Lost ADD response, own marker and exact value present | Recover confirmation; never repeat the ADD |
| Lost ADD response, both names absent | `ErrReconcile`; absence cannot disprove a still pending packet |
| Owned marker missing while the value remains | Stop; do not infer ownership from the value alone |
| TXT concatenation matches but chunk encoding changed | Stop cleanup; do not guess another writer's RDATA |
| Lost DELETE response, confirmed pair now absent | Commit CLEANED without another update |
| Resolver view missing or incompatible | Return propagation/view error, retain ownership for explicit cleanup/resumption |

`Present` cancellation retains its durable intent. `Cleanup` accepts reference
and hash fields without a raw token/value, looks up the original value locally
and is idempotent after CLEANED. A workflow caller cancellation first persists
`ACMERecord.CancelRequested`, then performs bounded cleanup with a fresh context.
If cleanup fails, a later `Engine.Run` completes only cleanup and returns
`ErrCanceled`; it does not resume issuance. Child network timeouts retain the
original resumable order and challenge. Neither path releases the service lock
or claims that an already submitted CA request was revoked.

The host can inspect `PendingDNS` and resume the original ACME operation or clean
its exact recorded references after restart. There is no age-based sweeper that
deletes active challenges. Unknown outcomes keep their records and service
ownership for explicit reconciliation. DNS records are not undone merely by
editing SQLite, changing configuration or deleting the database.

The private journal now includes challenge TXT values and random markers, in
addition to hashes and references. It stores no raw ACME token, DNS password,
Kerberos ticket, account private key or GSS context. Preserve its private ACL,
WAL consistency and exclusive local-instance boundary.

## Executable evidence and private acceptance

`tests/catalog.json` links the executable assertions A-005 and A-020 onward.
Tests use temporary SQLite, concurrent in-memory authoritative state, loopback
TCP DNS, and synthetic MIC contexts for packet tests. The latter exercise
signature enforcement and TKEY orchestration; they do not simulate a real KDC
or establish AD interoperability. No public CI task reaches the private network.

Before enabling the backend in #15, capture actual DNS-01 offers, both DNS-node
ACLs and negative scope checks, KDC/SPN/AES negotiation, signed AD update/readback,
resolver views as used by ILM, and exact cleanup after success/failure/restart.
Test competing TXT challenges explicitly before enabling multi-value mode.
Synchronize time before Kerberos and signing, and retain the existing RA/template,
CA policy and device-key checks. Source pins and observations are recorded in
[the AD DNS reference](../contracts/ad-dns-reference.json).
