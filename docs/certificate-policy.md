# Certificate acceptance policy — backlog #9

`internal/certpolicy` validates a public leaf against the durable device CSR,
approved service identity, explicit CA bundle and trusted enrollment evidence.
`lifecycle.CertificateGate.Accept` reads that CSR from SQLite and commits
CERT_READY only after validation. It has no signing, network-chain-fetching,
device import or HTTPS binding capability. The default HTTP Provider remains
read-only; the opt-in [native adapter](native-core-lifecycle.md) uses these checks.

## Host configuration and trust boundary

Construct `certpolicy.New(policy, clock, evidenceSource)` before opening the
operation journal. Use `validator.Digest()` as the approved issuance policy hash
in the journal binding and matching device CSR policy. A change to an effective
security field changes that digest and requires the existing explicit policy
reconciliation rules. RA Profile display-label changes do not change identity.
The constructor copies DER buffers, DNS names, issuer pins and version pointers.
Bundle ordering and duplicate configured certificates do not change the digest.

| Input | Meaning |
|---|---|
| `Spec` | Exact approved Subject CN/O/OU, DNS SAN set and device RSA size |
| `RAProfileID`, `AuthorityID` | Stable reviewed ILM enrollment binding; not display names |
| `Template` | Technical AD CS name; for v2 also template OID and exact version presence/value |
| `PrincipalRef`, `EvidenceRef` | Private effective enrolling principal and authenticated evidence selector |
| `BundleRef`, `Roots`, `Intermediates` | Reviewed bundle identity and public DER CA certificates |
| `IssuerSHA256` | Allowed immediate issuing CA certificate hashes, distinct from root anchors |
| `KeyUsage` | Explicit digitalSignature, optionally keyEncipherment for the RSA HTTPS key |
| Time limits | Minimum remaining validity, maximum lifetime/backdating, clock error/freshness and evidence age |

These are trusted host inputs, not additional ILM DTO fields. No runtime policy
loader, AD ACL collector or public configuration endpoint is added here. The
future authenticated host must resolve private references with least privilege;
Core attributes must not be allowed to assert successful authorization checks.

`Clock.Read` must report current UTC, synchronization, observation time and
bounded uncertainty from the host's checked time source. Bare `time.Now()` does
not establish synchronization. Missing, stale, future or excessive-uncertainty
readings fail closed. Tests use a synthetic checked clock; they do not waive the
device NTP acceptance deferred to #15 / L-002.

## Certificate and chain checks

The saved CSR must still pass signature, Subject/SAN, RSA size/exponent, public
key and recorded non-exportable-key-proof checks. The leaf must have the same
SPKI and exact Subject and DNS-only SANs. Added IP/email/URI/otherName SANs,
duplicates, missing names and extra Subject attributes are rejected.

Require an explicit, exact KeyUsage and serverAuth-only EKU, no CA status and
modern signatures. A legacy leaf may omit Basic Constraints; it cannot gain CA
or signing-key usages. If Microsoft Application Policies is present, require
exactly serverAuth without qualifiers, as its encoding permits. See the
[Microsoft extension specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/160b96b1-c431-457a-8eed-27c11873f378).

Validity must cover the checked clock's uncertainty and approved remaining
lifetime, maximum total lifetime and backdating. Private-CA lifetime is explicit
policy; there is no hardcoded public WebPKI lifetime limit.

Only explicit self-signed approved roots populate a new trust pool. Cached and
returned intermediates must be CA certificates with certificate-signing usage
and strong keys/signatures. Verify the complete path, CA validity, constraints,
hostname and serverAuth purpose at the checked time. Require the immediate
issuer's certificate hash to match both the policy pins and enrollment evidence.
Returned duplicate/unrelated certificates, unknown roots, malformed data and
incomplete paths are rejected. Leaf-only input works when the approved local
bundle supplies its path; no chain field is invented for Core push.

There is no operating-system trust fallback or AIA download. Revocation is
outside this component: Go's verifier does not perform it, so a passed receipt
must not be represented as a CRL/OCSP check. Any later revocation requirement
needs a separately reviewed provider and acceptance. See
[Go's Verify contract](https://pkg.go.dev/crypto/x509#Certificate.Verify).

## Template identity and effective permissions

V1 checks the technical template name from extension `1.3.6.1.4.1.311.20.2`.
The decoder accepts strict legacy BMPString and the single UTF8String sequence
documented by [MS-WCCE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/3aec3e50-511a-42f9-a5d5-240af503e470).
Both forms are limited to the same bounded ASCII technical-name syntax, with
no trailing fields or lossy Unicode conversion. They are encoding alternatives,
not alternative enrollment identities.

V2 checks `1.3.6.1.4.1.311.21.7`: template OID and optional unsigned 32-bit
major/minor versions. Absence and explicit zero are different; configured
presence and values must match exactly. A concurrent legacy-name extension must
agree. Critical template extensions and conflicting/malformed encodings are
rejected. See [the v2 ASN.1 definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9da866e5-9ce9-4a83-9064-0d20af8b2ccf).

The evidence source must authenticate a current, private snapshot that binds the
policy digest, RA/Authority IDs, effective enrolling principal, template and
issuer. It must affirm the RA mapping, template publication, CA computer's
template read access, effective CA Request Certificates permission, template
Read/Enroll and permitted request-supplied Subject/SAN policy. The snapshot
reference/hash and bounded validity provide audit correlation and freshness;
a hash alone does not authenticate the snapshot. Denied/stale/missing evidence
blocks acceptance. Group membership, deny entries and the actual connector
identity must be resolved by the trusted source. Certificate contents or an old
CA request number cannot establish those permissions. See
[Microsoft's template permissions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/75d6d6d3-9fa0-4f20-85c6-64e4d2ff854e)
and [template management](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates).

Public CI uses synthetic snapshots and does not independently query AD ACLs.
Actual RA IDs, technical template identity/versions, enrolling-principal rights,
CA bundle and snapshot-source protection remain private evidence under #15.
Friendly RA labels, legacy certificate templates and renewal templates must not
be assumed equivalent.

## Durable acceptance and retries

```mermaid
sequenceDiagram
    participant Caller as Future Core / ACME path
    participant Gate as CertificateGate
    participant DB as SQLite journal
    participant V as Certificate validator
    participant E as Trusted host clock / private evidence
    Caller->>Gate: Operation reference + leaf + optional returned chain
    Gate->>DB: Authorized current revision + saved CSR/specification/SPKI
    Gate->>V: Validate against saved CSR and frozen policy
    V->>E: Read current time and effective enrollment snapshot
    V->>V: Verify identity, key, purpose, template, time and pinned path
    alt Any check fails
        V-->>Gate: Safe typed error; no receipt
        Gate-->>Caller: State unchanged; no import or switch
    else All checks pass
        V-->>Gate: Short-lived opaque receipt and copied public chain
        Gate->>DB: CAS revision; bind CSR/policy/leaf hashes; CERT_READY + event
        Gate-->>Caller: Recorded state + transient validation receipt
    end
```

Receipts have private fields, copied DER/path bytes, evidence provenance and a
maximum one-minute handoff window shortened by evidence/clock/certificate expiry.
The journal checks receipt freshness against host time, saved CSR hash, approved
policy digest, baseline exclusion and current revision in the commit transaction.
A zero, expired, mismatched or stale-revision receipt cannot advance the record.
Same-leaf retries preserve the revision; changing the bound leaf is rejected.

The old digest-only `CertificateReady` entry point is retained solely for the
journal foundation harness and rejects any operation with a recorded CSR. The
runtime certificate gate requires recorded artifacts. The ACME component extends
the journal to [schema v3](acme-external-csr.md) while preserving these artifacts;
the certificate gate persists only the accepted digest/state/history, not a reusable permission
grant or receipt. Every `Accept` retry, including after reopening SQLite, checks
time and evidence again. Failure leaves service ownership and state intact.

The [runtime StageGate](stage-only.md) revalidates the actual certificate,
time/evidence, device key and baseline immediately before public-certificate
import. Journal v5 records its immutable artifacts/settings and exact read-only
recovery boundary. The counting ImportGate remains a journal harness and rejects
real recorded CSRs; the [native HTTP lifecycle](native-core-lifecycle.md) now
shares the runtime gates. Actual Core/router acceptance remains private.

## Executable evidence

Runtime-generated CA/CSR/leaf tests cover mismatched keys and identities, SAN/EKU/
KeyUsage, validity, clocks, template DER/version/permissions, pinned and incomplete
chains, CA name/purpose constraints, defensive copies and concurrent validation.
Real temporary SQLite tests reject raw-digest/zero-receipt/revision bypasses and
show that invalid acceptance does not advance state. Gate tests reopen the
journal, revoke synthetic enrollment permission and reject a cached-leaf retry.
These assertions run offline; no router, ILM, CA, AD or DNS service is contacted.
