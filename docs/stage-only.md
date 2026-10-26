# Inactive certificate staging — backlog #12

`lifecycle.StageGate` imports a validated public certificate into the existing,
operation-owned CSR Trustpoint and stops at STAGED. `NewIOSXEStageGate` wires the
real inventory verifier, opt-in pinned SSH adapter and independent TLS probe.
The default Entity Provider remains read-only; the opt-in
[native CSR/push adapter](native-core-lifecycle.md) now reuses this gate.
The credential/service host follows #14. Actual router acceptance is #15.

## Reviewed transport and CA layout

The pinned [26.1 crypto RPC model](https://github.com/YangModels/yang/blob/7cb93ea27b7ee86ad3dd9f82998146aa838d13b8/vendor/cisco/xe/2611/Cisco-IOS-XE-crypto-rpc.yang#L184)
declares an empty `import/certificate` selector and PKCS12 URL/password fields,
without an inline public-certificate payload. The enclosing RPC has a generic
string result. This does not establish an inline NETCONF import transaction.
The initial adapter therefore uses an explicitly enabled SSH terminal channel;
discovery does not advertise import/switch/save based on those YANG nodes.

The [Cisco PKI guide](https://www.cisco.com/c/en/us/support/docs/security-vpn/public-key-infrastructure-pki/220422-configure-ca-signed-certificates-with-io.html)
and [command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-c5.html)
distinguish authenticating a CA from importing the identity certificate. Each
Trustpoint holds one CA certificate; the immediate issuer belongs in the CSR
Trustpoint. Higher CAs use other Trustpoints. The adapter authenticates only the
validated immediate issuer, then imports the leaf into that same inactive slot.
For a longer path, every higher CA must already exist at an explicitly approved
protected Trustpoint with matching DER. It creates or changes no ancestor slot.

The source examples cover older IOS XE versions; exact target-image prompts,
inventory output, chain lookup and accepted configuration remain private test
conditions. [The immutable source manifest](../contracts/iosxe-staging-reference.json)
records the reviewed model blobs and observations. Unknown prompts fail closed.

## Trusted host construction

```go
gate, err := lifecycle.NewIOSXEStageGate(
    journalStore, certificateValidator, deviceClient,
    approvedStagePolicies, approvedHTTPSPorts,
)
result, err := gate.Stage(ctx, operationRef, leafDER, returnedPublicChain)
```

The host supplies the same approved service policy/validator used for issuance.
The reference includes the original Entity/Location, device, address, host-key
fingerprint, owner, active Trustpoint, baseline SHA-256 and staging name. The
operation UUID alone grants no access. Leaf-only input resolves its complete
path from the validator's approved public bundle; it performs no network issuer
fetch and adds no root from caller-provided data.

`device.StagePolicy` embeds the existing `CSRPolicy`: explicit `AllowWrites`,
exact image version, canonical CSR spec, policy digest, reserved staging pool
and protected names. Its optional `Ancestors` maps higher-CA SHA-256 values to
existing protected Trustpoints. Every device also needs an explicitly approved
HTTPS port. Constructors freeze these inputs and hash effective adapter/endpoint,
policy and TLS settings; unfinished artifacts cannot be rebound to new settings.

The concrete adapter checks the pinned host before authentication, uses the
fixed CLI read allowlist and never enables another protocol. Every preflight
requires the exact configured version, complete inventory, unchanged active
Trustpoint/leaf, synchronized NTP, exact CSR Trustpoint configuration, and the
operation-derived non-exportable key with matching SPKI. Other Trustpoints must
not reference that key label. A separate state digest covers non-staging
certificate inventory, other Trustpoint configuration and all observed public
keys; it must remain stable through staging and recovery.

The initial slot must contain neither issuer nor leaf. Existing certificates
are not adopted merely because their bytes happen to match. The command surface
contains configuration-mode entry/exit, CA authentication, and public identity
import for the exact approved staging name. It contains no key creation/import,
PKCS12, certificate deletion, revocation-policy weakening, HTTPS binding write,
global configuration save or activation command. Platform PKI storage may
persist imported objects internally; global configuration persistence and
activation retain their separate gates.

## Durable sequence and fresh validation

```mermaid
sequenceDiagram
    participant Host as Trusted Core/ACME host
    participant Gate as Shared StageGate
    participant V as Certificate validator
    participant DB as SQLite journal v5
    participant Dev as Pinned IOS XE
    participant TLS as Independent HTTPS connection
    Host->>Gate: Full operation reference and public leaf/chain
    Gate->>DB: Acquire operation lock; read saved CSR and owner
    Gate->>V: Revalidate leaf, path, template, time and enrollment evidence
    Gate->>DB: Bind immutable public artifacts and adapter settings
    Gate->>Dev: Read inventory, CSR configuration, public keys and NTP
    Gate->>TLS: Verify exact baseline DER and approved hostname
    Gate->>DB: Save unrelated-state baseline; commit IMPORTING
    Gate->>Dev: Re-observe reserved slot and original baseline
    Gate->>V: Refresh policy/evidence before each write
    Gate->>DB: Recheck operation revision and ACME cancellation
    Gate->>Dev: Authenticate validated immediate CA on inactive slot
    Gate->>Dev: Independently reread issuer, key and unchanged state
    Gate->>V: Refresh policy/evidence before leaf import
    Gate->>DB: Recheck current cancellation and correlation
    Gate->>Dev: Import only the public leaf into the same slot
    Gate->>Dev: Independently verify complete issuer/leaf and device key
    Gate->>TLS: Fresh handshake must still present original baseline
    Gate->>V: Revalidate current policy/evidence for completion
    Gate->>DB: Commit STAGED and history
    Gate-->>Host: STAGED withKey=true from fresh device evidence
```

The certificate-policy receipt is short-lived and opaque. The gate reloads the
saved CSR, verifies the candidate digest, and revalidates policy/time/template/
permissions even on retries. `StageOnce` commits intent before dispatch, holds
instance ownership through the callback and completion, and supplies a recheck
that avoids recursive Store locking during shutdown. The real adapter invokes
that authorization check again before each certificate command, payload and CA
acceptance. A permission change or cancellation stops subsequent writes.

CA acceptance is limited to the documented question after submitting approved
DER. The displayed SHA256 or legacy SHA1 fingerprint must match that submitted
DER before answering. SHA1 is used solely to compare the legacy CLI display;
trust comes from the validated pinned path and exact-DER readback. Replacement,
overwrite, key-password, paging, stderr, unknown prompt or unexpected success
output stops the session. Returned diagnostics contain no transcript or secret.

The independent probe creates a fresh TLS connection with TLS 1.2+, the recorded
target and approved port/SNI. It authenticates exact baseline DER obtained via
pinned SSH and verifies the hostname. CA trust for that old baseline is evaluated
separately by the reused probe. No HTTP request or management credential is sent.
An import error/cancellation also triggers a bounded fresh baseline probe using
the already pinned pre-dispatch DER, while its import outcome stays unresolved.

`withKey=true` requires current matching leaf/issuer and a non-exportable public
key matching the saved, signed CSR. Cached STAGED alone cannot produce it. This
is staging association evidence; activation will separately prove use of the
new certificate through an actual new TLS handshake.

## Recovery and cancellation

| Durable state / observation | Behavior |
|---|---|
| CERT_READY with empty owned CSR slot | Persist artifacts/baseline and one import intent |
| CERT_READY with an existing issuer or leaf | Refuse adoption; no import |
| IMPORTING after error, process loss or lost reply | Read-only inspection and TLS verification; no redispatch |
| IMPORTING with only issuer, missing leaf, missing key or changed state | Retain uncertainty and service ownership |
| IMPORTING with exact complete result and original TLS | Fresh policy validation, then CAS commit STAGED |
| STAGED retry | Fresh inventory/key/TLS/policy validation before returning withKey |
| ACME cancellation recorded or ACME issuance not complete | Block staging before actual dispatch |
| Failed artifact/intent commit | No device mutation |
| Failed completion commit | Keep IMPORTING; recover using independent reads |

The operation lock is shared with ACME runs for ACME-owned services. Native Core
and worker ownership remain exclusive through the journal's service binding.
Cancellation does not revoke a CA request or remove imported objects. A cancelled
operation retains ownership and requires explicit operator handling; it cannot
continue automated issuance/import. There is no automatic slot/key cleanup,
expiry-based lock release or rollback of unrelated changes. CLI lacks a
cross-administrator compare-and-create transaction: reserve the staging namespace
for this connector and treat observed competing changes as a conflict.

## Journal v5 and evidence

`staging_operations` stores immutable public leaf/path DER, saved CSR digest,
effective settings digest, unrelated-state baseline and its own CAS revision.
Operation IMPORTING/STAGED transitions still commit history atomically. It stores
no private key, password, permission receipt or device transcript. Migration from
v4 preserves prior operation/CSR/ACME/DNS data. Missing runtime import provenance,
foreign schemas and inconsistent records fail startup; no inferred success or
database reset is performed. The earlier digest-only ImportGate remains a
foundation harness and refuses any operation with a real recorded CSR.

Executable evidence includes real temporary SQLite, loopback SSH certificate
dialogues, separately parsed complete inventory, fresh loopback TLS, permission
and ACME-cancellation races, storage fault injection, concurrent calls, shutdown
and restart. Packet/semantic/gate tests are separate layers; they establish no
actual IOS XE write or ILM lifecycle compatibility. S-007's Core DTO integration
is covered by the native adapter's joint test; C-009 and private stage-only
acceptance remain #15/L-002.

Before the first real write, finish the deferred NTP check, confirm the exact
image/prompt dialect and reserved CSR configuration, pin recovery access, verify
effective command permissions and the actual RA/template/CA policy, and confirm
any higher CAs already installed in approved protected slots. Capture independent
old TLS before/after success and injected failure, exact key/issuer/leaf readback,
and lost-response recovery. Actual hostnames, DER/fingerprints, raw output and
credential evidence remain private.
