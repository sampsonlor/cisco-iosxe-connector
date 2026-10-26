# Device-generated CSR — backlog #8

The CSR library creates a separate RSA key and terminal-enrollment Trustpoint
through a pinned, explicitly enabled SSH adapter. The shared lifecycle gate
persists the request before dispatch and validates the public result before
committing CSR_READY. This is an internal component: the read-only Provider
continues to return 501 for CSR/push. There is no new live-test executable,
credential input, signing request or production HTTPS activation in this item.

## Verified interfaces and selected scope

The published IOS XE 26.1 YANG reference was inspected at YangModels commit
`7cb93ea27b7ee86ad3dd9f82998146aa838d13b8`:

| Source | Revision | Git blob |
|---|---|---|
| [Cisco-IOS-XE-rpc](https://github.com/YangModels/yang/blob/7cb93ea27b7ee86ad3dd9f82998146aa838d13b8/vendor/cisco/xe/2611/Cisco-IOS-XE-rpc.yang) | 2026-02-01 | `99d5a5371100b66238d0e8999ea2c75abdeb634a` |
| [Cisco-IOS-XE-crypto-rpc](https://github.com/YangModels/yang/blob/7cb93ea27b7ee86ad3dd9f82998146aa838d13b8/vendor/cisco/xe/2611/Cisco-IOS-XE-crypto-rpc.yang) | 2026-02-01 | `c7d8b89758c3879054349aedfd238509b42fde16` |

The parent crypto RPC includes a generic string `result`; the submodule includes
enrollment input. This is not a tested contract for retrieving a complete CSR
through terminal enrollment, nor evidence that an actual target advertises or
executes that path. The published release reference is not an exact schema dump
from the target's 26.01.02 image. A NETCONF/RESTCONF CSR adapter therefore remains
future capability acceptance; there is no automatic RPC/CLI fallback on errors.

This implementation uses Cisco's documented terminal PEM workflow, with an
explicit per-target CLI policy. RSA generation omits the exportable flag; the
adapter then reads the named public key and requires the device's non-exportable
status and a public key matching the signed CSR. It never attempts a private-key
export. See [Cisco's PKI workflow](https://www.cisco.com/c/en/us/support/docs/security-vpn/public-key-infrastructure-pki/220422-configure-ca-signed-certificates-with-io.html)
and [RSA key status examples](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_conn_pki/configuration/xe-16-10/sec-pki-xe-16-10-book/sec-deploy-rsa-pki.html).

## Production wiring boundary

Use `lifecycle.NewIOSXECSRGate(store, client, policies)` to wire the journal,
concrete adapter and `inventory.VerifyCSRBaseline`. The generic constructors
remain dependency-injection points for tests/trusted hosts; substituting a
successful transport check for semantic inventory validation is unsafe.

`device.CSRPolicy` must explicitly set `AllowWrites`, the exact observed IOS XE
version, reviewed policy digest, CSR specification, unused staging pool and
protected active/rollback Trustpoint and key names. The constructor copies all
policy values. Default-disabled or invalid policy cannot authenticate or write.
The journal's target, pinned SSH fingerprint, policy digest and staging name must
match the adapter's approved target. Request attributes do not supply commands,
connection overrides or credentials.

The supported specification contains one CN, optional O/OU, exact DNS SANs and
RSA 2048/3072/4096 with SHA-256. It is deliberately limited to bounded ASCII DNS
and DN values, CN at most 64 bytes and an internal SAN command limit of 512
bytes. Wildcards, IP/email/URI SANs, DN delimiters and unapproved algorithms are
rejected. The validator checks the CSR signature, exact Subject/SAN, RSA size and
exponent, expected device SPKI and permitted extensions. This does not establish
that AD CS will accept the request or that a future certificate meets RA/template,
EKU, validity or chain policy; [the certificate gate](certificate-policy.md)
handles those checks against current trusted enrollment evidence.

## Generation sequence

```mermaid
sequenceDiagram
    participant Caller as API / worker
    participant Gate as CSR lifecycle gate
    participant DB as SQLite journal
    participant Device as IOS XE SSH
    Caller->>Gate: operation reference + approved CSR specification
    Gate->>DB: commit normalized request + KEY_CREATING intent
    alt Recorded CSR already exists
        DB-->>Caller: same verified public CSR; no generation
    else Unknown prior generation
        DB-->>Caller: reconciliation required; no generation
    else New committed intent
        Gate->>Device: pinned reads: inventory/config/key labels/NTP
        Gate->>Device: generate uniquely labelled non-exportable RSA key
        Device-->>Gate: public key and exportability status
        Gate->>Device: recheck active baseline and unused Trustpoint
        Gate->>Device: create only new terminal-PEM Trustpoint; bind new key
        Gate->>Device: enroll; answer only display=yes and redisplay=no
        Device-->>Gate: public PKCS#10 request
        Gate->>Device: repeat key/config/inventory checks
        Gate->>Gate: verify signature, Subject/SAN, key policy and device SPKI
        Gate->>DB: commit public CSR/SPKI + CSR_READY + history event
        Gate-->>Caller: public CSR only
    end
```

Before mutation the adapter requires complete inventory with the expected active
leaf/binding, the configured image, synchronized NTP, full Trustpoint configuration
and RSA/EC public-key inventory. It rejects an occupied Trustpoint or key label,
protected name and any existing reference to the new label. The new key label is
derived from the server-generated operation UUID, not a caller-selected label.
Its public key must differ from every existing key. Before creating the
Trustpoint, inventory and names are read again because key generation can take
time. After enrollment, existing configurations/keys and the active leaf/binding
must remain unchanged; only the expected new key and Trustpoint may appear.

The shell sends only compiled, parameter-validated commands. It has bounded
output/deadlines, strict privileged/configuration prompts, fixed display/redisplay
answers and no enable-password path. Replacement/overwrite prompts, unknown
prompts, paging, stderr, authorization errors and timeouts stop the session.
There are no delete, zeroize, export, HTTPS-binding or save commands. No raw
configuration, password or console diagnostic is written to the journal or
returned in an error. The private host still needs appropriate directory ACLs.

CLI has no atomic compare-and-create operation covering a Trustpoint and a key.
The staging namespace must be reserved exclusively for the connector and other
administrators must not repurpose it during generation. Repeated reads detect
observed drift; they cannot exclude an administrator racing between the last
read and a command. This is a required private-lab boundary, not a claim of a
device-wide transaction. No production live operation has been enabled by CI.

## Persistence, uncertainty and inventory

Journal schema v2 adds normalized CSR specifications, unique key labels and public
CSR/SPKI artifacts. The v1-to-v2 migration is transactional and preserves existing
operation IDs, correlations, states, history and service ownership. Missing or
inconsistent v2 artifacts fail startup; legacy unfinished operations are not
regenerated. CSR_READY and its artifacts commit together. No private key is
generated by production Go code, sent to the connector or stored in SQLite.

The Store holds instance ownership while the generation callback runs. Any
unknown device result, failed validation or failed completion write leaves
KEY_CREATING and the service lock intact. A repeated request cannot regenerate
the key. `CSRGate.Reconcile` only reads current public state; it cannot recover a
lost CSR, silently rerun enrollment, mark success or release ownership. A later
recovery workflow must handle unresolved work explicitly. Cached CSR return is
recorded evidence, not proof that a device has retained its key after a reboot;
the import stage must recheck actual key/baseline state.

Inventory now represents an empty Trustpoint only when an exact, matching
unenrolled notice accompanies its explicit group and configuration. It is
listed separately in `UnenrolledTrustpoints`; it is never fabricated as a
certificate or key-availability claim. Missing, contradictory or truncated
evidence still fails, and an active identity is still required. Existing CA-only
notices remain supported. NETCONF empty-bundle semantics remain conservative.

## Evidence and next live test

Tests generate keys only inside synthetic device/CSR fixtures. An actual local
SSH server exercises PTY/shell requests, command order, non-exportable key proof,
public CSR validation, occupied slots, replacement and unknown prompts, NTP/image
mismatch, wrong host identity, stderr and timeout. Real temporary SQLite tests
cover concurrent generation, cached restart results, request mutation, missing
schema and failure before/after the device callback. No router, ILM or CA is
contacted by these tests.

The next private test remains #15 / L-002. It must verify the actual interactive
profile, command permissions/output, reserved unused names, independent recovery
access and time synchronization before any write. #6's NTP deferral does not
waive this requirement. Certificate/chain and AD CS policy matching are implemented
in #9; external-CSR ACME orders follow #10, and real inactive import and observation
follow #12.
