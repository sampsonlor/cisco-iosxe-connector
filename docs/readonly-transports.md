# Read-only device transports — backlog #4

`internal/device.Client` collects bounded discovery evidence over NETCONF and
SSH. It exposes `Collect(ctx, approvedDeviceID)`, with no arbitrary command,
RPC, write or recovery-account API. SQLite continues to store Entity metadata
as implemented in #3. This item does not change that store or add a device
operation journal; durable write intents/locks remain a later milestone.

The collector feeds #5's [inventory adapter](certificate-inventory.md), which
establishes certificate/Trustpoint/active-binding relationships and implements
the Provider's reader. `Evidence.Complete` means all required **wire
reads** finished; it is not proof of valid inventory, supported firmware,
correct time, a matching private key or successful certificate deployment.

## Approved connection policy

The host constructs a client from a copied device registry. Each device has
one approved literal management IP, a NETCONF endpoint and an optional CLI
endpoint. Endpoints contain a port, credential reference and host-key reference.
Only device IDs from that registry can be requested. No request can override
an IP, port, credential or command; addresses bypass DNS/proxy discovery.

The reference resolver returns credentials and an explicit public host key.
The collector uses `ssh.FixedHostKey`, the pinned x/crypto v0.58.0 supported
algorithm set, and one authentication identity. Password authentication or
plain Ed25519/ECDSA/RSA signers are supported; RSA authentication is restricted
to RSA-SHA2. Credentials, signers and host key material are never logged or
persisted by this package. The host is responsible for secure secret lookup.
Certificate-based SSH authentication is outside this initial subset.

CLI and NETCONF may have different pinned host keys, but an automatic
supplement/fallback must use the same credential reference. A different
recovery identity is rejected at construction. A port such as 2222 has no
special treatment and is never guessed or selected automatically.

NETCONF is preferred when its port is configured. Setting its port to zero
is an explicit operator choice of CLI-only mode. TCP errors, timeouts,
authentication failure, host identity changes, malformed responses and AAA
denial do not trigger another transport or identity. A rejected SSH subsystem
is ambiguous: it may be authorization or configuration, so it returns
`ErrSessionRejected` and does not trigger CLI fallback.

## NETCONF reads and capability evidence

NETCONF runs through the `netconf` SSH subsystem. Both base 1.0 end markers and
base 1.1 byte-counted chunk framing are supported, with hello negotiation,
session ID validation, message-ID correlation and bounded frames. XML
directives/entities, excessive depth, duplicate attributes, ambiguous
envelopes and wrong protocol namespaces fail closed. Device schema URLs are
never downloaded.

Only these filtered `get` operations are generated:

| Operation | Filter root / required model |
|---|---|
| PKI metadata | `Cisco-IOS-XE-crypto-pki-oper:crypto-pki-oper-data/crypto-pki-bundle` |
| HTTPS binding | `Cisco-IOS-XE-native:native/ip` plus `Cisco-IOS-XE-http:http/secure-trustpoint` |

Model namespace and module names must be advertised by the peer. Successful
reads establish transport availability for that operation only. Missing
models or explicit `operation-not-supported`/unknown node errors can use the
approved CLI supplement. `access-denied` is a permission failure and ends the
collection. NETCONF write capabilities in hello cannot enable any write API.

The pinned 26.1 reference PKI model contains public certificate metadata and a
storage filename; it does not expose complete PEM certificate bytes. Model
references, namespaces, paths and hashes are recorded in
[`contracts/iosxe-26.1-reference.json`](../contracts/iosxe-26.1-reference.json).
These are design references, not evidence of the live router's schemas or AAA.

## Constrained CLI supplement

The CLI uses a fresh pinned SSH connection and one exec channel per fixed
command, without a PTY or interactive shell. A server may end its connection
after a successful exec; no second channel is assumed. Each command is planned
once, and a rejection never triggers a retry or alternate credential.
No `enable`, terminal configuration, enrollment, import, key generation or
save command is sent. Commands are selected from this fixed set:

| Evidence | Exact command |
|---|---|
| Software/version | `show version` |
| Trustpoints | `show crypto pki trustpoints` |
| Public PEM | `show crypto pki certificates pem` |
| HTTPS binding | `show running-config \| include ^ip http secure-trustpoint` |
| HTTP/HTTPS state | `show ip http server status` |

Successful NETCONF metadata/binding reads are retained; CLI runs only for the
remaining reads. Version, full PEM and HTTP state currently require CLI.
With CLI disabled, the result can explicitly contain partial capabilities;
it never fabricates full inventory support.

Commands fail on authorization denial, nonzero/missing exit status, empty
output, paging or unexpected IOS `%` errors. Known PEM certificate header
markers and the documented unenrolled/CA-only informational notices are admitted
as data; a CA-export failure remains an error. Unknown formats require #5's semantic
parser to reject them; a successful exec alone cannot establish certificate
roles or active binding. The adapter does not work around rejected exec
channels by enabling protocols, adding privileges or opening a shell.

Each collection has a default 15-second overall deadline (configurable up to
one minute); the deadline covers dialing, SSH handshake, channels and reads.
Cancellation closes the connection. Hello is bounded to 64 KiB, and each data
frame/CLI result to 4 MiB. Limit failures close the connection. Failure results
discard raw transcripts and return constant typed errors. Successful raw
evidence is private operational data and must not be published as a fixture.

Safe in-memory audit events record transport, operation and outcome. They do
not contain credentials, device output or public certificate fingerprints.
There is no implicit retry loop; explicit repeated collections obey the same
policy and read-only command/RPC allowlist.

## Acceptance

Tests generate SSH host/client keys in memory and run actual SSH/NETCONF
servers on loopback. A package-private dial substitution routes documentation
addresses to those test servers; production exposes no insecure-host-key or
target-override option. Independent server logs assert the exact CLI allowlist
and NETCONF `get` operations on success, errors and repeated calls.

D-001/D-002/D-006/D-007 now have executable transport evidence. Additional
tests cover framing limits, namespaces, protocol errors, CLI-only policy,
no fallback after connection/authentication failures, Ed25519/RSA-SHA2 client
authentication and concurrent collections. A framing fuzz target is included.
No real device, Core, CA or DNS was accessed in this item. Private read-only
acceptance L-001 remains planned.

References:

- [Cisco IOS XE 26 NETCONF protocol and AAA](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/26x/26x-programmability-cg/netconf_protocol.html)
- [Cisco PKI show command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s3.html)
- [RFC 6241 NETCONF](https://datatracker.ietf.org/doc/html/rfc6241)
- [RFC 6242 SSH transport/framing](https://datatracker.ietf.org/doc/html/rfc6242)
- [Go SSH API](https://pkg.go.dev/golang.org/x/crypto/ssh)
