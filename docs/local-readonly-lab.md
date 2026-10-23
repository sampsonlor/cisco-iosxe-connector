# Local read-only lab — backlog #6

`cmd/iosxe-lab` is a manual Windows acceptance entry point for a computer
already authorized to reach the management network. Public GitHub CI runs
only synthetic tests; it never invokes this entry point against a real target.
This is not the deployable Connector HTTP host or an issuance/deployment tool.

## Invocation

Build from the reviewed source with the pinned Go toolchain. Use an approved
literal target, a trusted OpenSSH **public** host key file, and a new private
directory outside any Git checkout. Example values below are synthetic:

```powershell
go build -o C:\PrivateLab\iosxe-lab.exe ./cmd/iosxe-lab
C:\PrivateLab\iosxe-lab.exe `
  --address 192.0.2.10 --hostname router.example.test `
  --username operator --ssh-port 22 --https-port 443 `
  --host-key-file C:\PrivateLab\trusted-router.pub `
  --evidence-dir C:\PrivateLab\run-001
```

The supplied directory must exist and contain no previous report. Give only
the current operator and necessary system identities access to it. Windows
file mode bits do not establish an ACL: the operator must protect the parent
directory. The tool rejects directories inside Git checkouts, including
resolved symlink targets, and creates `report.json` exclusively without
overwriting. Linux/macOS builds intentionally do not implement this password
dialog; no CI secret or interactive prompt is required by the synthetic tests.

Windows CredUI prompts for the supplied username and SSH password, with
`DO_NOT_PERSIST`, `ALWAYS_SHOW_UI`, generic credentials and a fixed username.
There is no password command-line flag, environment variable or password
file. Passwords exist in process memory for the run; the UTF-16 dialog buffer
is cleared after use. Go/SSH string copies cannot be guaranteed erased before
process exit. The program never logs credentials or sends them to TLS/HTTP.

The trusted host key must come from an independently verified source. An
unverified `ssh-keyscan` result alone is not a trust decision. The initial
tool uses the same supplied pin for CLI and an optional NETCONF daemon;
a different daemon identity fails before authentication, with no automatic
pin acceptance or alternate account/port selection.

## Reads and independent verification

The existing five inventory commands from #4 remain unchanged. A separate
readiness method sends only these fixed commands through SSH exec, including
an early HTTPS status observation for diagnosing incomplete inventory:

```text
show clock detail
show ntp status
show privilege
show running-config | include ^netconf|^restconf
show ip http server status
```

Each fixed command uses its own pinned SSH connection; servers that end the
connection after one exec are supported without retrying any command.
There is no arbitrary-command API, interactive shell, `enable`, terminal
setting, key generation, CSR, import, activation or save operation. Empty
output from the protocol configuration filter is recorded as a limited CLI
observation. It does not establish that NETCONF is disabled, nor constitute an
empty certificate inventory. Readiness permission
failure stops collection; no identity escalation or automatic retry occurs.

The NTP-disabled notice and `No time source` are retained as explicit readiness
observations. Recording a clock is distinct from proving time synchronization.
For #6, the operator deferred NTP to the next live test (#15 / L-002); it does
not block this read-only acceptance. Time synchronization remains a prerequisite
before a later live issuance/staging operation.

The tool captures readiness, reads the inventory, makes an independent TLS
handshake, and then repeats the inventory and TLS read. It compares the active
binding, all certificate/Trustpoint occurrences and the wire-served leaf.
The TLS verifier requires exact DER equality with the public leaf learned
through pinned SSH and validates the DNS name. CA chain validation is recorded
separately against system trust. It sends no HTTP application data. A pinned
baseline match must never be reported as proof of a trusted CA chain, expiry
policy, revocation or future renewal eligibility.

`--netconf-port` is optional and defaults to zero, selecting `cli-only` scope.
A nonzero approved port selects `netconf-and-cli` and attempts that endpoint
regardless of the CLI filter result. No protocol is enabled. The probe retains
the validated server hello and the existing filtered PKI/binding reads;
actual model revision presence and inventory semantics are checked together.
Absent or unverified models prevent PASS for `netconf-and-cli`. They are not
required for `cli-only`, whose report explicitly states that NETCONF and model
revisions were not tested. Authentication/host-key/permission failures on a
selected endpoint still stop the run.

## Result scope

The private report contains raw public certificate evidence, operational
outputs, model hello when collected, source addresses, fixed-operation audit
events and public fingerprints. Treat the whole report as private operational
data. Publish only a sanitized summary and a private evidence reference.

The lab entry point opts into bounded copies of CLI replies for private
diagnostics, including a failed certificate read. `WireReads.Complete` means
exec finished; `Accepted` records the transport's validation decision. Neither
field is a healthy inventory claim. Default collector failures still discard
`Evidence.Raw`; diagnostic replies never feed the Provider's InventoryReader.

`PASS` requires all gates for the explicitly selected scope: recorded clock
and completed readiness, complete repeated inventory, matching independent TLS
DER/name, stable baseline, and an audit containing only fixed read operations.
Selected NETCONF additionally requires actual model revisions and matching
inventory semantics. CA trust and time synchronization are separate observations.

The operator-approved account may have read/write privileges, including level
15. Acceptance evaluates the operations performed, not proof that the account
cannot write. No configuration command is sent to test write permission. This
acceptance does not grant future write authorization: renewal needs phase-specific
permissions for keys/CSR/import, with separate activation/persistence controls.

`no-mutation-requests` describes only this tool's allowlisted requests. Matching
before/after snapshots cannot prove that no other actor changed the device
between reads. Independently retained device-side AAA accounting can strengthen
the audit; the tool does not enable accounting or retrieve unrelated logs.

An observed failure produces `FAIL`; missing required scope evidence produces
`INCOMPLETE`. Both return nonzero status. The report must be reviewed before
#6 / L-001 is closed; no offline test substitutes for that acceptance.

## Reassessing a completed recorded run

When the operator changes acceptance scope, preserve the original live report
and create a separate assessment:

```powershell
go build -o C:\PrivateLab\iosxe-lab-assess.exe ./cmd/iosxe-lab-assess
C:\PrivateLab\iosxe-lab-assess.exe --scope cli-only C:\PrivateLab\run-001\report.json
```

This creates `acceptance-assessment.json` exclusively beside the private report,
with its original SHA-256, policy version and evaluation time. It revalidates
the recorded complete inventories, operation audit and TLS evidence; it does
not open a connection or rerun any live check. Failed executions, conflicting
selected scopes, incomplete reads or inconsistent evidence cannot become PASS.
Neither file may be overwritten or placed in a Git checkout. For legacy reports
without a scope field, the operator must verify the recorded execution mode
before selecting scope; the assessment is not an independent attestation of
the recording's authenticity or present device state.

Private reference `L001-20261023-run04` records the completed CLI-only live run.
Its original broader-gate report remains `INCOMPLETE`; a separate `read-only-v2`
assessment accepts the operator-approved CLI scope with NTP deferred. Live
NETCONF, ILM Core registration and issuance/deployment remain untested.

## Offline reply replay

`go run ./cmd/iosxe-lab-replay C:\PrivateLab\run-001\report.json` revalidates
captured reply semantics with the current parser without connecting anywhere.
It requires a completed exec for every inventory read, even when an older
parser rejected a now-supported display form. The summary is explicitly
`OFFLINE_REPLAY`; it cannot establish current device state, repeated inventory
stability, TLS availability, AAA restrictions or live acceptance. Real replies
remain private; only generated equivalents belong in regression tests.

Sources:

- [Cisco show clock semantics](https://www.cisco.com/E-Learning/bulk/public/tac/cim/cib/using_cisco_ios_software/cmdrefs/show_clock.htm)
- [Microsoft CredUI flags and credential lifetime](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creduipromptforcredentialsw)
- [Existing inventory evidence and limitations](certificate-inventory.md)
