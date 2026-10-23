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
  --username reader --ssh-port 22 --https-port 443 `
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
readiness method sends only these four fixed commands through SSH exec:

```text
show clock detail
show ntp status
show privilege
show running-config | include ^netconf|^restconf
```

Each fixed command uses its own pinned SSH connection; servers that end the
connection after one exec are supported without retrying any command.
There is no arbitrary-command API, interactive shell, `enable`, terminal
setting, key generation, CSR, import, activation or save operation. Empty
output from the protocol configuration filter is a valid absence of explicit
configuration, not a valid empty certificate inventory. Readiness permission
failure stops collection; no identity escalation or automatic retry occurs.

The tool captures readiness, reads the inventory, makes an independent TLS
handshake, and then repeats the inventory and TLS read. It compares the active
binding, all certificate/Trustpoint occurrences and the wire-served leaf.
The TLS verifier requires exact DER equality with the public leaf learned
through pinned SSH and validates the DNS name. CA chain validation is recorded
separately against system trust. It sends no HTTP application data. A pinned
baseline match must never be reported as proof of a trusted CA chain, expiry
policy, revocation or future renewal eligibility.

`--netconf-port` is optional and defaults to zero. It is used only when the
readiness output explicitly contains the already-configured `netconf-yang`
line. No protocol is enabled. When authorized and supplied, the probe retains
the validated server hello and the existing filtered PKI/binding reads;
actual model revision presence and inventory semantics are checked together.
Absent or unverified models remain visible as an incomplete gate.

## Result scope

The private report contains raw public certificate evidence, operational
outputs, model hello when collected, source addresses, fixed-operation audit
events and public fingerprints. Treat the whole report as private operational
data. Publish only a sanitized summary and a private evidence reference.

`PASS` requires every recorded gate. Technical observations can succeed while
overall status remains `INCOMPLETE`, especially when NETCONF models are not
available or account restrictions have not been independently established.
The tool deliberately cannot prove restricted write privilege by executing
configuration commands. A privilege-15 account used only for reads is not
classified as a restricted identity. Review this gate against private AAA
policy evidence or use an approved restricted account before accepting it.

`no-mutation-requests` describes only this tool's allowlisted requests. Matching
before/after snapshots cannot prove that no other actor changed the device
between reads. Independently retained device-side AAA accounting can strengthen
the audit; the tool does not enable accounting or retrieve unrelated logs.

An observed failure produces `FAIL`; missing environment evidence produces
`INCOMPLETE`. Both return nonzero status. The report must be reviewed before
#6 / L-001 is closed; no offline test substitutes for that acceptance.

Sources:

- [Cisco show clock semantics](https://www.cisco.com/E-Learning/bulk/public/tac/cim/cib/using_cisco_ios_software/cmdrefs/show_clock.htm)
- [Microsoft CredUI flags and credential lifetime](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creduipromptforcredentialsw)
- [Existing inventory evidence and limitations](certificate-inventory.md)
