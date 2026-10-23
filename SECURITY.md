# Security reporting

Do not disclose device credentials, internal addresses, private keys or live
device configuration in public issues, pull requests or Actions logs.

Use GitHub private vulnerability reporting when it is enabled for this
repository. If it is unavailable, open an issue containing only a request for
a private reporting channel, without vulnerability details or environment
data.

No version is supported for production use yet. Public CI does not establish
that deployment, recovery or device permissions are safe in a particular
network. Those capabilities require the explicit acceptance gates documented
in `docs/test-strategy.zh-CN.md`.
