# Contributing

Start with the acceptance case in `tests/catalog.json`. For a behavior change,
write a failing test before the implementation, then include the test result
and the case ID in the pull request. A test-only provider is not the connector.

Reuse `develop` for one backlog item at a time. Keep failed acceptance tests
in an earlier commit and their implementation in the following commit(s).
Submit the finished item through the required checks on a PR to `main`;
retain `develop` for the next item rather than creating per-item branches.

Keep work small: SDK/HTTP compatibility, read-only inventory, staging, then
activation and recovery. Do not add device mutations to the discovery phase.
Keep unimplemented acceptance cases `planned`; do not add empty tests or skip
them to obtain green CI.

Use reserved example names (`router.example.test`) and documentation address
ranges (RFC 5737 / RFC 3849). Generate test keys in memory at test time. Never
copy a live certificate, host key, configuration or transcript into fixtures.

Run the commands in the README. Changes to contract snapshots need an explicit
upstream commit, content hashes, license review and compatibility analysis.
Changes to GitHub Actions must preserve the trust boundaries in
`docs/ci-security.md`; pin third-party actions to complete commit hashes.

First implementation layout (create packages only as they gain code):

```text
cmd/connector/        process wiring and configuration
internal/provider/   ILM v1 HTTP boundary and capability advertisement
internal/inventory/  certificate and Trustpoint discovery
internal/device/     per-operation NETCONF / constrained SSH adapters
internal/lifecycle/  preflight, device CSR and staging
internal/deployment/ switch, verify, persist and recover
internal/journal/    durable operation records and service locks
internal/acme/       order/challenge handling; external CSR only
internal/tlsprobe/   fresh-connection hostname/chain/fingerprint checks
```

Use dependency interfaces for clock, issuer, device, probe and journal. Pass
deadlines through contexts. Store secret references, not credentials, in
operations and fixtures. Keep transport details out of the deployment state
machine.
