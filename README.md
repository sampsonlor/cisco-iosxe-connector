# Cisco IOS XE Connector for OmniTrust ILM

[![CI](https://github.com/sampsonlor/cisco-iosxe-connector/actions/workflows/ci.yml/badge.svg)](https://github.com/sampsonlor/cisco-iosxe-connector/actions/workflows/ci.yml)

An independent, community connector for certificate discovery and renewal on
Cisco IOS XE. Initial target: the HTTPS service on Cisco C8000V, with OmniTrust
ILM **2.19.0**, Microsoft AD CS and device-generated, non-exportable keys.

**Status: read-only Provider, SQLite metadata, NETCONF/SSH reads, certificate inventory and offline tests. There is no deployable
connector or device-writing implementation yet.** A passing CI run validates
only the implemented checks, not IOS XE renewal or SDK compatibility
with every ILM 2.19.0 feature. This project is not affiliated with Cisco or
OmniTrust.

## Design and delivery order

1. [CI/CD and acceptance design (中文)](docs/test-strategy.zh-CN.md), the
   [test catalog](tests/catalog.json) and pinned upstream contract evidence.
2. Read-only discovery and capability assessment, with synthetic fixtures.
3. Device-generated CSR, issuance and certificate import to a staging
   Trustpoint. Leave the active HTTPS binding in place.
4. Controlled activation, independent TLS verification and recovery.
5. Renewal scheduling and release packaging after the preceding gates pass.

See the [architecture and sequence diagrams](docs/architecture.md),
[compatibility assessment](docs/compatibility.md),
[CI trust boundaries](docs/ci-security.md) and
[implementation milestones](docs/roadmap.md).

The implementation includes [the v1 HTTP boundary](docs/provider-boundary.md)
and [read-only Provider](docs/readonly-provider.md) in `internal/provider`.
The [read-only transports](docs/readonly-transports.md) in `internal/device`
collect raw evidence; [certificate inventory](docs/certificate-inventory.md) in
`internal/inventory` validates it and supplies the Provider's `InventoryReader`.
Development reuses the `develop` branch, completing
one backlog item at a time; `main` retains its required PR checks.

A [manual Windows read-only lab tool](docs/local-readonly-lab.md) is available
under `cmd/iosxe-lab`. It uses a local password dialog and private evidence
outside Git checkouts. Private CLI-only acceptance is recorded under
`L001-20261023-run04`; an approved account may have write privileges while the
tool performs only fixed reads. NTP is deferred to the next live test. NETCONF
models and ILM Core integration still require their own live evidence.

The [operation journal and shared import gate](docs/durable-journal.md) implement
durable service ownership, request/operation correlation and commit-before-dispatch
with SQLite WAL. Counting-importer tests cover concurrency, storage failure and
crash recovery of intent. Actual CSR/issuance/import adapters and activation are
still future milestones; the read-only HTTP Provider does not enable writes.

## Local checks

Python 3.12+ and Go 1.27.3 are the reference tools. The SDK's earlier supported
Go line is also checked in CI. Dependencies and GitHub Actions are pinned.

```sh
python -m unittest discover -s tests/repository -v
go mod download
go mod verify
go vet ./...
go test -race -count=1 ./...
```

The Go tests exercise the official SDK, connector boundary and read-only
Provider through in-process HTTP, real temporary SQLite files and synthetic
inventory readers. They never connect to a router, CA, DNS service or ILM
instance. They do not implement certificate issuance or device configuration.
Planned acceptance cases remain explicitly `planned` in the catalog; they
are not represented by skipped or empty passing tests.

## CI/CD boundaries

Public pull requests run on GitHub-hosted runners with read-only permissions,
without device secrets or internal network access. There is no lab workflow,
self-hosted runner registration, image publishing or production deployment
enabled in this milestone. Lab and release gates are specified before those
pipelines are implemented.

All checked-in examples are synthetic. Keep real addresses, credentials,
certificate fingerprints, device transcripts and signed lab evidence outside
this public repository. Report security issues through
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. The pinned ILM contract excerpts retain their upstream licensing
and attribution; see [NOTICE](NOTICE) and
[contracts/ilm-2.19.0](contracts/ilm-2.19.0/README.md).
