# Compatibility baseline and known differences

| Component | Pin | Meaning |
|---|---|---|
| ILM contract | interfaces 2.19.0, `e62233777518296f70a151cf766dde5e1a6cea2d` | Target contract, not the current website |
| Go SDK | v1.1.0, `1a6c93aae95e32da738c5f830459a9f344ab0394` | Official scaffolding selected for characterization |
| Go | 1.26.10 / 1.27.3 in CI | Supported release lines with current security patches |
| Device | Cisco C8000V, IOS XE 26.1 family | Model reference only; lab capability evidence is pending |

The SDK's generated Entity v1 models declare API version **2.20.0-SNAPSHOT**.
Its module version does not assert compatibility with ILM 2.19.0. No live Core
registration, native renewal or IOS XE write has been tested here.

The initial dependency scan rejected the workstation's Go 1.27.1 standard
library (including GO-2026-6617). CI uses patched versions instead of suppressing
the findings. See [Go release history](https://go.dev/doc/devel/release) and
[GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617). This repository does not
change the workstation's globally installed toolchain.

## K-001: successful per-entity attribute validation

The pinned 2.19.0 controllers use `@ResponseStatus(HttpStatus.NO_CONTENT)` for
location, push and CSR attribute validation. The SDK v1.1.0 handler passes
`http.StatusOK` to those three routes. The source's OpenAPI response annotation
also says 200, so the actual Core tolerance must be tested, not inferred from
one annotation alone.

The harness asserts the observed SDK status **200**, while the reference
route manifest records **204**. A separate test asserts that these exact
differences remain enumerated. This is a characterization test, not a waiver
or a claim that strict 2.19.0 compatibility has passed.

The connector's `internal/provider.NewBoundary` now adapts successful 200
responses on those **three routes only** to 204, removes the response body
and Content-Length, and preserves errors. The kind-level validator remains
200. `TestBoundaryV1Contract` independently expects the target 204;
`TestValidationStatusAdapter` checks error preservation. The upstream SDK
observation tests and manifest remain unchanged. This resolves K-001 for the
offline connector boundary; actual Core acceptance is still pending C-009.

## Other boundaries still to validate

- The boundary supports only single-value **v3 string** request attributes,
  with exact UUID/name pairs and no reference indirection. It rejects v2,
  null/empty/unknown attributes and unknown envelope/content properties before
  SDK decoding. See [boundary policy and tests](provider-boundary.md).
  Other attribute subtypes and actual Core form submission remain unproven.
- SDK generated models still preserve unknown properties. The boundary
  decodes JSON independently, rejects duplicate keys, and applies exact field
  allowlists; SDK strict decoding is retained as an additional check.
- Provider authentication/authorization and real Core lifecycle calls.
- Device CSR extraction, certificate import prompts, chain association,
  Trustpoint switch effects and configuration persistence on the target image.
- AD CS actual template identity, SAN policy, EKU, chain and enrollment rights.

## SSH dependency scan scope

The read-only transports pin `golang.org/x/crypto` v0.58.0 and import `ssh`,
not `openpgp`. The verbose Go scan reports
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) at module level for the
unmaintained OpenPGP package (no fixed version), with zero affected imported
packages or reachable symbols in this project, including tests. The advisory
is recorded rather than suppressed; the existing vulnerability gate is unchanged.

References:

- [2.19.0 LocationController](https://github.com/OmniTrustILM/interfaces/blob/e62233777518296f70a151cf766dde5e1a6cea2d/src/main/java/com/otilm/api/interfaces/connector/entity/LocationController.java)
- [2.19.0 EntityController](https://github.com/OmniTrustILM/interfaces/blob/e62233777518296f70a151cf766dde5e1a6cea2d/src/main/java/com/otilm/api/interfaces/connector/entity/EntityController.java)
- [SDK v1.1.0 routes](https://github.com/OmniTrustILM/go-sdk/blob/v1.1.0/connector/provider/entity/v1/routes.go)
- [SDK generated CSR model](https://github.com/OmniTrustILM/go-sdk/blob/v1.1.0/connector/model/entity/v1/model_generate_csr_response_dto.go)
