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

Before shipping a provider, either adapt these specific routes to the target
contract or establish and document actual ILM 2.19.0 acceptance. Prefer a small
boundary adapter or an upstream SDK fix over forking generated DTOs. A future
strict connector test must expect the decided target behavior and must not
reuse the SDK-observation values as its expected results.

## Other boundaries still to validate

- Required/null/empty attributes and every attribute subtype used by this
  connector; the initial round-trip test uses v3 string content, which is
  declared by the pinned 2.19.0 RequestAttribute source. Legacy v2 content
  decoding remains unproven and must not be advertised as compatible.
- SDK generated models may preserve unknown JSON properties. HTTP strict
  decoding alone must not be treated as application-level allowlisting.
- Provider authentication/authorization and real Core lifecycle calls.
- Device CSR extraction, certificate import prompts, chain association,
  Trustpoint switch effects and configuration persistence on the target image.
- AD CS actual template identity, SAN policy, EKU, chain and enrollment rights.

References:

- [2.19.0 LocationController](https://github.com/OmniTrustILM/interfaces/blob/e62233777518296f70a151cf766dde5e1a6cea2d/src/main/java/com/otilm/api/interfaces/connector/entity/LocationController.java)
- [2.19.0 EntityController](https://github.com/OmniTrustILM/interfaces/blob/e62233777518296f70a151cf766dde5e1a6cea2d/src/main/java/com/otilm/api/interfaces/connector/entity/EntityController.java)
- [SDK v1.1.0 routes](https://github.com/OmniTrustILM/go-sdk/blob/v1.1.0/connector/provider/entity/v1/routes.go)
- [SDK generated CSR model](https://github.com/OmniTrustILM/go-sdk/blob/v1.1.0/connector/model/entity/v1/model_generate_csr_response_dto.go)
