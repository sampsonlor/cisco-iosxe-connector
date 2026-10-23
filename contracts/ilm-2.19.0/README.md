# Pinned ILM 2.19.0 evidence

The unmodified Java files in `java/` come from
[`OmniTrustILM/interfaces` release 2.19.0](https://github.com/OmniTrustILM/interfaces/tree/e62233777518296f70a151cf766dde5e1a6cea2d).
`sources.json` records upstream paths, Git blob IDs and SHA-256 content hashes.
These are public upstream files, not device or customer data.

`routes.json` is a reviewed, deliberately limited extraction of the Entity
Provider and v1 common routes used by this project. It is **not** an official
OpenAPI document or a complete ILM Core API listing. The attribute controller
for kind attributes is outside the current extraction; its SDK surface is
characterized separately. Do not replace this evidence with current online
API docs without reviewing a version migration.

`../sdk-v1.1.0-observations.json` records known behavior in the pinned SDK.
In particular, three per-entity attribute validation routes return 200 in
the SDK and are annotated 204 in the pinned Java source. The tests preserve
this difference visibly; they do not assert full end-to-end compatibility.

The DTO tests compare serialized SDK fields with fields extracted from these
Java sources and use fixture-only HTTP calls. They do not validate every
attribute subtype, authorization policy, schema constraint or real Core call.

Licensing: MIT, upstream copy in `LICENSE.upstream`; attribution in the
repository `NOTICE`.
