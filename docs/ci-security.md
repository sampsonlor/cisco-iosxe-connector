# CI trust boundaries

## Enabled now

`ci.yml` handles `pull_request`, push to main and manual dispatch. All jobs run
on GitHub-hosted Ubuntu 24.04 with `contents: read`. Checkout does not persist
credentials. Actions use reviewed full commit hashes. Tool modules and Go
versions use exact releases. Dependency checks retain Go's checksum verification.

No job receives environment secrets, uses an internal runner, publishes a
package or calls a device. Uploaded reports are synthetic test results, have
seven-day retention and are not consumed by privileged downstream workflows.
Only explicit report files are uploaded; never upload a workspace or home
directory. Caches are disabled for the initial milestone.

Workflow and Go dependency updates arrive through Dependabot PRs and undergo
the same checks. Source/plan validation is an additional regression guard;
maintainer review is still needed when those guards themselves change.

## Not enabled yet

- Device/ILM/AD CS/DNS secrets or real environment fixtures.
- Self-hosted runners, public-to-private lab dispatch, or automatic deployment.
- `pull_request_target`, privileged `workflow_run` artifact consumers, or PR
  comment commands that execute contributor code.
- Container/release publishing permissions, OIDC tokens or deployment jobs.

Keep future lab automation in a private management project with ephemeral,
network-restricted runners. Only reviewed exact commits and verified build
digests may cross into it. Configure and verify separate approval policies for
staging and activation; a named GitHub environment is not proof of protection.
Never promote an untrusted PR artifact to a trusted release or lab run.

## Repository settings

Main should reject force pushes/deletion and require all P0 check contexts
before merging. A single-maintainer repository can require PR review of the
diff without requiring an unavailable second person's approval. Workflow files
remain subject to the same protected-branch checks. Branch protections govern
future changes; the initial seed necessarily precedes the first check result.

Private vulnerability reporting should be enabled. No production secret is
needed for this repository. Deployment environments and lab runners should
remain absent until their workflows and protection policies are reviewable.

References:

- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [GitHub protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
