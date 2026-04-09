# Supply-chain pin rationale

The bake-off pins every third-party scanner and GitHub Action to a specific
version (and where possible, a commit SHA) for two reasons:

1. **Reproducibility.** A bake-off only makes sense if every run scans the
   same code with the same scanner version. Floating tags break that.
2. **Risk containment.** Two of the five scanners in this comparison
   (Trivy and KICS) had their official GitHub Actions reportedly compromised
   in March 2026. Until we independently verify those advisories against
   upstream sources, we run those tools via container/binary rather than via
   their marketplace actions, and we pin to last-known-safe versions.

## ⚠️ Verify before merging

The pins below were chosen based on initial research and **must be
re-validated against the upstream advisories** before this project is used
to make a procurement decision. Owner: whoever cuts the first release tag.

| Tool | Pin | Verification source |
|---|---|---|
| Checkov | `bridgecrewio/checkov-action@v12` (replace with SHA) | https://github.com/bridgecrewio/checkov-action/releases |
| KICS | `checkmarx/kics:v2.1.4` container, digest TBD | Aqua/Checkmarx advisory + https://hub.docker.com/r/checkmarx/kics/tags |
| Trivy | binary `v0.69.3` from official release tarball | https://github.com/aquasecurity/trivy/security/advisories + Aqua security blog |
| Snyk | `snyk-linux` from `static.snyk.io/cli/latest` (pin to a versioned URL after verification) | https://github.com/snyk/cli/releases |
| Semgrep | `semgrep/semgrep:1.96.0` container (replace with digest) | https://github.com/semgrep/semgrep/releases |

The KICS workflow currently has `sha256:REPLACE_ME_WITH_VERIFIED_DIGEST` as
the digest pin. **The first task during implementation is to fetch the real
digest from Docker Hub for the verified-safe tag and substitute it in.**

## Pinning strategy

- **Marketplace actions** (`actions/checkout`, `actions/setup-python`,
  `actions/upload-artifact`): pinned to commit SHAs of v4/v5 releases.
- **Scanner binaries** (Trivy, Snyk): downloaded from versioned URLs at
  scanner-vendor domains, never via the marketplace action that was
  reportedly compromised.
- **Scanner containers** (KICS, Semgrep): pinned to `image:tag@sha256:digest`
  once digests are verified.

## Reporting drift

If a scanner ships a new release that materially changes findings (new rules,
severity remapping, or schema bumps), the diff should be evaluated **outside**
the bake-off harness first, then the pins updated in a single commit so the
historical comparison data remains coherent.
