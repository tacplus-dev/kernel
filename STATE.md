# State: kernel

Overwritten to stay current (loopers and agents). Last updated: 2026-11-15 by the looper (#60).

- **Version / line:** 0.1 line, v0.1.2 (v0.1.1 plus codegen's maven-plugin-api 3.9.16, which takes plexus-utils 3.6.1 off GHSA-6fmv-xxpf-w3cw, #60); v0.1.1 (v0.1.0 plus the security-check fixes of #48, #61 and #62) and v0.1.0 tagged on main by hand (Jody, 2026-11-07 and 2026-11-15); released by `.github/workflows/release.yml` (#7): a tag `vX.Y.Z` runs the gates on the tag in the build image its tacplus.lock pins, publishes `ghcr.io/tacplus-dev/kernel:X.Y.Z` and the line tag `X.Y` (arm64; amd64 behind `PLATFORMS`) and creates the GitHub release; v0.1.0 and v0.1.1, tagged before the workflow, are published by its manual run (`publish: true`). README.md, Releasing. tacplus floor 2.6, tacplus 2.6.1 and its build image pinned in tacplus.lock (#46)
- **Works:** <what is in and working>; the build's security checks pass: gitleaks with `.gitleaks.toml` (default rules, two false-positive shapes allowlisted, #48), the shaded-Jackson CVEs and the generated USO_UNSAFE_OBJECT_SYNCHRONIZATION accepted by `security-exceptions.yaml` until 2026-12-14 (#59, tacplus#712)
- **Released / deployed:** <where each version runs>
- **Known gaps:** <...>
- **Blocked on:** <issues>
