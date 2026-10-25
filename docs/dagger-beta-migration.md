# Dagger beta version policy

The candidate standard is **v1.0.0-beta.21**, pinned exactly in `dagger.json`
and the repository bootstrap. Do not use a floating `latest` or `head` release
for CI. New betas require verified archive and binary checksums, matching local
and hosted runners, passing project gates, and a coordinated reviewed promotion.
The initial six-project promotion is held until all six validation gates pass.

Run `./scripts/run-dagger-ci.sh` for the repository-pinned local gate.
It uses the reviewed beta engine without depending on the global PATH CLI.

`dagger.json` remains supported by the beta. Migrating to workspace/module TOML
configuration is separate from this version upgrade. String-returning check
functions remain available to callers; decorated checks must return Void.

Before a coordinated switch, drain local Dagger sessions and update every
installed shared host guard with the same version. Dagger's image driver may
remove old engine containers on startup; do not assume two versions can run
side by side. Preserve rollback binaries/images and never prune shared caches
as part of a version bump.

ARM64 Cloud Engines and bring-your-own-compute are still marked Coming soon
on Dagger's October 22, 2026 changelog. This change neither connects a Cloud
account nor authorizes publication, deployment, remote engine use or host
installation. Use the existing separate approvals for those operations.
