# Frozen release vectors

One directory per live **production** release, named by its release
number (`1/`, `2/`, …): a copy of `testdata/vectors/` at the release's tag,
committed in the release's publish step (docs/RELEASING.md) and deleted
when the release is `removed` and dropped from the manifest.

`vms/vectors.TestFrozenReleaseVectors` checks every directory here with
the current code (VAULT-RELEASES §3.4, the move-only contract C1–C2), and
the compatibility matrix (`scripts/compat-matrix.sh`) runs the same check
on each previous release's own vectors. Never edit a frozen directory: if
the current code no longer derives a frozen vector, the change broke a
live release.

Empty until production release 1.
