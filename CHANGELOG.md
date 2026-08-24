# Changelog

All notable changes to ProcDrift are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release workflow reads the section matching the tag it is building and
publishes it as the release notes, appending the SHA-256 of the binary it just
produced. A tag whose version has no section here fails the release rather than
publishing an empty page, so this file is edited in the same commit that bumps
`Cargo.toml`.

## [Unreleased]

### Added

- `--version` and `--help`. Both are answered in a dialog, because a
  windows-subsystem binary is never attached to the console that started it and
  anything printed would go nowhere. Previously every argument except the
  internal `--replace-instance` produced an error dialog, so asking a program
  its version was indistinguishable from a mistake.
- The window title now carries the version, so a screenshot identifies the
  build as precisely as the command line does.
- Release binaries carry a build provenance attestation, verifiable with
  `gh attestation verify ProcDrift.exe --repo edgecasehuman/procdrift`. The
  published SHA-256 says a file has not changed since it was hashed; the
  attestation says which workflow, commit, and repository produced it.

### Changed

- The bug report template asks for the line `--version` reports instead of
  naming a release that goes stale at every tag.
- The README documents installing from crates.io, and what differs about a
  binary you compiled yourself: no mark-of-the-web, so no SmartScreen notice,
  but it embeds your own build paths and should not be redistributed.

### Security

- CodeQL analysis, and a release environment that requires an approval before a
  tag can publish.
- Repository secret and personal-data safeguards tightened.

## [1.0.1] - 2026-08-03

### Fixed

- A `baseline.json` placed anywhere in the working directory or its parents was
  adopted as the reference snapshot, `{}` was accepted as a valid one, and
  onboarding was then marked complete, so the machine's idea of normal could be
  set by a planted file without anyone being told. The snapshot is now read only
  from the executable's own directory, the file must actually look like a
  baseline, and the first-run prompt names what it read.

## [1.0.0] - 2026-07-26

### Added

- Initial public release. A single Windows executable that records a reference
  snapshot of every executable path it can see, then shows each later scan as a
  difference against it: Trust states describing where a process stands relative
  to the snapshot, and Findings describing what is true about it now.
- Offline Authenticode verification, catalog signatures first, distinguishing an
  absent signature from one that fails to verify.
- Process control that re-checks process identity before acting, so a recycled
  PID cannot be acted on by mistake.
- Findings phrased as observations rather than verdicts, enforced by a test.

[Unreleased]: https://github.com/edgecasehuman/procdrift/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/edgecasehuman/procdrift/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/edgecasehuman/procdrift/releases/tag/v1.0.0
