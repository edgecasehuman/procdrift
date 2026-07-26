# Contributing

Bug reports and focused pull requests are welcome. Please read the scope section
before opening a feature request — this project says no to more things than it
says yes to, and that is deliberate.

## Reporting a bug

Open an issue with the Windows build number (`winver`), whether ProcDrift was
elevated, what you did, what you expected, and what happened. If a process was
misclassified, the finding shown and the executable path matter more than a
screenshot of the whole window.

**Do not report security vulnerabilities as issues.** See
[SECURITY.md](SECURITY.md) for the private channel.

## Building

Requires rustup and the Visual Studio Build Tools (`build.rs` invokes the
Windows resource compiler). Windows only — there is nothing to build elsewhere.
The compiler is pinned in `rust-toolchain.toml` and installs itself on the first
`cargo` command; do not work around the pin, because Clippy runs with
`-D warnings` and an unpinned toolchain turns a new Rust release into a broken
build on an untouched commit.

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
```

All four must pass; CI runs exactly these, in this order, on `windows-latest`.
A separate job checks the crate against the `rust-version` floor in
`Cargo.toml`, so raising the minimum has to be a deliberate manifest edit rather
than something a merged pull request does by accident.
`--locked` is not optional: `Cargo.lock` is committed, and a build that quietly
resolves different dependency versions is a supply-chain gap. Five tests
deliberately exercise the live machine: catalog verification against the real
`kernel32.dll`, a non-empty startup index, and three that scan the running
process list. All five would pass vacuously if stubbed. Two further tests are
`#[ignore]`d: one spawns and kills a disposable child process, the other is a
manual performance measurement.

## Scope

ProcDrift answers one question: what is running now that was not running when
this machine was known-good? Changes that sharpen that answer are in scope.

Things that are **not** in scope, and why:

- **Network access of any kind** — reputation lookups, telemetry, update checks.
  The guarantee that this binary never talks to anything is worth more than any
  feature that would break it.
- **A service, driver, or scheduled task.** Close the window and nothing of
  ProcDrift is left running. That is a feature.
- **History databases, graphs, or periodic file writes.** State is written only
  on an explicit user action.
- **Verdict language.** Nothing may say "malicious", "threat", or "safe". A
  process monitor cannot know that, and tools that say it anyway are how people
  learn to ignore warnings. Findings are observations.
- **Name-based trust.** Allowances are per exact path, never per process name,
  so a different binary with a familiar name is never silently trusted. A patch
  that relaxes this will be declined.

If you are unsure whether something fits, open an issue before writing code.

## Pull requests

- Keep the diff focused. One behavioural change per PR.
- Add a test that fails without your change, unless the change is genuinely
  untestable (a window layout constant, for example).
- Do not add dependencies. The crate deliberately builds on `serde`,
  `serde_json`, and `windows-sys` alone, plus `winresource` as the only build
  dependency, and every addition is weighed against the fact that this tool runs
  on machines people are worried about.
- Keep the UI thread free. Anything that can touch the disk or block — signature
  verification, catalog resolution — belongs on the details worker thread. The
  refresh timer runs once a second and must stay cheap.
- Match the surrounding comment style. Comments explain *why* a decision was
  made, not what the line does. If a comment would only restate the code, leave
  it out.
- Preserve behaviour on failure paths. A failed kernel query leaves the last
  good table on screen rather than emptying it; a failed registry read skips
  that hive rather than aborting the scan.

## Unsafe code

Most of this crate is FFI against the Win32 and NT APIs, so `unsafe` is
unavoidable. Keep each `unsafe` block as small as the call it wraps, give every
raw handle an owning type with a `Drop` impl (see `OwnedKey` in `autostart.rs`
and `OwnedHandle` in `signature.rs`), and never let a struct cross the FFI
boundary without setting its `cbStruct`/size field.

## Licence

Contributions are accepted under the MIT licence in [LICENSE](LICENSE). There is
no CLA. Copyright is held by "ProcDrift contributors" — do not add individual
copyright lines.
