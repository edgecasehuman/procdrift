# ProcDrift

[![CI](https://github.com/edgecasehuman/procdrift/actions/workflows/ci.yml/badge.svg)](https://github.com/edgecasehuman/procdrift/actions/workflows/ci.yml)
[![Security audit](https://github.com/edgecasehuman/procdrift/actions/workflows/audit.yml/badge.svg)](https://github.com/edgecasehuman/procdrift/actions/workflows/audit.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A single-executable Windows process monitor that answers one question: **what is
running now that was not running when this machine was known-good?**

Task Manager tells you what is running. Autoruns tells you what is configured to
start. Neither tells you what *changed*. ProcDrift records a reference snapshot
of every executable path it can see, then shows each later scan as a difference
against it.

One executable, under half a megabyte: a desktop window, no console, no
installer. No service, no driver, no telemetry, no network access, no background
process. Close it and nothing of it is left running.

## What it shows

Trust and findings are kept separate, because they answer different questions.

**Trust** is where the executable stands relative to your snapshot:

| Trust | Meaning |
|---|---|
| Protected | A Windows-critical process. ProcDrift refuses to act on it, because ending it would stop the machine. |
| Allowed | Its exact path is in your reference snapshot |
| Known | A Windows-shipped program ProcDrift can describe, but not in your snapshot |
| Unclassified | Nothing is known about it beyond what this scan observed |

`Protected` is a statement about what ProcDrift will do, not about whether the
process is benign.

**Findings** are what is true about it right now:

| Finding | Meaning |
|---|---|
| New | Not present in the reference snapshot |
| Different path | This name was seen at a different path |
| Starts automatically | An exact startup entry exists for this executable |
| Parent ended | The launching process is no longer running |
| Restarting | Started at least three times in two minutes |
| Peer outlier | Using more resources than matching instances |
| Many instances | Multiple matching instances are running |
| Known parent | Launched by a process that matches the snapshot |
| Heavy CPU / memory / disk | Currently among the top five |

The combination worth acting on is **New + Starts automatically**: something
absent from your baseline that will still be here after a reboot. ProcDrift
sorts that to the top.

Findings are phrased as observations, not verdicts. Nothing here says
"malicious" or "threat", because a process monitor cannot know that and saying
so anyway is how these tools train people to ignore them.

## Authenticode

Selecting a process verifies its signature offline: security catalogs first
(which is how most Windows system binaries are signed — an embedded-only check
reports a clean machine as mostly "Unsigned"), then the embedded signature. The
result distinguishes **Unsigned** (no signature at all) from **Invalid**
(a signature that is present but does not verify), because collapsing those
loses the only interesting case. Revocation checking is off and URL retrieval is
cache-only, so selecting a row never blocks on the network.

## Install

Download `ProcDrift.exe` from [Releases] and run it. That is the whole install.

[Releases]: https://github.com/edgecasehuman/procdrift/releases

State is written to `%LOCALAPPDATA%\ProcDrift\state.json`, and only after you
answer the first-run prompt, capture a snapshot, or change an allowance. Writes
are atomic. Nothing is written on a timer.

### About SmartScreen

Release binaries are unsigned. Windows SmartScreen will warn on first run until
a given build accumulates reputation. Verify the SHA-256 against the release
notes if you want certainty, or build it yourself from this repository.

ProcDrift never asks you to add a Defender exclusion. A tool that requests one
is asking you to reduce your protection on its say-so.

## Use

1. Run it on a machine you believe is clean and choose **Record all**.
2. Come back later. The **Review** filter shows what does not match.
3. **Allow** marks a specific executable path as expected. Allowances are per
   path, never per name, so a different binary with a familiar name is not
   silently trusted.

Keyboard: `F5` refresh, `Ctrl+F` or `Ctrl+K` search, `Ctrl+C` copy selected
rows, `Enter` details, `Space` toggle suspend, `F2` allow the selected path,
`Delete` end process, `Escape` clear search. Click a column heading to sort.

Process control (suspend, resume, end, end captured tree) acts only on the
selected process and re-checks the process identity, so a recycled PID cannot be
acted on by mistake.

## Design constraints

These are deliberate, not missing features:

- One process, one window, one process enumeration per visible refresh.
- The timer stops while minimized.
- If a kernel query fails, the last good table stays on screen rather than
  emptying.
- The startup index is built once, not per refresh, because it reads several
  hundred registry keys.
- Signature verification runs on a worker thread, never the UI thread.

There is no history database, no graphing, no online lookup, no socket census,
and no periodic file writes.

## Build

Requires rustup and the Visual Studio Build Tools. The compiler version is
pinned in `rust-toolchain.toml` and installs itself on the first `cargo`
command. The crate also builds on Rust 1.88 and later, which CI verifies
separately.

```bash
cargo build --locked --release
```

The binary is `target/release/ProcDrift.exe` and is the complete application.

```bash
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Some tests deliberately exercise the live machine: catalog verification is
checked against the real `kernel32.dll`, and the startup index is asserted to be
non-empty. Both fail loudly rather than silently reporting nothing.

## Security

This tool ends and suspends processes and reports Authenticode results, so its
trust boundary is written down explicitly in [SECURITY.md](SECURITY.md) —
including what a `Trusted` verdict does *not* mean, and the fact that revocation
checking is off by design. Report vulnerabilities privately through the
repository's Security tab, never as a public issue.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the build, the four gates CI enforces,
and the list of things this project deliberately will not do. Participation is
governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

MIT. See [LICENSE](LICENSE).
