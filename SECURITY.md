# Security Policy

## Reporting a vulnerability

Report privately through GitHub, not in a public issue:

**[Open a private security advisory](https://github.com/edgecasehuman/procdrift/security/advisories/new)**
— or use the **Security** tab on the repository, then *Report a vulnerability*.

This project is maintained anonymously and has no contact email. The GitHub
advisory form is the only private channel, and it is monitored.

Useful things to include, in rough order of value: the Windows build number and
architecture, whether ProcDrift was elevated, the exact steps, and what an
attacker gains. A crash on a malformed state file is worth reporting even
without a working exploit.

There is no bounty. Expect an acknowledgement within about a week. If a report
is valid, a fix and an advisory are published together, and you are credited
under whatever name you ask for — including none.

## Supported versions

Only the latest released version is supported. Fixes ship as a new release
rather than as patches to older tags.

## Trust boundary

Being honest about this matters more here than in most projects, because
ProcDrift terminates processes and reports on signatures — both are things a
user may act on.

**What ProcDrift is trusted to do.** It runs as the invoking user
(`asInvoker`; it never silently self-elevates). With the *Restart as
administrator* prompt accepted, it runs elevated and can terminate or suspend
processes belonging to other users. Termination, suspension, and resumption
re-check the target's PID *and* creation time before acting, so a recycled PID
cannot be hit by mistake, and Windows-critical processes are refused outright.

**What ProcDrift reads that it does not control.** Process names and image
paths from the kernel, the `Run`/`RunOnce` registry keys and the service list,
file metadata, and Authenticode signatures. All of this is attacker-influenced
on a compromised machine. Names and paths are treated purely as opaque display
and comparison strings — never executed, never passed to a shell — but a
process is free to name itself something misleading.

**Where the baseline can come from.** Normally the state file under
`%LOCALAPPDATA%\ProcDrift\`, written only when you record a snapshot. There is
one other source: on a first run, with no state file yet, a legacy
`baseline.json` sitting **next to the executable** is read and offered as a
starting snapshot. It has to look like one — a `processes` object with at least
one entry carrying a path — and it does not count as having answered the
first-run prompt, which names the file it found and lets you record your own
instead. Nothing else on disk is consulted, and no directory you merely
launched from is searched.

**What a signature verdict does and does not mean.** `Trusted` means the file on
disk verified against a security catalog or its embedded signature, and that its
certificate chain reached a root this machine trusts, at the moment it was
checked. It does not mean the process in memory still matches that file, and it
does not mean the signed code is benign — a trusted publisher is a statement
about who signed, not about what the code does. Revocation checking is deliberately
**off** and URL retrieval is cache-only so that selecting a row never blocks on
the network — the direct consequence is that a **revoked** certificate can still
report `Trusted`. `Unsigned` and `Invalid` are kept distinct on purpose;
collapsing them hides the only interesting case.

**What ProcDrift does not claim.** It is not an anti-malware product and does
not detect malware. Findings are observations about drift from a snapshot, not
verdicts. A snapshot captured on an already-compromised machine bakes the
compromise into the baseline, and nothing in the tool can notice that.

**Boundaries the design holds.** No network access of any kind. No listening
socket, no telemetry, no update check. No service, driver, or scheduled task.
State is a single JSON file under `%LOCALAPPDATA%\ProcDrift\`, written only on
an explicit user action and replaced atomically; a state file written by a newer
build is refused rather than overwritten. Nothing is written on a timer.

**Out of scope.** An attacker who already has administrator or SYSTEM on the
machine can defeat every guarantee above — tamper with the state file, hide from
the process list, or forge what the kernel reports. Reports that assume that
starting position are not vulnerabilities in ProcDrift.

## Release integrity

Release binaries are **unsigned**. The SHA-256 published in the release notes is
the only integrity check available, and SmartScreen will warn on first run until
a build accumulates reputation. ProcDrift will never ask you to add a Defender
exclusion; if something claiming to be ProcDrift does, it is not this project.
