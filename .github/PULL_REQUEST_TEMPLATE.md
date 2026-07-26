<!--
Suspected vulnerabilities do not belong in a pull request. Use the private
advisory form; see SECURITY.md.
-->

## What this changes

<!-- The user-visible behaviour, in a sentence or two. -->

## Scope

<!--
CONTRIBUTING.md lists what this project declines: network access of any kind, a
service or driver, history databases and periodic writes, verdict language
("malicious", "threat", "safe"), and name-based trust. If this change touches
any of them, make the case here rather than leaving it to review.
-->

- [ ] Adds no network access, background persistence, or periodic file write
- [ ] Adds no dependency
- [ ] Keeps blocking work off the UI thread
- [ ] Phrases anything user-visible as an observation, not a verdict

## Checks

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`
- [ ] `cargo test --locked`
- [ ] A test fails without this change, or the change is genuinely untestable

## Unsafe code

<!--
Delete if this PR adds none. Otherwise: each block as small as the call it
wraps, every raw handle in an owning type with a Drop impl, and every struct
crossing the FFI boundary with its cbStruct/size field set.
-->

None added.
