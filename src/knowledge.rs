//! Plain-language descriptions for processes that appear on every Windows
//! machine.
//!
//! The point is not to be a threat database. It is to stop a reader from
//! spending attention on `csrss.exe` or `Memory Compression` when what they
//! actually want to look at is the one unrecognised binary further down the
//! list. Entries are limited to components shipped by Windows itself, because
//! third-party descriptions go stale and a confidently wrong description is
//! worse than none.

/// Names are matched case-insensitively against the process name.
const ENTRIES: &[(&str, &str)] = &[
    (
        "svchost.exe",
        "Generic host for Windows services that run from DLLs. Dozens of copies are normal; each hosts a different set of services.",
    ),
    (
        "explorer.exe",
        "Provides the desktop, taskbar, and File Explorer windows.",
    ),
    (
        "csrss.exe",
        "Client/Server Runtime Subsystem. Handles console windows and thread bookkeeping. Cannot be ended.",
    ),
    (
        "wininit.exe",
        "Windows start-up application. Runs background initialisation for the session.",
    ),
    (
        "smss.exe",
        "Session Manager Subsystem. Starts user sessions and sets up system environment variables.",
    ),
    (
        "lsass.exe",
        "Local Security Authority Subsystem Service. Enforces security policy and handles logons.",
    ),
    (
        "services.exe",
        "Service Control Manager. Starts, stops, and tracks the machine's Windows services.",
    ),
    (
        "winlogon.exe",
        "Handles interactive logon and logoff, the secure attention sequence, and screen locking.",
    ),
    (
        "conhost.exe",
        "Console Window Host. Draws the window for Command Prompt and other console programs.",
    ),
    (
        "spoolsv.exe",
        "Print Spooler. Queues printing and faxing jobs.",
    ),
    (
        "dwm.exe",
        "Desktop Window Manager. Composites the on-screen image using the GPU.",
    ),
    (
        "taskhostw.exe",
        "Host for Windows scheduled tasks that run as DLLs rather than their own executable.",
    ),
    (
        "sihost.exe",
        "Shell Infrastructure Host. Runs the Start menu, action centre, and parts of the taskbar.",
    ),
    (
        "runtimebroker.exe",
        "Checks that Store apps stay within the permissions they declared.",
    ),
    (
        "searchindexer.exe",
        "Windows Search Indexer. Builds the index behind Start-menu and File Explorer search.",
    ),
    (
        "fontdrvhost.exe",
        "Isolated font driver host. Parses font files away from the kernel.",
    ),
    (
        "registry",
        "Kernel process holding the Windows registry in memory. Has no executable on disk.",
    ),
    (
        "memory compression",
        "Kernel process that compresses memory pages instead of paging them to disk. Its memory use is expected to be large.",
    ),
    (
        "system",
        "The kernel itself and its worker threads. Has no executable on disk.",
    ),
    (
        "system idle process",
        "Not a real program. Its CPU share is the percentage of time the processor is doing nothing.",
    ),
];

/// Description for a process name, if this is a component Windows ships.
pub fn describe(name: &str) -> Option<&'static str> {
    let name = name.trim();
    ENTRIES
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, description)| *description)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_case_insensitive_and_covers_pseudo_processes() {
        assert!(describe("SVCHOST.EXE").is_some());
        assert!(describe("svchost.exe").is_some());
        assert!(describe("Memory Compression").is_some());
        assert!(describe("System Idle Process").is_some());
    }

    #[test]
    fn unknown_processes_get_no_invented_description() {
        assert_eq!(describe("totally-made-up.exe"), None);
        assert_eq!(describe(""), None);
    }

    #[test]
    fn entries_are_unique_and_stored_for_case_insensitive_lookup() {
        let mut names: Vec<String> = ENTRIES
            .iter()
            .map(|(name, _)| name.to_ascii_lowercase())
            .collect();
        names.sort();
        let before = names.len();
        names.dedup();
        assert_eq!(
            before,
            names.len(),
            "duplicate entry in the knowledge table"
        );
    }
}
