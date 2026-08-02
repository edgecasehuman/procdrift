//! The reference snapshot: what was running when the user recorded it, plus the
//! paths they have since allowed by hand.
//!
//! A match here is a statement about the baseline, never about the process.

use crate::process::ProcessRow;
use crate::state;
use crate::win32::{GetSystemTime, SystemTime};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(Clone)]
pub(crate) struct Baseline {
    pub(crate) records: HashMap<String, Vec<String>>,
    pub(crate) allowed_paths: HashSet<String>,
    pub(crate) path: PathBuf,
    pub(crate) onboarding_complete: bool,
    /// Set when an existing state file could not be read. While this is set the
    /// in-memory baseline is empty but the file on disk is not, so saving would
    /// destroy a reference snapshot the user still has. `save` refuses instead.
    pub(crate) load_error: Option<String>,
    /// Set when this baseline came from a `baseline.json` found on disk rather
    /// than from the user's own state file. The first-run prompt says so,
    /// because a snapshot nobody in this session recorded should not pass for
    /// one that somebody did.
    pub(crate) imported_from: Option<PathBuf>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum BaselineMatch {
    Allowed,
    Path,
    LegacyName,
    PathUnknown,
    PathMismatch,
    None,
}

impl Baseline {
    pub(crate) fn load() -> Self {
        let path = state::state_path();
        let load_error = match state::State::load(&path) {
            Ok(saved) => return Self::from_state(saved, path),
            // Distinguish "no baseline yet", which is the normal first run, from
            // "there is a baseline and it could not be read", which must not be
            // silently replaced by an empty one.
            Err(_) if !path.exists() => None,
            Err(error) => Some(error),
        };
        if load_error.is_none() {
            for candidate in baseline_candidates() {
                if let Ok(imported) = state::State::import_v1(&candidate) {
                    // Deliberately not persisted here: state is written only on an
                    // explicit user action. The import is cheap and repeats until
                    // the user does something that saves.
                    let mut baseline = Self::from_state(imported, path);
                    baseline.imported_from = Some(candidate);
                    return baseline;
                }
            }
        }
        Self {
            records: HashMap::new(),
            allowed_paths: HashSet::new(),
            path,
            onboarding_complete: false,
            load_error,
            imported_from: None,
        }
    }

    pub(crate) fn from_state(saved: state::State, path: PathBuf) -> Self {
        let records = saved
            .snapshot
            .map(|snapshot| {
                snapshot
                    .executables
                    .into_iter()
                    .map(|(name, paths)| (name, paths.into_iter().collect()))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            records,
            allowed_paths: saved.allowed_paths.into_iter().collect(),
            path,
            onboarding_complete: saved.onboarding_complete,
            load_error: None,
            imported_from: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn classify_match(&self, name: &str, path: &str) -> BaselineMatch {
        let normalized_name = name.to_lowercase();
        let normalized_path = normalize_path(path);
        self.classify_normalized(&normalized_name, &normalized_path)
    }

    pub(crate) fn classify_normalized(
        &self,
        normalized_name: &str,
        normalized_path: &str,
    ) -> BaselineMatch {
        if !normalized_path.is_empty() && self.allowed_paths.contains(normalized_path) {
            return BaselineMatch::Allowed;
        }
        let Some(paths) = self.records.get(normalized_name) else {
            return BaselineMatch::None;
        };
        if paths.is_empty() {
            return BaselineMatch::LegacyName;
        }
        if normalized_path.is_empty() {
            return BaselineMatch::PathUnknown;
        }
        if paths.iter().any(|candidate| candidate == normalized_path) {
            BaselineMatch::Path
        } else {
            BaselineMatch::PathMismatch
        }
    }

    pub(crate) fn replacement_from_rows(&self, rows: &[ProcessRow]) -> Self {
        let mut records: HashMap<String, Vec<String>> = HashMap::new();
        for row in rows.iter().filter(|row| !row.path.is_empty()) {
            let path = normalize_path(&row.path);
            if path.is_empty() {
                continue;
            }
            let paths = records.entry(row.name.to_lowercase()).or_default();
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        Self {
            records,
            allowed_paths: self.allowed_paths.clone(),
            path: self.path.clone(),
            onboarding_complete: true,
            load_error: self.load_error.clone(),
            imported_from: self.imported_from.clone(),
        }
    }

    pub(crate) fn add(&mut self, path: &str) -> bool {
        let path = normalize_path(path);
        !path.is_empty() && self.allowed_paths.insert(path)
    }

    pub(crate) fn remove(&mut self, path: &str) -> bool {
        self.allowed_paths.remove(&normalize_path(path))
    }

    pub(crate) fn save(&self) -> Result<(), String> {
        if let Some(error) = &self.load_error {
            return Err(format!(
                "{error} Nothing was written. Move or delete that file if you want to start a new baseline."
            ));
        }
        let mut snapshot = state::Snapshot {
            recorded_at: utc_now(),
            ..state::Snapshot::default()
        };
        snapshot.executables = self
            .records
            .iter()
            .map(|(name, paths)| (name.clone(), paths.iter().cloned().collect()))
            .collect();
        state::State {
            version: 2,
            snapshot: Some(snapshot),
            allowed_paths: self.allowed_paths.iter().cloned().collect(),
            onboarding_complete: self.onboarding_complete,
        }
        .save_atomic(&self.path)
    }
}

pub(crate) fn utc_now() -> String {
    let mut value = SystemTime::default();
    unsafe { GetSystemTime(&mut value) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.year, value.month, value.day, value.hour, value.minute, value.second
    )
}

/// Where a legacy `baseline.json` is looked for: beside the executable, and
/// nowhere else.
///
/// This used to include the working directory and that directory's parent.
/// The working directory is wherever the user happened to launch from -- a
/// Downloads folder, a share, a USB stick -- and writing one file into it
/// needs no privilege at all. Since the file it finds becomes the reference
/// snapshot for what counts as normal on the machine, that put the answer
/// inside the question: plant a baseline naming your own process and it reads
/// as `Known`; plant a near-empty one and everything reads as new, which is
/// noise the user learns to scroll past. Neither needs the administrator or
/// SYSTEM access that SECURITY.md scopes out.
///
/// Beside the executable is the portable-deployment case and the one a user
/// chose when they put the file there.
pub(crate) fn baseline_candidates() -> Vec<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("baseline.json")))
        .into_iter()
        .collect()
}

pub(crate) fn normalize_path(path: &str) -> String {
    state::normalize_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_requires_a_matching_path_for_trust() {
        let baseline = Baseline {
            records: HashMap::from([
                (
                    "trusted.exe".to_string(),
                    vec![normalize_path(r"C:\Program Files\Trusted\trusted.exe")],
                ),
                ("legacy.exe".to_string(), Vec::new()),
            ]),
            allowed_paths: HashSet::new(),
            path: PathBuf::from("baseline.json"),
            onboarding_complete: true,
            load_error: None,
            imported_from: None,
        };
        assert!(
            baseline.classify_match("TRUSTED.EXE", r"c:/program files/trusted/TRUSTED.exe")
                == BaselineMatch::Path
        );
        assert!(
            baseline.classify_match("trusted.exe", r"C:\Temp\trusted.exe")
                == BaselineMatch::PathMismatch
        );
        assert!(baseline.classify_match("trusted.exe", "") == BaselineMatch::PathUnknown);
        assert!(
            baseline.classify_match("legacy.exe", r"C:\legacy.exe") == BaselineMatch::LegacyName
        );
    }

    #[test]
    fn baseline_mutations_are_path_scoped_and_atomically_persisted() {
        let path = std::env::temp_dir().join(format!(
            "procdrift-baseline-test-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut baseline = Baseline {
            records: HashMap::new(),
            allowed_paths: HashSet::new(),
            path: path.clone(),
            onboarding_complete: true,
            load_error: None,
            imported_from: None,
        };
        assert!(baseline.add(r"C:\One\Example.exe"));
        assert!(baseline.add(r"D:\Two\Example.exe"));
        assert!(!baseline.add(r"d:/two/example.exe"));
        baseline.save().expect("persist added paths");

        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read saved baseline"))
                .expect("parse saved baseline");
        assert_eq!(saved["version"], 2);
        assert_eq!(
            saved["allowed_paths"]
                .as_array()
                .expect("saved paths")
                .len(),
            2
        );
        assert!(
            saved["snapshot"]["recorded_at"]
                .as_str()
                .is_some_and(|value| value.ends_with('Z'))
        );

        assert!(baseline.remove(r"C:\One\Example.exe"));
        assert_eq!(baseline.allowed_paths.len(), 1);
        assert!(baseline.remove(r"D:\Two\Example.exe"));
        assert!(baseline.allowed_paths.is_empty());
        baseline.save().expect("persist removed paths");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_unreadable_state_file_is_never_overwritten() {
        let path = std::env::temp_dir().join(format!(
            "procdrift-unreadable-test-{}.json",
            std::process::id()
        ));
        // Stand in for a state file written by a newer build: State::load
        // refuses it, so the app starts with an empty in-memory baseline while
        // the user's real reference snapshot is still on disk.
        let original = br#"{"version":99,"snapshot":null,"allowed_paths":[]}"#;
        std::fs::write(&path, original).expect("write newer state file");
        let mut baseline = Baseline {
            records: HashMap::new(),
            allowed_paths: HashSet::new(),
            path: path.clone(),
            onboarding_complete: false,
            load_error: Some("state file was written by a newer version.".to_owned()),
            imported_from: None,
        };
        baseline.add(r"C:\One\Example.exe");
        let error = baseline
            .save()
            .expect_err("saving over an unreadable state file must be refused");
        assert!(
            error.contains("Nothing was written"),
            "the refusal must tell the user their baseline survived: {error}"
        );
        assert_eq!(
            std::fs::read(&path).expect("read state file"),
            original,
            "the existing state file must be byte-for-byte untouched"
        );
        let _ = std::fs::remove_file(path);
    }

    // Restricting this to the executable's directory is the whole of the fix
    // for a planted baseline, so it is worth a test rather than a comment.
    #[test]
    fn a_baseline_is_only_ever_looked_for_beside_the_executable() {
        let candidates = baseline_candidates();
        let exe_directory = std::env::current_exe()
            .expect("current_exe")
            .parent()
            .expect("executable has a parent directory")
            .to_path_buf();

        assert_eq!(candidates, vec![exe_directory.join("baseline.json")]);

        let cwd = std::env::current_dir().expect("current_dir");
        for forbidden in [Some(cwd.as_path()), cwd.parent(), exe_directory.parent()] {
            let Some(directory) = forbidden else { continue };
            if directory == exe_directory {
                continue;
            }
            assert!(
                !candidates.contains(&directory.join("baseline.json")),
                "{} is attacker-writable without privilege and must not be searched",
                directory.display()
            );
        }
    }
}
