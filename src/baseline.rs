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
                    return Self::from_state(imported, path);
                }
            }
        }
        Self {
            records: HashMap::new(),
            allowed_paths: HashSet::new(),
            path,
            onboarding_complete: false,
            load_error,
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

pub(crate) fn baseline_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(4);
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        paths.push(dir.join("baseline.json"));
        if let Some(parent) = dir.parent() {
            paths.push(parent.join("baseline.json"));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("baseline.json");
        if !paths.contains(&candidate) {
            paths.push(candidate);
        }
        if let Some(parent) = cwd.parent() {
            let candidate = parent.join("baseline.json");
            if !paths.contains(&candidate) {
                paths.push(candidate);
            }
        }
    }
    paths
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
}
