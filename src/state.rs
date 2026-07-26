use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

/// Highest state-file version this build can read. Older files load and are
/// upgraded in memory; newer ones are refused rather than silently replaced.
pub const CURRENT_VERSION: u32 = 2;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Snapshot {
    pub recorded_at: String,
    pub executables: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub version: u32,
    pub snapshot: Option<Snapshot>,
    pub allowed_paths: BTreeSet<String>,
    #[serde(default)]
    pub onboarding_complete: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: CURRENT_VERSION,
            snapshot: None,
            allowed_paths: BTreeSet::new(),
            onboarding_complete: false,
        }
    }
}

impl State {
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        let state: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("could not parse {}: {error}", path.display()))?;
        // Only refuse state written by a *newer* build. An exact-equality check
        // here rejects every future version, and because the caller treats a
        // load failure as "no baseline", the next snapshot silently overwrites
        // the user's reference with an empty one.
        if state.version > CURRENT_VERSION {
            return Err(format!(
                "state file was written by a newer version of ProcDrift (state version {}, this build understands {}). \
                 Refusing to load it so the existing baseline is not overwritten.",
                state.version, CURRENT_VERSION
            ));
        }
        Ok(state.normalized())
    }

    pub fn import_v1(path: &Path) -> Result<Self, String> {
        let root: serde_json::Value = serde_json::from_slice(
            &std::fs::read(path)
                .map_err(|error| format!("could not read legacy baseline: {error}"))?,
        )
        .map_err(|error| format!("could not parse legacy baseline: {error}"))?;
        let mut snapshot = Snapshot {
            recorded_at: root
                .get("recorded_at")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            ..Snapshot::default()
        };
        if let Some(processes) = root.get("processes").and_then(serde_json::Value::as_object) {
            for (name, record) in processes {
                let paths = record
                    .get("paths")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .map(normalize_path)
                    .filter(|path| !path.is_empty())
                    .collect();
                snapshot.executables.insert(name.to_lowercase(), paths);
            }
        }
        Ok(Self {
            version: CURRENT_VERSION,
            snapshot: Some(snapshot),
            allowed_paths: BTreeSet::new(),
            onboarding_complete: true,
        })
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| "state path has no parent".to_owned())?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("could not create state directory: {error}"))?;
        let temp = path.with_extension(format!("json.{}.tmp", std::process::id()));
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|error| format!("encode state: {error}"))?;
        bytes.push(b'\n');
        let result = (|| {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temp)
                .map_err(|error| format!("open temporary state: {error}"))?;
            file.write_all(&bytes)
                .map_err(|error| format!("write temporary state: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("flush temporary state: {error}"))?;
            drop(file);
            let from = wide(&temp);
            let to = wide(path);
            if unsafe {
                MoveFileExW(
                    from.as_ptr(),
                    to.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(format!(
                    "replace state atomically: Windows error {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temp);
        }
        result
    }

    fn normalized(mut self) -> Self {
        self.allowed_paths = self
            .allowed_paths
            .into_iter()
            .map(|path| normalize_path(&path))
            .filter(|path| !path.is_empty())
            .collect();
        self.snapshot = self.snapshot.map(Snapshot::normalized);
        self
    }
}

impl Snapshot {
    fn normalized(mut self) -> Self {
        self.executables = self
            .executables
            .into_iter()
            .map(|(name, paths)| {
                (
                    name.to_lowercase(),
                    paths
                        .into_iter()
                        .map(|path| normalize_path(&path))
                        .filter(|path| !path.is_empty())
                        .collect(),
                )
            })
            .collect();
        self
    }
}

pub fn state_path() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map_or_else(std::env::temp_dir, PathBuf::from)
        .join("ProcDrift")
        .join("state.json")
}

pub fn normalize_path(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

pub fn command_executable(command: &str) -> Option<String> {
    let expanded = expand_environment(command);
    let command = expanded.trim_start();
    if command.is_empty() {
        return None;
    }
    let executable = if let Some(rest) = command.strip_prefix('"') {
        let end = rest.find('"')?;
        &rest[..end]
    } else {
        command
            .split_once(char::is_whitespace)
            .map_or(command, |(first, _)| first)
    };
    Some(normalize_path(executable))
}

pub fn expand_environment(value: &str) -> String {
    expand_environment_with(value, |name| std::env::var(name).ok())
}

fn expand_environment_with(value: &str, mut lookup: impl FnMut(&str) -> Option<String>) -> String {
    let mut result = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        result.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            result.push('%');
            result.push_str(after);
            return result;
        };
        let name = &after[..end];
        if let Some(replacement) = lookup(name) {
            result.push_str(&replacement);
        } else {
            result.push('%');
            result.push_str(name);
            result.push('%');
        }
        rest = &after[end + 1..];
    }
    result.push_str(rest);
    result
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_import_is_known_snapshot_never_allowed() {
        let path = std::env::temp_dir().join(format!("procdrift-v1-{}.json", std::process::id()));
        std::fs::write(
            &path,
            br#"{"version":1,"recorded_at":"then","processes":{"A.EXE":{"paths":["C:/A.exe"]}}}"#,
        )
        .unwrap();
        let state = State::import_v1(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(state.version, 2);
        assert!(state.allowed_paths.is_empty());
        assert!(state.snapshot.unwrap().executables["a.exe"].contains(r"c:\a.exe"));
    }

    #[test]
    fn only_newer_state_versions_are_refused() {
        let directory = std::env::temp_dir().join(format!("procdrift-ver-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();

        let older = directory.join("older.json");
        std::fs::write(
            &older,
            br#"{"version":1,"snapshot":null,"allowed_paths":[]}"#,
        )
        .unwrap();
        assert!(
            State::load(&older).is_ok(),
            "a state file from an older build must still load; refusing it makes the \
             next snapshot overwrite the user's baseline with an empty one"
        );

        let newer = directory.join("newer.json");
        std::fs::write(
            &newer,
            br#"{"version":99,"snapshot":null,"allowed_paths":[]}"#,
        )
        .unwrap();
        assert!(State::load(&newer).is_err());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn persistence_command_matching_is_quoted_and_exact() {
        // A quoted path containing spaces resolves to the executable itself,
        // compared case-insensitively.
        assert_eq!(
            command_executable(r#""C:\Program Files\App\app.exe" --quiet"#),
            Some(normalize_path(r"c:\program files\app\APP.exe"))
        );
        // A longer name that merely starts with the expected one must not match.
        assert_ne!(
            command_executable(r#""C:\Program Files\App\app-helper.exe" --quiet"#),
            Some(normalize_path(r"C:\Program Files\App\app.exe"))
        );
        // The executable is the launcher, not a path handed to it as an argument.
        assert_ne!(
            command_executable(r#"rundll32.exe "C:\Program Files\App\app.exe""#),
            Some(normalize_path(r"C:\Program Files\App\app.exe"))
        );
    }

    #[test]
    fn persistence_environment_expansion_preserves_unknown_variables() {
        assert_eq!(
            expand_environment_with(r"%ROOT%\App\app.exe --quiet", |name| {
                (name.eq_ignore_ascii_case("root")).then(|| r"C:\Root".to_owned())
            }),
            r"C:\Root\App\app.exe --quiet"
        );
        assert_eq!(
            expand_environment_with(r"%UNKNOWN%\app.exe", |_| None),
            r"%UNKNOWN%\app.exe"
        );
    }
}
