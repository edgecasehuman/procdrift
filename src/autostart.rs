//! Index of executables configured to start on their own.
//!
//! "This process is running" and "this process would come back after a reboot"
//! are different facts, and the second is the one that decides whether an
//! unexpected binary is worth acting on. The index is built once and reused,
//! because enumerating the service list touches several hundred registry keys
//! and must never run on the UI thread's refresh timer.
//!
//! Matching is by exact executable path, reusing the same normalization the
//! baseline uses. A startup entry whose command line merely *mentions* a path —
//! `rundll32.exe "C:\...\app.dll"` — does not count as that path starting
//! automatically.
//!
//! Coverage is deliberately narrow: the `Run` and `RunOnce` keys under both
//! `HKEY_LOCAL_MACHINE` and `HKEY_CURRENT_USER`, in both registry views, plus
//! services whose `Start` value is automatic. Startup folders, scheduled tasks,
//! and the rest of the persistence surface are not read, so the absence of an
//! entry here is not evidence that a binary does not start on its own.

use std::collections::BTreeSet;

use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    REG_SAM_FLAGS, RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW,
};

use crate::state::{command_executable, expand_environment, normalize_path};

/// `Start` value meaning "automatic" for a service.
const SERVICE_AUTO_START: u32 = 2;

const RUN_KEYS: &[(HKEY, &str)] = &[
    (
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    (
        HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
];

const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";

#[derive(Clone, Debug, Default)]
pub struct AutostartIndex {
    executables: BTreeSet<String>,
}

impl AutostartIndex {
    /// Read every startup location once. Individual failures are skipped rather
    /// than aborting the scan: a machine where one hive is unreadable should
    /// still get findings from the rest.
    pub fn build() -> Self {
        let mut executables = BTreeSet::new();

        // Both registry views are read explicitly. A 32-bit application's Run
        // entry lives under HKLM\SOFTWARE\WOW6432Node and is invisible to a
        // 64-bit-only read. HKEY_CURRENT_USER\SOFTWARE is not redirected, so
        // there the two views resolve to the same key and the second read is a
        // harmless duplicate rather than a second source of entries.
        for (root, path) in RUN_KEYS {
            for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
                collect_run_values(*root, path, view, &mut executables);
            }
        }

        collect_services(&mut executables);

        Self { executables }
    }

    /// True when `path` is the exact executable of some startup entry.
    pub fn contains(&self, path: &str) -> bool {
        let normalized = normalize_path(path);
        !normalized.is_empty() && self.executables.contains(&normalized)
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

/// Owns an open registry key so every early return closes it.
struct OwnedKey(HKEY);

impl Drop for OwnedKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { RegCloseKey(self.0) };
        }
    }
}

fn open(root: HKEY, path: &str, view: REG_SAM_FLAGS) -> Option<OwnedKey> {
    let mut key: HKEY = std::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(root, wide(path).as_ptr(), 0, KEY_READ | view, &mut key) };
    (status == ERROR_SUCCESS && !key.is_null()).then_some(OwnedKey(key))
}

/// Decode a registry string value, expanding `%VARIABLES%` in `REG_EXPAND_SZ`.
fn decode_string(buffer: &[u8], byte_length: usize) -> Option<String> {
    let usable = byte_length.min(buffer.len()) / 2;
    if usable == 0 {
        return None;
    }
    let units: Vec<u16> = buffer[..usable * 2]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect();
    if units.is_empty() {
        return None;
    }
    Some(expand_environment(&String::from_utf16_lossy(&units)))
}

fn collect_run_values(root: HKEY, path: &str, view: REG_SAM_FLAGS, out: &mut BTreeSet<String>) {
    let Some(key) = open(root, path, view) else {
        return;
    };
    let mut index = 0u32;
    loop {
        let mut name = [0u16; 16 * 1024];
        let mut name_length = name.len() as u32;
        let mut kind = 0u32;
        let mut data = vec![0u8; 32 * 1024];
        let mut data_length = data.len() as u32;
        let status = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut name_length,
                std::ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut data_length,
            )
        };
        if status != ERROR_SUCCESS {
            // ERROR_MORE_DATA means this one value was too large for the
            // buffer; skip it and keep enumerating the rest.
            if status == ERROR_MORE_DATA {
                index += 1;
                continue;
            }
            break;
        }
        if let Some(command) = decode_string(&data, data_length as usize)
            && let Some(executable) = command_executable(&command)
        {
            out.insert(executable);
        }
        index += 1;
    }
}

/// Collect the image path of every service set to start automatically.
///
/// `HKLM\SYSTEM` is outside the WOW64 redirection scope, so the 64-bit view is
/// the only view and a second pass would enumerate the same keys.
fn collect_services(out: &mut BTreeSet<String>) {
    let Some(services) = open(HKEY_LOCAL_MACHINE, SERVICES_KEY, KEY_WOW64_64KEY) else {
        return;
    };
    let mut index = 0u32;
    loop {
        let mut name = [0u16; 512];
        let mut name_length = name.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                services.0,
                index,
                name.as_mut_ptr(),
                &mut name_length,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            break;
        }
        index += 1;

        let service = String::from_utf16_lossy(&name[..name_length as usize]);
        let Some(key) = open(
            HKEY_LOCAL_MACHINE,
            &format!("{SERVICES_KEY}\\{service}"),
            KEY_WOW64_64KEY,
        ) else {
            continue;
        };

        // Only automatic services are a persistence signal. Manual and disabled
        // ones do not bring a process back on their own.
        if read_dword(&key, "Start") != Some(SERVICE_AUTO_START) {
            continue;
        }
        if let Some(image) = read_string(&key, "ImagePath")
            && let Some(executable) = service_executable(&image)
        {
            out.insert(executable);
        }
    }
}

fn read_dword(key: &OwnedKey, value: &str) -> Option<u32> {
    let mut data = [0u8; 4];
    let mut length = data.len() as u32;
    let mut kind = 0u32;
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            wide(value).as_ptr(),
            std::ptr::null(),
            &mut kind,
            data.as_mut_ptr(),
            &mut length,
        )
    };
    (status == ERROR_SUCCESS && length == 4).then(|| u32::from_le_bytes(data))
}

fn read_string(key: &OwnedKey, value: &str) -> Option<String> {
    let mut data = vec![0u8; 32 * 1024];
    let mut length = data.len() as u32;
    let mut kind = 0u32;
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            wide(value).as_ptr(),
            std::ptr::null(),
            &mut kind,
            data.as_mut_ptr(),
            &mut length,
        )
    };
    (status == ERROR_SUCCESS)
        .then(|| decode_string(&data, length as usize))
        .flatten()
}

/// Extensions a service image can have. Drivers are `.sys`; a handful of
/// service hosts are `.dll` loaded by a shared host.
const IMAGE_EXTENSIONS: [&str; 3] = [".exe", ".sys", ".dll"];

/// Cut an unquoted service image path at the end of its executable name,
/// tolerating embedded spaces. Falls back to whole-string parsing when no known
/// extension is present.
fn unquoted_service_executable(value: &str) -> Option<String> {
    let lowered = value.to_ascii_lowercase();
    let cut = IMAGE_EXTENSIONS
        .iter()
        .filter_map(|extension| lowered.find(extension).map(|at| at + extension.len()))
        .min();
    match cut {
        // Only treat it as the executable if what follows is a boundary; a hit
        // inside a longer directory name is not the end of the path.
        Some(end) if value[end..].chars().next().is_none_or(char::is_whitespace) => {
            Some(normalize_path(&value[..end]))
        }
        _ => command_executable(value),
    }
}

/// Resolve a service `ImagePath` to an absolute executable path.
///
/// Service image paths use forms the ordinary command parser does not handle:
/// an `\??\` NT prefix, and paths relative to the Windows directory.
pub fn service_executable(image: &str) -> Option<String> {
    let trimmed = image.trim();
    let without_prefix = trimmed
        .strip_prefix(r"\??\")
        .or_else(|| trimmed.strip_prefix(r"\\?\"))
        .unwrap_or(trimmed);
    let executable = if without_prefix.starts_with('"') {
        command_executable(without_prefix)?
    } else {
        // Unquoted service image paths routinely contain spaces
        // (`C:\Program Files\App\svc.exe -k netsvcs`), so splitting on the
        // first space would truncate them. Cut after the image extension
        // instead, which is how these values are actually shaped.
        unquoted_service_executable(without_prefix)?
    };
    if executable.is_empty() {
        return None;
    }
    // An absolute path has a drive letter; anything else is relative to the
    // Windows directory, which is how driver entries are usually written.
    if executable.chars().nth(1) == Some(':') || executable.starts_with(r"\\") {
        return Some(executable);
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    Some(normalize_path(&format!(
        "{}\\{}",
        root.trim_end_matches('\\'),
        executable.trim_start_matches('\\')
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_image_paths_resolve_nt_prefixes_and_relative_drivers() {
        assert_eq!(
            service_executable(r"\??\C:\Program Files\App\svc.exe"),
            Some(r"c:\program files\app\svc.exe".to_owned())
        );
        assert_eq!(
            service_executable(r#""C:\Program Files\App\svc.exe" -k netsvcs"#),
            Some(r"c:\program files\app\svc.exe".to_owned())
        );
        let relative = service_executable(r"system32\drivers\http.sys").unwrap();
        assert!(
            relative.ends_with(r"\system32\drivers\http.sys"),
            "relative driver paths must be anchored to the Windows directory, got {relative}"
        );
        assert!(relative.starts_with("c:\\") || relative.contains(":\\"));
    }

    #[test]
    fn matching_is_by_exact_executable_not_substring() {
        let index = AutostartIndex {
            executables: BTreeSet::from([r"c:\program files\app\app.exe".to_owned()]),
        };
        assert!(index.contains(r"C:\Program Files\App\APP.exe"));
        assert!(!index.contains(r"C:\Program Files\App\app-helper.exe"));
        assert!(!index.contains(""));
    }

    #[test]
    fn the_real_machine_has_automatic_startup_entries() {
        // Every Windows install runs automatic services. An empty index means
        // the enumeration silently failed and the finding would never fire.
        let index = AutostartIndex::build();
        assert!(
            !index.executables.is_empty(),
            "expected at least one autostart executable on a live Windows host"
        );
    }
}
