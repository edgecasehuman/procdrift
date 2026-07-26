#![windows_subsystem = "windows"]

mod activity;
mod autostart;
mod details;
mod knowledge;
mod model;
mod signature;
mod state;

use activity::{ActivityTracker, ProcessKey as ActivityKey};
use autostart::AutostartIndex;
use model::{EvidenceRow, Findings, TrustState};
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, c_void};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, FILETIME, GetLastError, HANDLE, HINSTANCE, HWND, LPARAM,
    LRESULT, RECT, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, DEFAULT_GUI_FONT, DeleteObject, FW_NORMAL, GetStockObject, HFONT, UpdateWindow,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::Controls::{
    InitCommonControls, LVCF_FMT, LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT, LVCFMT_RIGHT, LVCOLUMNW,
    LVIF_TEXT, LVITEMW, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_EX_GRIDLINES, LVS_REPORT,
    LVS_SHOWSELALWAYS, WC_LISTVIEWW,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetFocus, GetKeyState, SetFocus};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreatePopupMenu,
    CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW, EN_CHANGE,
    ES_AUTOHSCROLL, GWLP_USERDATA, GetClientRect, GetCursorPos, GetMessageW, GetWindowLongPtrW,
    GetWindowTextLengthW, GetWindowTextW, HMENU, IDC_ARROW, IsIconic, KillTimer, LoadCursorW,
    MB_ICONERROR, MB_ICONWARNING, MB_OK, MB_YESNO, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG,
    MessageBoxW, MoveWindow, PostMessageW, PostQuitMessage, RegisterClassW, SIZE_MINIMIZED,
    SW_SHOW, SW_SHOWNORMAL, SendMessageW, SetTimer, SetWindowLongPtrW, SetWindowTextW, ShowWindow,
    TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WM_APP, WM_CLOSE, WM_COMMAND,
    WM_CREATE, WM_DESTROY, WM_KEYDOWN, WM_NCDESTROY, WM_NOTIFY, WM_SETFONT, WM_SIZE, WM_TIMER,
    WNDCLASSW, WS_BORDER, WS_CHILD, WS_CLIPCHILDREN, WS_EX_CLIENTEDGE, WS_OVERLAPPEDWINDOW,
    WS_TABSTOP, WS_VISIBLE,
};

const ID_SEARCH: usize = 101;
const ID_LIST: usize = 102;
const ID_REFRESH: usize = 103;
const ID_END: usize = 104;
const ID_SUSPEND: usize = 105;
const ID_RESUME: usize = 106;
const ID_DETAILS: usize = 107;
const ID_RECORD_BASELINE: usize = 108;
const ID_ADD_BASELINE: usize = 109;
const ID_REMOVE_BASELINE: usize = 110;
const ID_FILTER_REVIEW: usize = 120;
const ID_FILTER_NEW: usize = 121;
const ID_FILTER_HEAVY: usize = 122;
const ID_FILTER_RESTARTING: usize = 123;
const ID_FILTER_KNOWN: usize = 124;
const ID_FILTER_ALL: usize = 125;
const ID_MENU_DETAILS: usize = 201;
const ID_MENU_COPY: usize = 202;
const ID_MENU_OPEN_LOCATION: usize = 203;
const ID_MENU_END_TREE: usize = 204;
const ID_MENU_END: usize = 205;
const ID_MENU_SUSPEND: usize = 206;
const ID_MENU_RESUME: usize = 207;
const ID_MENU_TRUST: usize = 208;
const ID_MENU_UNTRUST: usize = 209;
const ID_MENU_ACTIVITY: usize = 210;
const TIMER_SCAN: usize = 1;
const WM_REFRESH: u32 = WM_APP + 1;
const WM_DETAILS_READY: u32 = WM_APP + 2;

const LVM_FIRST: u32 = 0x1000;
const LVM_SETEXTENDEDLISTVIEWSTYLE: u32 = LVM_FIRST + 54;
const LVM_INSERTCOLUMNW: u32 = LVM_FIRST + 97;
const LVM_INSERTITEMW: u32 = LVM_FIRST + 77;
const LVM_SETITEMTEXTW: u32 = LVM_FIRST + 116;
const LVM_DELETEALLITEMS: u32 = LVM_FIRST + 9;
const LVM_GETNEXTITEM: u32 = LVM_FIRST + 12;
const LVM_GETTOPINDEX: u32 = LVM_FIRST + 39;
const LVM_GETCOUNTPERPAGE: u32 = LVM_FIRST + 40;
const LVM_SETITEMSTATE: u32 = LVM_FIRST + 43;
const LVNI_SELECTED: isize = 0x0002;
const LVIS_FOCUSED: u32 = 0x0001;
const LVIS_SELECTED: u32 = 0x0002;
const LVN_FIRST: i32 = -100;
const LVN_COLUMNCLICK: i32 = LVN_FIRST - 8;
const LVN_ITEMACTIVATE: i32 = LVN_FIRST - 14;
const NM_RCLICK: i32 = -5;
const BN_CLICKED: usize = 0;
const CF_UNICODETEXT: u32 = 13;
const GMEM_MOVEABLE: u32 = 0x0002;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const VK_CONTROL_KEY: i32 = 0x11;
const VK_ESCAPE_KEY: usize = 0x1B;
const VK_ENTER_KEY: usize = 0x0D;
const VK_SPACE_KEY: usize = 0x20;
const VK_DELETE_KEY: usize = 0x2E;
const VK_F2_KEY: usize = 0x71;
const VK_F5_KEY: usize = 0x74;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        class: u32,
        buffer: *mut c_void,
        length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn NtSuspendProcess(process: HANDLE) -> i32;
    fn NtResumeProcess(process: HANDLE) -> i32;
}

#[repr(C)]
#[derive(Default)]
struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemTime(system_time: *mut SystemTime);
    fn IsProcessCritical(process: HANDLE, critical: *mut i32) -> i32;
    fn GlobalAlloc(flags: u32, bytes: usize) -> HANDLE;
    fn GlobalFree(memory: HANDLE) -> HANDLE;
    fn GlobalLock(memory: HANDLE) -> *mut c_void;
    fn GlobalUnlock(memory: HANDLE) -> i32;
}

#[link(name = "user32")]
unsafe extern "system" {
    fn CloseClipboard() -> i32;
    fn EmptyClipboard() -> i32;
    fn OpenClipboard(owner: HWND) -> i32;
    fn SetClipboardData(format: u32, memory: HANDLE) -> HANDLE;
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProcKey {
    pid: u32,
    created: u64,
}

#[derive(Clone, Copy, Default)]
struct Counters {
    cpu_100ns: u64,
    io_bytes: u64,
}

#[derive(Clone)]
struct Identity {
    name: Rc<str>,
    normalized_name: Rc<str>,
    path: Rc<str>,
    normalized_path: Rc<str>,
    accessible: bool,
}

#[derive(Clone)]
struct RawProcess {
    key: ProcKey,
    ppid: u32,
    session_id: u32,
    thread_count: u32,
    handle_count: u32,
    identity: Rc<Identity>,
    memory_bytes: u64,
    private_bytes: u64,
    counters: Counters,
}

#[derive(Clone, Eq, PartialEq)]
struct ProcessRow {
    key: ProcKey,
    ppid: u32,
    session_id: u32,
    thread_count: u32,
    handle_count: u32,
    trust: TrustState,
    findings: Findings,
    name: Rc<str>,
    cpu_tenths: u32,
    memory_bytes: u64,
    private_bytes: u64,
    io_per_second: u64,
    path: Rc<str>,
    paused_by_procdrift: bool,
}

#[derive(Clone)]
struct Baseline {
    records: HashMap<String, Vec<String>>,
    allowed_paths: HashSet<String>,
    path: PathBuf,
    onboarding_complete: bool,
    /// Set when an existing state file could not be read. While this is set the
    /// in-memory baseline is empty but the file on disk is not, so saving would
    /// destroy a reference snapshot the user still has. `save` refuses instead.
    load_error: Option<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum BaselineMatch {
    Allowed,
    Path,
    LegacyName,
    PathUnknown,
    PathMismatch,
    None,
}

impl Baseline {
    fn load() -> Self {
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

    fn from_state(saved: state::State, path: PathBuf) -> Self {
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
    fn classify_match(&self, name: &str, path: &str) -> BaselineMatch {
        let normalized_name = name.to_lowercase();
        let normalized_path = normalize_path(path);
        self.classify_normalized(&normalized_name, &normalized_path)
    }

    fn classify_normalized(&self, normalized_name: &str, normalized_path: &str) -> BaselineMatch {
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

    fn replacement_from_rows(&self, rows: &[ProcessRow]) -> Self {
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

    fn add(&mut self, path: &str) -> bool {
        let path = normalize_path(path);
        !path.is_empty() && self.allowed_paths.insert(path)
    }

    fn remove(&mut self, path: &str) -> bool {
        self.allowed_paths.remove(&normalize_path(path))
    }

    fn save(&self) -> Result<(), String> {
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

fn utc_now() -> String {
    let mut value = SystemTime::default();
    unsafe { GetSystemTime(&mut value) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.year, value.month, value.day, value.hour, value.minute, value.second
    )
}

fn baseline_candidates() -> Vec<PathBuf> {
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

fn normalize_path(path: &str) -> String {
    state::normalize_path(path)
}

struct Scanner {
    previous: HashMap<ProcKey, Counters>,
    counter_scratch: HashMap<ProcKey, Counters>,
    identities: HashMap<ProcKey, Rc<Identity>>,
    all_pids: HashSet<u32>,
    baseline_pids: HashSet<u32>,
    baseline_matches: Vec<BaselineMatch>,
    query_buffer: Vec<u8>,
    last_scan: Option<Instant>,
    logical_processors: u32,
    baseline: Baseline,
    /// Built once. Rebuilding it costs several hundred registry reads, which
    /// must not happen on the one-second refresh timer.
    autostart: AutostartIndex,
    activity: ActivityTracker,
    started: Instant,
    paused: HashSet<ProcKey>,
}

impl Scanner {
    fn new() -> Self {
        let mut info: SYSTEM_INFO = unsafe { zeroed() };
        unsafe { GetSystemInfo(&mut info) };
        Self {
            previous: HashMap::new(),
            counter_scratch: HashMap::new(),
            identities: HashMap::new(),
            all_pids: HashSet::new(),
            baseline_pids: HashSet::new(),
            baseline_matches: Vec::new(),
            query_buffer: vec![0; 512 * 1024],
            last_scan: None,
            logical_processors: info.dwNumberOfProcessors.max(1),
            baseline: Baseline::load(),
            autostart: AutostartIndex::build(),
            activity: ActivityTracker::default(),
            started: Instant::now(),
            paused: HashSet::new(),
        }
    }

    fn scan(&mut self) -> Result<Vec<ProcessRow>, String> {
        let now = Instant::now();
        let raw = enumerate_processes(&mut self.query_buffer, &mut self.identities)?;
        let elapsed = self
            .last_scan
            .map_or(Duration::ZERO, |last| now.saturating_duration_since(last));
        self.last_scan = Some(now);

        self.all_pids.clear();
        self.all_pids
            .extend(raw.iter().map(|process| process.key.pid));
        self.baseline_matches.clear();
        self.baseline_matches.extend(raw.iter().map(|process| {
            self.baseline.classify_normalized(
                &process.identity.normalized_name,
                &process.identity.normalized_path,
            )
        }));
        self.baseline_pids.clear();
        self.baseline_pids.extend(
            raw.iter()
                .zip(&self.baseline_matches)
                .filter(|(process, baseline_match)| {
                    process.identity.accessible && **baseline_match == BaselineMatch::Path
                })
                .map(|(process, _)| process.key.pid),
        );

        let mut next = std::mem::take(&mut self.counter_scratch);
        next.clear();
        next.reserve(raw.len().saturating_sub(next.capacity()));
        let elapsed_secs = elapsed.as_secs_f64();
        let mut rows: Vec<ProcessRow> = raw
            .into_iter()
            .zip(self.baseline_matches.iter().copied())
            .map(|(process, baseline_match)| {
                let previous = self.previous.get(&process.key).copied().unwrap_or_default();
                let cpu_tenths = if elapsed_secs > 0.0 {
                    let delta = process
                        .counters
                        .cpu_100ns
                        .saturating_sub(previous.cpu_100ns);
                    ((delta as f64 * 1000.0)
                        / (elapsed_secs * 10_000_000.0 * f64::from(self.logical_processors)))
                    .round()
                    .clamp(0.0, 1000.0) as u32
                } else {
                    0
                };
                let io_per_second = if elapsed_secs > 0.0 {
                    let delta = process.counters.io_bytes.saturating_sub(previous.io_bytes);
                    (delta as f64 / elapsed_secs) as u64
                } else {
                    0
                };
                next.insert(process.key, process.counters);

                let (trust, findings) = classify_evidence(
                    process.identity.accessible,
                    !self.baseline.records.is_empty(),
                    baseline_match,
                    process.ppid,
                    &self.all_pids,
                    &self.baseline_pids,
                );

                ProcessRow {
                    key: process.key,
                    ppid: process.ppid,
                    session_id: process.session_id,
                    thread_count: process.thread_count,
                    handle_count: process.handle_count,
                    trust,
                    findings,
                    name: Rc::clone(&process.identity.name),
                    cpu_tenths,
                    memory_bytes: process.memory_bytes,
                    private_bytes: process.private_bytes,
                    io_per_second,
                    path: Rc::clone(&process.identity.path),
                    paused_by_procdrift: self.paused.contains(&process.key),
                }
            })
            .collect();
        self.paused
            .retain(|key| rows.iter().any(|row| row.key == *key));
        let now_seconds = self.started.elapsed().as_secs();
        self.activity.update(
            now_seconds,
            rows.iter().map(|row| {
                (
                    ActivityKey {
                        pid: row.key.pid,
                        created: row.key.created,
                    },
                    row.path.as_ref(),
                )
            }),
        );
        apply_live_findings(&mut rows, &self.activity, &self.autostart, now_seconds);
        self.identities.retain(|key, _| next.contains_key(key));
        std::mem::swap(&mut self.previous, &mut next);
        self.counter_scratch = next;
        Ok(rows)
    }
}

fn classify_evidence(
    accessible: bool,
    baseline_recorded: bool,
    baseline_match: BaselineMatch,
    ppid: u32,
    all_pids: &HashSet<u32>,
    baseline_pids: &HashSet<u32>,
) -> (TrustState, Findings) {
    let mut findings = Findings::default();
    if !accessible {
        return (TrustState::Protected, findings);
    }
    let trust = if baseline_match == BaselineMatch::Allowed {
        TrustState::Allowed
    } else if baseline_match == BaselineMatch::Path {
        TrustState::Known
    } else {
        TrustState::Unclassified
    };
    if baseline_recorded && baseline_match == BaselineMatch::None {
        findings.insert(Findings::NEW);
    }
    if baseline_match == BaselineMatch::PathMismatch {
        findings.insert(Findings::DIFFERENT_PATH);
    }
    if ppid != 0 && !all_pids.contains(&ppid) {
        findings.insert(Findings::PARENT_ENDED);
    }
    if ppid != 0 && baseline_pids.contains(&ppid) {
        findings.insert(Findings::LAUNCHED_BY_KNOWN);
    }
    (trust, findings)
}

fn apply_live_findings(
    rows: &mut [ProcessRow],
    activity: &ActivityTracker,
    autostart: &AutostartIndex,
    now_seconds: u64,
) {
    let mut evidence: Vec<_> = rows
        .iter()
        .map(|row| EvidenceRow {
            trust: row.trust,
            findings: row.findings,
            cpu_tenths: row.cpu_tenths,
            memory_bytes: row.memory_bytes,
            disk_bytes_per_second: row.io_per_second,
        })
        .collect();
    model::apply_resource_findings(&mut evidence);
    let mut peers: HashMap<Rc<str>, Vec<(usize, u32, u64)>> = HashMap::new();
    for (index, row) in rows
        .iter()
        .enumerate()
        .filter(|(_, row)| !row.path.is_empty())
    {
        peers.entry(Rc::clone(&row.path)).or_default().push((
            index,
            row.cpu_tenths,
            row.memory_bytes,
        ));
    }
    let outliers = model::peer_outliers(&peers);
    for (index, row) in rows.iter_mut().enumerate() {
        row.findings = evidence[index].findings;
        if peers.get(&row.path).is_some_and(|values| values.len() >= 2) {
            row.findings.insert(Findings::MANY_INSTANCES);
        }
        if outliers.contains(&index) {
            row.findings.insert(Findings::PEER_OUTLIER);
        }
        if activity.is_restarting(&row.path, now_seconds) {
            row.findings.insert(Findings::RESTARTING);
        }
        if autostart.contains(&row.path) {
            row.findings.insert(Findings::STARTS_AUTOMATICALLY);
        }
    }
}

fn primary_finding(row: &ProcessRow) -> &'static str {
    for (flag, label) in [
        (Findings::RESTARTING, "Restarting"),
        (Findings::DIFFERENT_PATH, "Different path"),
        (Findings::PARENT_ENDED, "Parent ended"),
        (Findings::PEER_OUTLIER, "Peer outlier"),
        (Findings::HEAVY_CPU, "Heavy CPU"),
        (Findings::HEAVY_MEMORY, "Heavy memory"),
        (Findings::HEAVY_DISK, "Heavy disk"),
        (Findings::NEW, "New"),
        (Findings::STARTS_AUTOMATICALLY, "Starts automatically"),
        (Findings::MANY_INSTANCES, "Many instances"),
        (Findings::LAUNCHED_BY_KNOWN, "Known parent"),
    ] {
        if row.findings.contains(flag) {
            return label;
        }
    }
    "None"
}

fn legacy_category(row: &ProcessRow) -> &'static str {
    if row.paused_by_procdrift {
        "Paused by ProcDrift"
    } else if row.trust == TrustState::Protected {
        "Protected"
    } else if !row.findings.is_empty() {
        primary_finding(row)
    } else {
        row.trust.label()
    }
}

fn filetime_value(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn query_process_path(handle: HANDLE) -> String {
    let mut path_buffer = [0_u16; 1024];
    let mut path_len = path_buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, path_buffer.as_mut_ptr(), &mut path_len) }
        != 0
    {
        String::from_utf16_lossy(&path_buffer[..path_len as usize])
    } else {
        String::new()
    }
}

fn query_identity(pid: u32, name: Rc<str>) -> Rc<Identity> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Rc::new(Identity {
            normalized_name: name.to_lowercase().into(),
            name,
            path: Rc::from(""),
            normalized_path: Rc::from(""),
            accessible: false,
        });
    }
    let path = query_process_path(handle);
    unsafe { CloseHandle(handle) };
    Rc::new(Identity {
        normalized_name: name.to_lowercase().into(),
        name,
        normalized_path: normalize_path(&path).into(),
        path: path.into(),
        accessible: true,
    })
}

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Clone, Copy)]
struct UnicodeString {
    Length: u16,
    MaximumLength: u16,
    Buffer: *const u16,
}

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Clone, Copy)]
struct SystemProcessInformation {
    NextEntryOffset: u32,
    NumberOfThreads: u32,
    WorkingSetPrivateSize: i64,
    HardFaultCount: u32,
    NumberOfThreadsHighWatermark: u32,
    CycleTime: u64,
    CreateTime: i64,
    UserTime: i64,
    KernelTime: i64,
    ImageName: UnicodeString,
    BasePriority: i32,
    UniqueProcessId: usize,
    InheritedFromUniqueProcessId: usize,
    HandleCount: u32,
    SessionId: u32,
    UniqueProcessKey: usize,
    PeakVirtualSize: usize,
    VirtualSize: usize,
    PageFaultCount: u32,
    PeakWorkingSetSize: usize,
    WorkingSetSize: usize,
    QuotaPeakPagedPoolUsage: usize,
    QuotaPagedPoolUsage: usize,
    QuotaPeakNonPagedPoolUsage: usize,
    QuotaNonPagedPoolUsage: usize,
    PagefileUsage: usize,
    PeakPagefileUsage: usize,
    PrivatePageCount: usize,
    ReadOperationCount: i64,
    WriteOperationCount: i64,
    OtherOperationCount: i64,
    ReadTransferCount: i64,
    WriteTransferCount: i64,
    OtherTransferCount: i64,
}

fn enumerate_processes(
    buffer: &mut Vec<u8>,
    identities: &mut HashMap<ProcKey, Rc<Identity>>,
) -> Result<Vec<RawProcess>, String> {
    const SYSTEM_PROCESS_INFORMATION: u32 = 5;
    const STATUS_SUCCESS: u32 = 0;
    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
    const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
    const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

    let mut returned = 0_u32;
    let mut successful = false;
    let mut last_status = STATUS_SUCCESS;
    for _ in 0..5 {
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut returned,
            )
        } as u32;
        last_status = status;
        if status == STATUS_SUCCESS {
            successful = true;
            break;
        }
        if !matches!(
            status,
            STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_OVERFLOW | STATUS_BUFFER_TOO_SMALL
        ) {
            return Err(format!(
                "kernel process query failed (NTSTATUS 0x{status:08X})"
            ));
        }
        let needed = (returned as usize).saturating_add(64 * 1024);
        buffer.resize((buffer.len() * 2).max(needed), 0);
    }
    if !successful {
        return Err(format!(
            "kernel process query remained too large after five attempts (NTSTATUS 0x{last_status:08X})"
        ));
    }

    let used = if returned == 0 {
        buffer.len()
    } else {
        (returned as usize).min(buffer.len())
    };
    let mut processes = Vec::with_capacity(320);
    let mut offset = 0_usize;
    loop {
        if offset.saturating_add(size_of::<SystemProcessInformation>()) > used {
            break;
        }
        let process = unsafe {
            std::ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .add(offset)
                    .cast::<SystemProcessInformation>(),
            )
        };
        let pid = process.UniqueProcessId as u32;
        if pid != 0 {
            let key = ProcKey {
                pid,
                created: process.CreateTime.max(0) as u64,
            };
            let identity = if let Some(identity) = identities.get(&key) {
                Rc::clone(identity)
            } else {
                let name: Rc<str> =
                    if process.ImageName.Length > 0 && !process.ImageName.Buffer.is_null() {
                        let length = process.ImageName.Length as usize / 2;
                        let value =
                            unsafe { std::slice::from_raw_parts(process.ImageName.Buffer, length) };
                        String::from_utf16_lossy(value).into()
                    } else if pid == 4 {
                        Rc::from("System")
                    } else {
                        format!("<pid:{pid}>").into()
                    };
                let identity = query_identity(pid, name);
                identities.insert(key, Rc::clone(&identity));
                identity
            };
            let io_bytes = process
                .ReadTransferCount
                .max(0)
                .saturating_add(process.WriteTransferCount.max(0))
                .saturating_add(process.OtherTransferCount.max(0))
                as u64;
            let cpu_100ns = process
                .KernelTime
                .max(0)
                .saturating_add(process.UserTime.max(0)) as u64;
            processes.push(RawProcess {
                key,
                ppid: process.InheritedFromUniqueProcessId as u32,
                session_id: process.SessionId,
                thread_count: process.NumberOfThreads,
                handle_count: process.HandleCount,
                identity,
                memory_bytes: process.WorkingSetSize as u64,
                private_bytes: process.PrivatePageCount as u64,
                counters: Counters {
                    cpu_100ns,
                    io_bytes,
                },
            });
        }
        if process.NextEntryOffset == 0 {
            break;
        }
        offset = offset.saturating_add(process.NextEntryOffset as usize);
    }
    if processes.is_empty() {
        Err("kernel process query returned no usable records".to_string())
    } else {
        Ok(processes)
    }
}

#[repr(C)]
struct Nmlistview {
    hdr: windows_sys::Win32::UI::Controls::NMHDR,
    item: i32,
    sub_item: i32,
    new_state: u32,
    old_state: u32,
    changed: u32,
    point: windows_sys::Win32::Foundation::POINT,
    lparam: LPARAM,
}

struct AppState {
    hwnd: HWND,
    search: HWND,
    list: HWND,
    status: HWND,
    refresh: HWND,
    end: HWND,
    suspend: HWND,
    resume: HWND,
    details: HWND,
    record_baseline: HWND,
    add_baseline: HWND,
    remove_baseline: HWND,
    filters: [HWND; 6],
    font: HFONT,
    scanner: Scanner,
    rows: Vec<ProcessRow>,
    displayed: Vec<ProcessRow>,
    rendered: Vec<ProcessRow>,
    position_scratch: HashMap<ProcKey, usize>,
    sort_column: usize,
    sort_descending: bool,
    search_text: String,
    timer_active: bool,
    active_filter: model::Filter,
    detail_worker: Option<details::DetailWorker>,
    onboarding_done: bool,
}

impl Drop for AppState {
    fn drop(&mut self) {
        if !self.font.is_null() {
            unsafe { DeleteObject(self.font.cast()) };
        }
    }
}

impl AppState {
    unsafe fn create(hwnd: HWND) -> Box<Self> {
        let font_name = wide("Segoe UI");
        let font = unsafe {
            CreateFontW(
                -16,
                0,
                0,
                0,
                FW_NORMAL as i32,
                0,
                0,
                0,
                1,
                0,
                0,
                5,
                0,
                font_name.as_ptr(),
            )
        };
        let effective_font = if font.is_null() {
            (unsafe { GetStockObject(DEFAULT_GUI_FONT) }) as HFONT
        } else {
            font
        };
        let search = unsafe {
            CreateWindowExW(
                WS_EX_CLIENTEDGE,
                wide("EDIT").as_ptr(),
                wide("").as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32,
                0,
                0,
                0,
                0,
                hwnd,
                ID_SEARCH as HMENU,
                null_mut(),
                null(),
            )
        };
        let list = unsafe {
            CreateWindowExW(
                WS_EX_CLIENTEDGE,
                WC_LISTVIEWW,
                wide("").as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | LVS_REPORT | LVS_SHOWSELALWAYS,
                0,
                0,
                0,
                0,
                hwnd,
                ID_LIST as HMENU,
                null_mut(),
                null(),
            )
        };
        let status = create_control(hwnd, "STATIC", "Starting first scan…", 0);
        let refresh = create_control(hwnd, "BUTTON", "Refresh", ID_REFRESH);
        let end = create_control(hwnd, "BUTTON", "End process", ID_END);
        let suspend = create_control(hwnd, "BUTTON", "Suspend", ID_SUSPEND);
        let resume = create_control(hwnd, "BUTTON", "Resume", ID_RESUME);
        let details = create_control(hwnd, "BUTTON", "Details", ID_DETAILS);
        let record_baseline = create_control(hwnd, "BUTTON", "Record all", ID_RECORD_BASELINE);
        let add_baseline = create_control(hwnd, "BUTTON", "Allow", ID_ADD_BASELINE);
        let remove_baseline = create_control(hwnd, "BUTTON", "Unallow", ID_REMOVE_BASELINE);
        let filters = [
            create_control(hwnd, "BUTTON", "Review", ID_FILTER_REVIEW),
            create_control(hwnd, "BUTTON", "New", ID_FILTER_NEW),
            create_control(hwnd, "BUTTON", "Heavy", ID_FILTER_HEAVY),
            create_control(hwnd, "BUTTON", "Restarting", ID_FILTER_RESTARTING),
            create_control(hwnd, "BUTTON", "Known", ID_FILTER_KNOWN),
            create_control(hwnd, "BUTTON", "All", ID_FILTER_ALL),
        ];

        for control in [
            search,
            list,
            status,
            refresh,
            end,
            suspend,
            resume,
            details,
            record_baseline,
            add_baseline,
            remove_baseline,
        ]
        .into_iter()
        .chain(filters)
        {
            unsafe { SendMessageW(control, WM_SETFONT, effective_font as WPARAM, 1) };
        }
        unsafe {
            SendMessageW(
                list,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                0,
                (LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER) as LPARAM,
            )
        };
        for (index, (title, width, format)) in [
            ("Finding", 110, LVCFMT_LEFT),
            ("Process", 190, LVCFMT_LEFT),
            ("PID", 72, LVCFMT_RIGHT),
            ("CPU", 72, LVCFMT_RIGHT),
            ("RAM", 88, LVCFMT_RIGHT),
            ("Disk/s", 92, LVCFMT_RIGHT),
            ("Path", 540, LVCFMT_LEFT),
        ]
        .into_iter()
        .enumerate()
        {
            insert_column(list, index as i32, title, width, format);
        }

        let scanner = Scanner::new();
        let onboarding_done = scanner.baseline.onboarding_complete;
        Box::new(Self {
            hwnd,
            search,
            list,
            status,
            refresh,
            end,
            suspend,
            resume,
            details,
            record_baseline,
            add_baseline,
            remove_baseline,
            filters,
            font: if font == effective_font {
                font
            } else {
                null_mut()
            },
            scanner,
            rows: Vec::new(),
            displayed: Vec::new(),
            rendered: Vec::new(),
            position_scratch: HashMap::new(),
            sort_column: 0,
            sort_descending: false,
            search_text: String::new(),
            timer_active: true,
            active_filter: model::Filter::Review,
            detail_worker: None,
            onboarding_done,
        })
    }

    fn resize(&self) {
        let mut rect: RECT = unsafe { zeroed() };
        unsafe { GetClientRect(self.hwnd, &mut rect) };
        let width = (rect.right - rect.left).max(760);
        let height = (rect.bottom - rect.top).max(320);
        let top = 76;
        let bottom = 38;
        unsafe {
            MoveWindow(self.search, 10, 9, (width - 665).max(80), 25, 1);
            MoveWindow(self.refresh, width - 645, 8, 65, 27, 1);
            MoveWindow(self.details, width - 572, 8, 65, 27, 1);
            MoveWindow(self.add_baseline, width - 499, 8, 60, 27, 1);
            MoveWindow(self.remove_baseline, width - 431, 8, 72, 27, 1);
            MoveWindow(self.record_baseline, width - 351, 8, 90, 27, 1);
            MoveWindow(self.suspend, width - 253, 8, 72, 27, 1);
            MoveWindow(self.resume, width - 173, 8, 65, 27, 1);
            MoveWindow(self.end, width - 100, 8, 90, 27, 1);
            let mut x = 10;
            for (button, button_width) in self.filters.into_iter().zip([76, 56, 64, 88, 64, 48]) {
                MoveWindow(button, x, 42, button_width, 27, 1);
                x += button_width + 6;
            }
            MoveWindow(self.list, 10, top, width - 20, height - top - bottom, 1);
            MoveWindow(self.status, 12, height - 29, width - 24, 22, 1);
        }
    }

    fn refresh(&mut self) {
        if unsafe { IsIconic(self.hwnd) } != 0 {
            return;
        }
        let started = Instant::now();
        match self.scanner.scan() {
            Ok(rows) => {
                self.rows = rows;
                self.show_onboarding_if_needed();
                let scan_ms = started.elapsed().as_secs_f64() * 1000.0;
                self.apply_filter_sort(false);
                let total = self.rows.len();
                let anomalies = self
                    .rows
                    .iter()
                    .filter(|row| {
                        row.trust == TrustState::Unclassified
                            || row.findings.contains(
                                Findings::DIFFERENT_PATH
                                    | Findings::PARENT_ENDED
                                    | Findings::RESTARTING
                                    | Findings::PEER_OUTLIER
                                    | Findings::HEAVY_CPU
                                    | Findings::HEAVY_MEMORY
                                    | Findings::HEAVY_DISK,
                            )
                    })
                    .count();
                let status = format!(
                    "{total} processes  |  {anomalies} anomalous  |  scan {scan_ms:.2} ms  |  polling stops when minimized"
                );
                set_text(self.status, &status);
            }
            Err(error) => {
                let retained = self.rows.len();
                set_text(
                    self.status,
                    &format!("Refresh failed; showing the last {retained} processes  |  {error}"),
                );
            }
        }
    }

    fn show_onboarding_if_needed(&mut self) {
        if self.onboarding_done || self.rows.is_empty() {
            return;
        }
        self.onboarding_done = true;
        let capture = message(
            self.hwnd,
            "ProcDrift reports evidence, not malware verdicts.\n\nUnclassified means there is not yet enough local evidence. Findings such as Heavy, Parent ended, or Restarting are independent observations.\n\nCapture the currently running executable paths as your reference snapshot now?\n\nChoose No to skip and open Review.",
            "Welcome to ProcDrift",
            MB_YESNO,
        ) == 6;
        let mut replacement = if capture {
            self.scanner.baseline.replacement_from_rows(&self.rows)
        } else {
            self.scanner.baseline.clone()
        };
        replacement.onboarding_complete = true;
        if let Err(error) = replacement.save() {
            set_text(
                self.status,
                &format!("Could not save first-run choice: {error}"),
            );
        } else {
            self.scanner.baseline = replacement;
        }
    }

    fn apply_filter_sort(&mut self, force_resort: bool) {
        let selected_key = self.selected_key();
        let query = self.search_text.trim();
        let query_bytes = query.as_bytes();
        let query_pid = query.parse::<u32>().ok();
        self.displayed.clear();
        self.displayed.extend(
            self.rows
                .iter()
                .filter(|row| {
                    EvidenceRow {
                        trust: row.trust,
                        findings: row.findings,
                        cpu_tenths: row.cpu_tenths,
                        memory_bytes: row.memory_bytes,
                        disk_bytes_per_second: row.io_per_second,
                    }
                    .matches_filter(self.active_filter)
                })
                .filter(|row| row_matches_search(row, query_bytes, query_pid))
                .cloned(),
        );
        let column = self.sort_column;
        let descending = self.sort_descending;
        if !force_resort && matches!(column, 3..=5) && !self.rendered.is_empty() {
            self.position_scratch.clear();
            self.position_scratch.extend(
                self.rendered
                    .iter()
                    .enumerate()
                    .map(|(index, row)| (row.key, index)),
            );
            self.displayed.sort_by_key(|row| {
                self.position_scratch
                    .get(&row.key)
                    .copied()
                    .unwrap_or(usize::MAX)
            });
        } else {
            self.displayed.sort_by(|a, b| {
                let order = match column {
                    0 => risk_rank(a)
                        .cmp(&risk_rank(b))
                        .then_with(|| cmp_ascii_case_insensitive(&a.name, &b.name)),
                    1 => cmp_ascii_case_insensitive(&a.name, &b.name),
                    2 => a.key.pid.cmp(&b.key.pid),
                    3 => a.cpu_tenths.cmp(&b.cpu_tenths),
                    4 => a.memory_bytes.cmp(&b.memory_bytes),
                    5 => a.io_per_second.cmp(&b.io_per_second),
                    _ => cmp_ascii_case_insensitive(&a.path, &b.path),
                };
                if descending { order.reverse() } else { order }
            });
        }
        self.render(selected_key);
    }

    fn render(&mut self, selected_key: Option<ProcKey>) {
        let same_order = self.rendered.len() == self.displayed.len()
            && self
                .rendered
                .iter()
                .zip(&self.displayed)
                .all(|(left, right)| left.key == right.key);
        if same_order {
            let top = unsafe { SendMessageW(self.list, LVM_GETTOPINDEX, 0, 0) }.max(0) as usize;
            let per_page =
                unsafe { SendMessageW(self.list, LVM_GETCOUNTPERPAGE, 0, 0) }.max(0) as usize;
            let visible_start = top.saturating_sub(1).min(self.displayed.len());
            let visible_end = top
                .saturating_add(per_page)
                .saturating_add(1)
                .min(self.displayed.len());
            let needs_update =
                self.rendered
                    .iter()
                    .zip(&self.displayed)
                    .enumerate()
                    .any(|(index, (old, new))| {
                        static_cells_changed(old, new)
                            || (index >= visible_start
                                && index < visible_end
                                && dynamic_cells_changed(old, new))
                    });
            if needs_update {
                unsafe { SendMessageW(self.list, 0x000B, 0, 0) };
                for index in 0..self.displayed.len() {
                    let old = &mut self.rendered[index];
                    let new = &self.displayed[index];
                    update_static_cells(self.list, index as i32, old, new);
                    if index >= visible_start && index < visible_end {
                        update_dynamic_cells(self.list, index as i32, old, new);
                        old.clone_from(new);
                    } else {
                        old.trust = new.trust;
                        old.findings = new.findings;
                        old.name = Rc::clone(&new.name);
                        old.path = Rc::clone(&new.path);
                    }
                }
                unsafe { SendMessageW(self.list, 0x000B, 1, 0) };
            }
        } else {
            unsafe { SendMessageW(self.list, 0x000B, 0, 0) };
            unsafe { SendMessageW(self.list, LVM_DELETEALLITEMS, 0, 0) };
            for (index, row) in self.displayed.iter().enumerate() {
                insert_row(self.list, index as i32, row);
            }
            unsafe { SendMessageW(self.list, 0x000B, 1, 0) };
            if let Some(index) = selected_key.and_then(|key| {
                self.displayed
                    .iter()
                    .position(|candidate| candidate.key == key)
            }) {
                let mut item: LVITEMW = unsafe { zeroed() };
                item.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
                item.state = LVIS_SELECTED | LVIS_FOCUSED;
                unsafe {
                    SendMessageW(
                        self.list,
                        LVM_SETITEMSTATE,
                        index,
                        &item as *const _ as LPARAM,
                    )
                };
            }
            self.rendered.clone_from(&self.displayed);
        }
    }

    fn update_search(&mut self) {
        self.search_text = window_text(self.search);
        self.apply_filter_sort(true);
    }

    fn set_filter(&mut self, filter: model::Filter) {
        self.active_filter = filter;
        self.apply_filter_sort(true);
    }

    fn set_minimized(&mut self, minimized: bool) {
        if minimized && self.timer_active {
            unsafe { KillTimer(self.hwnd, TIMER_SCAN) };
            self.timer_active = false;
            self.scanner.last_scan = None;
            self.scanner.previous.clear();
        } else if !minimized && !self.timer_active {
            unsafe {
                SetTimer(self.hwnd, TIMER_SCAN, 1000, None);
                PostMessageW(self.hwnd, WM_REFRESH, 0, 0);
            }
            self.timer_active = true;
        }
    }

    fn selected_key(&self) -> Option<ProcKey> {
        let index =
            unsafe { SendMessageW(self.list, LVM_GETNEXTITEM, usize::MAX, LVNI_SELECTED) } as isize;
        if index < 0 {
            None
        } else {
            self.rendered.get(index as usize).map(|row| row.key)
        }
    }

    fn selected(&self) -> Option<ProcessRow> {
        let key = self.selected_key()?;
        self.displayed.iter().find(|row| row.key == key).cloned()
    }

    fn select_index(&self, index: usize) {
        let mut clear: LVITEMW = unsafe { zeroed() };
        clear.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
        unsafe {
            SendMessageW(
                self.list,
                LVM_SETITEMSTATE,
                usize::MAX,
                &clear as *const _ as LPARAM,
            )
        };
        let mut select: LVITEMW = unsafe { zeroed() };
        select.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
        select.state = LVIS_SELECTED | LVIS_FOCUSED;
        unsafe {
            SendMessageW(
                self.list,
                LVM_SETITEMSTATE,
                index,
                &select as *const _ as LPARAM,
            )
        };
    }

    fn context_menu(&mut self) {
        let Some(row) = self.selected() else {
            return;
        };
        let menu = unsafe { CreatePopupMenu() };
        if menu.is_null() {
            return;
        }
        append_menu_item(menu, ID_MENU_DETAILS, "Details", false);
        append_menu_item(menu, ID_MENU_ACTIVITY, "Recent activity", false);
        append_menu_item(menu, ID_MENU_COPY, "Copy selected", false);
        append_menu_item(
            menu,
            ID_MENU_OPEN_LOCATION,
            "Open file location",
            row.path.is_empty(),
        );
        unsafe { AppendMenuW(menu, MF_SEPARATOR, 0, null()) };
        append_menu_item(menu, ID_MENU_END, "End process", false);
        append_menu_item(menu, ID_MENU_END_TREE, "End captured process tree", false);
        append_menu_item(menu, ID_MENU_SUSPEND, "Suspend", false);
        append_menu_item(menu, ID_MENU_RESUME, "Resume", false);
        unsafe { AppendMenuW(menu, MF_SEPARATOR, 0, null()) };
        append_menu_item(menu, ID_MENU_TRUST, "Allow exact path", row.path.is_empty());
        append_menu_item(
            menu,
            ID_MENU_UNTRUST,
            "Remove allowance for exact path",
            false,
        );

        let mut point = windows_sys::Win32::Foundation::POINT::default();
        if unsafe { GetCursorPos(&mut point) } != 0 {
            let command = unsafe {
                TrackPopupMenu(
                    menu,
                    TPM_RETURNCMD | TPM_RIGHTBUTTON,
                    point.x,
                    point.y,
                    0,
                    self.hwnd,
                    null(),
                )
            };
            self.dispatch_menu(command as usize);
        }
        unsafe { DestroyMenu(menu) };
    }

    fn dispatch_menu(&mut self, command: usize) {
        match command {
            ID_MENU_DETAILS => self.details(),
            ID_MENU_COPY => self.copy_selected(),
            ID_MENU_OPEN_LOCATION => self.open_selected_location(),
            ID_MENU_END_TREE => self.end_selected_tree(),
            ID_MENU_END => self.action(Action::Terminate),
            ID_MENU_SUSPEND => self.action(Action::Suspend),
            ID_MENU_RESUME => self.action(Action::Resume),
            ID_MENU_TRUST => self.add_selected_to_baseline(),
            ID_MENU_UNTRUST => self.remove_selected_from_baseline(),
            ID_MENU_ACTIVITY => self.recent_activity(),
            _ => {}
        }
    }

    fn recent_activity(&self) {
        let events: Vec<_> = self.scanner.activity.events().rev().take(40).collect();
        let text = if events.is_empty() {
            "No process starts or exits have been observed in this session.".to_owned()
        } else {
            events
                .into_iter()
                .map(|event| {
                    format!(
                        "{}s  {}  {} (PID {})",
                        event.at_seconds,
                        match event.kind {
                            activity::ActivityKind::Started => "Started",
                            activity::ActivityKind::Exited => "Exited",
                        },
                        event.executable,
                        event.key.pid
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        message(self.hwnd, &text, "Recent activity (memory only)", MB_OK);
    }

    fn copy_selected(&self) {
        let mut text = String::from("Status\tName\tPID\tCPU\tRAM\tDisk/s\tPath\r\n");
        let mut index = -1_isize;
        let mut count = 0;
        loop {
            index =
                unsafe { SendMessageW(self.list, LVM_GETNEXTITEM, index as usize, LVNI_SELECTED) };
            if index < 0 {
                break;
            }
            let Some(row) = self.rendered.get(index as usize) else {
                continue;
            };
            text.push_str(&format!(
                "{}\t{}\t{}\t{}.{:01}%\t{}\t{}\t{}\r\n",
                legacy_category(row),
                row.name,
                row.key.pid,
                row.cpu_tenths / 10,
                row.cpu_tenths % 10,
                format_bytes(row.memory_bytes),
                format_rate(row.io_per_second),
                row.path,
            ));
            count += 1;
        }
        if count == 0 {
            return;
        }
        match set_clipboard_text(self.hwnd, &text) {
            Ok(()) => set_text(
                self.status,
                &format!("Copied {count} selected process row(s)."),
            ),
            Err(error) => {
                message(
                    self.hwnd,
                    &error,
                    "Could not copy processes",
                    MB_ICONERROR | MB_OK,
                );
            }
        }
    }

    fn open_selected_location(&self) {
        let Some(row) = self.selected() else {
            return;
        };
        if row.path.is_empty() {
            message(
                self.hwnd,
                "Windows did not expose this process path.",
                "File location unavailable",
                MB_ICONWARNING | MB_OK,
            );
            return;
        }
        let parameters = wide(format!("/select,\"{}\"", row.path));
        let result = unsafe {
            ShellExecuteW(
                self.hwnd,
                wide("open").as_ptr(),
                wide("explorer.exe").as_ptr(),
                parameters.as_ptr(),
                null(),
                SW_SHOWNORMAL,
            )
        };
        if result as isize <= 32 {
            message(
                self.hwnd,
                "Windows could not open File Explorer for this executable.",
                "File location unavailable",
                MB_ICONERROR | MB_OK,
            );
        }
    }

    fn end_selected_tree(&mut self) {
        let Some(root) = self.selected() else {
            return;
        };
        if root.key.pid == std::process::id() {
            message(
                self.hwnd,
                "Refusing to act on ProcDrift itself.",
                "ProcDrift",
                MB_ICONWARNING | MB_OK,
            );
            return;
        }

        let targets = captured_process_tree(&self.rows, root.key, std::process::id());

        let prompt = format!(
            "End {} and {} captured descendant process(es)?\n\nEach PID is revalidated before termination.",
            root.name,
            targets.len().saturating_sub(1),
        );
        if message(
            self.hwnd,
            &prompt,
            "Confirm captured process-tree termination",
            MB_ICONWARNING | MB_YESNO,
        ) != 6
        {
            return;
        }

        let mut failures = Vec::new();
        for key in targets.into_iter().rev() {
            if let Err(error) = perform_action(key, Action::Terminate) {
                failures.push(format!("PID {}: {}", key.pid, error));
            }
        }
        self.refresh();
        if !failures.is_empty() {
            failures.truncate(8);
            message(
                self.hwnd,
                &failures.join("\n"),
                "Some processes were not ended",
                MB_ICONWARNING | MB_OK,
            );
        }
    }

    fn details(&mut self) {
        let Some(row) = self.selected() else {
            message(self.hwnd, "Select a process first.", "ProcDrift", MB_OK);
            return;
        };
        if self.detail_worker.is_none() {
            let target = self.hwnd as isize;
            match details::DetailWorker::start(move |result| {
                let pointer = Box::into_raw(Box::new(result));
                if unsafe { PostMessageW(target as HWND, WM_DETAILS_READY, 0, pointer as LPARAM) }
                    == 0
                {
                    unsafe { drop(Box::from_raw(pointer)) };
                }
            }) {
                Ok(worker) => self.detail_worker = Some(worker),
                Err(error) => {
                    set_text(self.status, &error);
                    return;
                }
            }
        }
        set_text(
            self.status,
            &format!("Inspecting {} without blocking the process list…", row.name),
        );
        let request = details::DetailRequest {
            key: details::SelectionKey {
                pid: row.key.pid,
                created: row.key.created,
            },
            name: row.name.to_string(),
            path: row.path.to_string(),
        };
        if let Some(worker) = &self.detail_worker
            && let Err(error) = worker.inspect(request)
        {
            set_text(self.status, &error);
        }
    }

    fn detail_ready(&mut self, result: details::DetailResult) {
        let selected = self.selected_key().map(|key| details::SelectionKey {
            pid: key.pid,
            created: key.created,
        });
        if !details::is_current_selection(selected, &result) {
            return;
        }
        let Some(row) = self.selected() else {
            return;
        };
        let reasons = row.findings.calm_reasons();
        let reason_text = if reasons.is_empty() {
            "No current review findings".to_owned()
        } else {
            reasons.join("\n• ")
        };
        let text = format!(
            "Trust: {}\nFinding: {}\nWhy shown:\n• {}\n\nPID: {}\nParent PID: {}\nSession: {}\nThreads: {}\nHandles: {}\nCPU: {}.{:01}%\nWorking set: {}\nPrivate memory: {}\nDisk I/O: {}\n\n{}",
            row.trust.label(),
            primary_finding(&row),
            reason_text,
            row.key.pid,
            row.ppid,
            row.session_id,
            row.thread_count,
            row.handle_count,
            row.cpu_tenths / 10,
            row.cpu_tenths % 10,
            format_bytes(row.memory_bytes),
            format_bytes(row.private_bytes),
            format_rate(row.io_per_second),
            result.summary(),
        );
        message(
            self.hwnd,
            &text,
            &format!("{} — Process details", result.name),
            MB_OK,
        );
    }

    fn record_baseline(&mut self) {
        if self.rows.is_empty() {
            message(
                self.hwnd,
                "No process snapshot is available yet.",
                "ProcDrift",
                MB_ICONWARNING | MB_OK,
            );
            return;
        }
        let replacement = self.scanner.baseline.replacement_from_rows(&self.rows);
        let count = replacement.records.len();
        let prompt = format!(
            "Replace the baseline with {count} currently accessible programs?\n\nThis writes the state file once; monitoring itself performs no file writes."
        );
        if message(
            self.hwnd,
            &prompt,
            "Replace baseline",
            MB_ICONWARNING | MB_YESNO,
        ) != 6
        {
            return;
        }
        match replacement.save() {
            Ok(()) => {
                self.scanner.baseline = replacement;
                self.refresh();
                set_text(
                    self.status,
                    &format!(
                        "Baseline replaced with {count} programs  |  {}",
                        self.scanner.baseline.path.display()
                    ),
                );
            }
            Err(error) => {
                message(
                    self.hwnd,
                    &error,
                    "Could not save baseline",
                    MB_ICONERROR | MB_OK,
                );
            }
        }
    }

    fn add_selected_to_baseline(&mut self) {
        let Some(row) = self.selected() else {
            message(self.hwnd, "Select a process first.", "ProcDrift", MB_OK);
            return;
        };
        if row.path.is_empty() {
            message(
                self.hwnd,
                "Windows did not expose this process path, so it cannot be added to the baseline.",
                "Cannot trust process",
                MB_ICONWARNING | MB_OK,
            );
            return;
        }
        let mut replacement = self.scanner.baseline.clone();
        if !replacement.add(&row.path) {
            set_text(self.status, "That exact program path is already trusted.");
            return;
        }
        match replacement.save() {
            Ok(()) => {
                self.scanner.baseline = replacement;
                self.refresh();
                set_text(
                    self.status,
                    &format!("Allowed {} at {}", row.name, row.path),
                );
            }
            Err(error) => {
                message(
                    self.hwnd,
                    &error,
                    "Could not save baseline",
                    MB_ICONERROR | MB_OK,
                );
            }
        }
    }

    fn remove_selected_from_baseline(&mut self) {
        let Some(row) = self.selected() else {
            message(self.hwnd, "Select a process first.", "ProcDrift", MB_OK);
            return;
        };
        let mut replacement = self.scanner.baseline.clone();
        if !replacement.remove(&row.path) {
            set_text(self.status, "That program path is not in the baseline.");
            return;
        }
        match replacement.save() {
            Ok(()) => {
                self.scanner.baseline = replacement;
                self.refresh();
                set_text(
                    self.status,
                    &format!("Removed {} from the trusted baseline.", row.name),
                );
            }
            Err(error) => {
                message(
                    self.hwnd,
                    &error,
                    "Could not save baseline",
                    MB_ICONERROR | MB_OK,
                );
            }
        }
    }

    fn action(&mut self, kind: Action) {
        let Some(row) = self.selected() else {
            message(self.hwnd, "Select a process first.", "ProcDrift", MB_OK);
            return;
        };
        let refusal = if row.key.pid == std::process::id() {
            Some("Refusing to act on ProcDrift itself.")
        } else if matches!(row.key.pid, 0 | 4) {
            Some("Refusing to act on a kernel pseudo-process. Ending it would stop the machine.")
        } else if row.trust == TrustState::Protected {
            Some("Refusing to act on a protected system process. Ending it would stop the machine.")
        } else {
            None
        };
        if let Some(refusal) = refusal {
            message(self.hwnd, refusal, "ProcDrift", MB_ICONWARNING | MB_OK);
            return;
        }
        if matches!(kind, Action::Terminate) {
            let prompt = format!("End {} (PID {})?", row.name, row.key.pid);
            if message(
                self.hwnd,
                &prompt,
                "Confirm process termination",
                MB_ICONWARNING | MB_YESNO,
            ) != 6
            {
                return;
            }
        }
        match perform_action(row.key, kind) {
            Ok(()) => {
                match kind {
                    Action::Suspend => {
                        self.scanner.paused.insert(row.key);
                    }
                    Action::Resume | Action::Terminate => {
                        self.scanner.paused.remove(&row.key);
                    }
                }
                self.refresh();
            }
            Err(error) => {
                message(
                    self.hwnd,
                    &error,
                    "Process action failed",
                    MB_ICONERROR | MB_OK,
                );
                if error.contains("denied")
                    && message(
                        self.hwnd,
                        "Windows denied access. Restart ProcDrift as administrator and replace this instance?",
                        "Administrator access",
                        MB_ICONWARNING | MB_YESNO,
                    ) == 6
                {
                    let _ = restart_elevated(self.hwnd);
                }
            }
        }
    }

    fn handle_shortcut(&mut self, message: &MSG) -> bool {
        if message.message != WM_KEYDOWN {
            return false;
        }
        let key = message.wParam;
        let control = unsafe { GetKeyState(VK_CONTROL_KEY) } < 0;
        let focused = unsafe { GetFocus() };
        match (control, key) {
            (true, key) if key == b'F' as usize => {
                unsafe { SetFocus(self.search) };
                true
            }
            (true, key) if key == b'K' as usize => {
                unsafe { SetFocus(self.search) };
                true
            }
            (true, key) if key == b'C' as usize && focused != self.search => {
                self.copy_selected();
                true
            }
            (false, VK_F5_KEY) => {
                self.refresh();
                true
            }
            (false, VK_DELETE_KEY) if focused == self.list => {
                self.action(Action::Terminate);
                true
            }
            (false, VK_F2_KEY) if focused == self.list => {
                self.add_selected_to_baseline();
                true
            }
            (false, VK_SPACE_KEY) if focused == self.list => {
                let action = if self.selected().is_some_and(|row| row.paused_by_procdrift) {
                    Action::Resume
                } else {
                    Action::Suspend
                };
                self.action(action);
                true
            }
            (false, VK_ENTER_KEY) if focused == self.list => {
                self.details();
                true
            }
            (false, VK_ESCAPE_KEY) => {
                if self.search_text.is_empty() {
                    unsafe { SetFocus(self.list) };
                } else {
                    set_text(self.search, "");
                }
                true
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy)]
enum Action {
    Terminate,
    Suspend,
    Resume,
}

fn process_created(handle: HANDLE) -> Option<u64> {
    let mut created: FILETIME = unsafe { zeroed() };
    let mut exited: FILETIME = unsafe { zeroed() };
    let mut kernel: FILETIME = unsafe { zeroed() };
    let mut user: FILETIME = unsafe { zeroed() };
    if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } != 0 {
        Some(filetime_value(created))
    } else {
        None
    }
}

fn perform_action(expected: ProcKey, action: Action) -> Result<(), String> {
    if matches!(expected.pid, 0 | 4) || expected.pid == std::process::id() {
        return Err("This protected process cannot be controlled by ProcDrift.".to_owned());
    }
    let access = match action {
        Action::Terminate => PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
        Action::Suspend | Action::Resume => 0x0800 | PROCESS_QUERY_LIMITED_INFORMATION,
    };
    let handle = unsafe { OpenProcess(access, 0, expected.pid) };
    if handle.is_null() {
        return Err("Windows denied access or the process has exited.".to_string());
    }
    let current_created = process_created(handle);
    if expected.created == 0 || current_created != Some(expected.created) {
        unsafe { CloseHandle(handle) };
        return Err("Process identity changed; refresh and retry.".to_string());
    }
    let mut critical = 0;
    if unsafe { IsProcessCritical(handle, &mut critical) } != 0 && critical != 0 {
        unsafe { CloseHandle(handle) };
        return Err("Windows reports this as a critical process; action blocked.".to_owned());
    }
    let succeeded = unsafe {
        match action {
            Action::Terminate => TerminateProcess(handle, 1) != 0,
            Action::Suspend => NtSuspendProcess(handle) >= 0,
            Action::Resume => NtResumeProcess(handle) >= 0,
        }
    };
    unsafe { CloseHandle(handle) };
    if succeeded {
        Ok(())
    } else {
        Err("Windows rejected the requested action.".to_string())
    }
}

fn captured_process_tree(rows: &[ProcessRow], root: ProcKey, excluded_pid: u32) -> Vec<ProcKey> {
    let mut members = HashMap::with_capacity(8);
    let mut targets = Vec::with_capacity(8);
    members.insert(root.pid, root.created);
    targets.push(root);
    loop {
        let before = targets.len();
        for row in rows {
            if row.key.pid != excluded_pid
                && !members.contains_key(&row.key.pid)
                && members
                    .get(&row.ppid)
                    .is_some_and(|parent_created| row.key.created >= *parent_created)
            {
                members.insert(row.key.pid, row.key.created);
                targets.push(row.key);
            }
        }
        if targets.len() == before {
            return targets;
        }
    }
}

fn risk_rank(row: &ProcessRow) -> u8 {
    // Something absent from the reference snapshot that is also configured to
    // start on its own will still be here after a reboot. That combination is
    // the one worth looking at first; either finding alone is ordinary.
    let persistent_and_new = row.findings.contains(Findings::NEW)
        && row.findings.contains(Findings::STARTS_AUTOMATICALLY);
    if row.findings.contains(Findings::RESTARTING) || persistent_and_new {
        0
    } else if row
        .findings
        .contains(Findings::DIFFERENT_PATH | Findings::PARENT_ENDED | Findings::PEER_OUTLIER)
    {
        1
    } else if row
        .findings
        .contains(Findings::HEAVY_CPU | Findings::HEAVY_MEMORY | Findings::HEAVY_DISK)
    {
        2
    } else if row.trust == TrustState::Unclassified {
        3
    } else if row.trust == TrustState::Allowed {
        4
    } else {
        5
    }
}

fn cmp_ascii_case_insensitive(left: &str, right: &str) -> std::cmp::Ordering {
    left.bytes()
        .map(|byte| byte.to_ascii_lowercase())
        .cmp(right.bytes().map(|byte| byte.to_ascii_lowercase()))
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack.as_bytes().windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
}

fn row_matches_search(row: &ProcessRow, query: &[u8], query_pid: Option<u32>) -> bool {
    query.is_empty()
        || contains_ascii_case_insensitive(&row.name, query)
        || contains_ascii_case_insensitive(&row.path, query)
        || contains_ascii_case_insensitive(legacy_category(row), query)
        || query_pid == Some(row.key.pid)
}

fn create_control(parent: HWND, class: &str, text: &str, id: usize) -> HWND {
    unsafe {
        CreateWindowExW(
            0,
            wide(class).as_ptr(),
            wide(text).as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            0,
            0,
            0,
            0,
            parent,
            id as HMENU,
            null_mut(),
            null(),
        )
    }
}

fn insert_column(list: HWND, index: i32, title: &str, width: i32, format: i32) {
    let mut title_wide = wide(title);
    let mut column: LVCOLUMNW = unsafe { zeroed() };
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    column.fmt = format;
    column.cx = width;
    column.pszText = title_wide.as_mut_ptr();
    unsafe {
        SendMessageW(
            list,
            LVM_INSERTCOLUMNW,
            index as WPARAM,
            &column as *const _ as LPARAM,
        )
    };
}

fn insert_row(list: HWND, index: i32, row: &ProcessRow) {
    let fields = [
        legacy_category(row).to_string(),
        row.name.to_string(),
        row.key.pid.to_string(),
        format!("{}.{:01}%", row.cpu_tenths / 10, row.cpu_tenths % 10),
        format_bytes(row.memory_bytes),
        format_rate(row.io_per_second),
        row.path.to_string(),
    ];
    let mut first = wide(&fields[0]);
    let mut item: LVITEMW = unsafe { zeroed() };
    item.mask = LVIF_TEXT;
    item.iItem = index;
    item.pszText = first.as_mut_ptr();
    unsafe { SendMessageW(list, LVM_INSERTITEMW, 0, &item as *const _ as LPARAM) };
    for (column, field) in fields.iter().enumerate().skip(1) {
        set_cell(list, index, column as i32, field);
    }
}

fn static_cells_changed(old: &ProcessRow, new: &ProcessRow) -> bool {
    old.trust != new.trust
        || old.findings != new.findings
        || old.name != new.name
        || old.key.pid != new.key.pid
        || old.path != new.path
}

fn dynamic_cells_changed(old: &ProcessRow, new: &ProcessRow) -> bool {
    old.cpu_tenths != new.cpu_tenths
        || old.memory_bytes != new.memory_bytes
        || old.io_per_second != new.io_per_second
}

fn update_static_cells(list: HWND, index: i32, old: &ProcessRow, new: &ProcessRow) {
    if old.trust != new.trust || old.findings != new.findings {
        set_cell(list, index, 0, legacy_category(new));
    }
    if old.name != new.name {
        set_cell(list, index, 1, &new.name);
    }
    if old.key.pid != new.key.pid {
        set_cell(list, index, 2, &new.key.pid.to_string());
    }
    if old.path != new.path {
        set_cell(list, index, 6, &new.path);
    }
}

fn update_dynamic_cells(list: HWND, index: i32, old: &ProcessRow, new: &ProcessRow) {
    if old.cpu_tenths != new.cpu_tenths {
        set_cell(
            list,
            index,
            3,
            &format!("{}.{:01}%", new.cpu_tenths / 10, new.cpu_tenths % 10),
        );
    }
    if old.memory_bytes != new.memory_bytes {
        set_cell(list, index, 4, &format_bytes(new.memory_bytes));
    }
    if old.io_per_second != new.io_per_second {
        set_cell(list, index, 5, &format_rate(new.io_per_second));
    }
}

fn set_cell(list: HWND, row: i32, column: i32, text: &str) {
    let mut value = wide(text);
    let mut item: LVITEMW = unsafe { zeroed() };
    item.iSubItem = column;
    item.pszText = value.as_mut_ptr();
    unsafe {
        SendMessageW(
            list,
            LVM_SETITEMTEXTW,
            row as WPARAM,
            &item as *const _ as LPARAM,
        )
    };
}

fn format_bytes(value: u64) -> String {
    if value >= 1 << 30 {
        format!("{:.1} GB", value as f64 / (1_u64 << 30) as f64)
    } else {
        format!("{:.1} MB", value as f64 / (1_u64 << 20) as f64)
    }
}

fn format_rate(value: u64) -> String {
    if value >= 1 << 20 {
        format!("{:.1} MB/s", value as f64 / (1_u64 << 20) as f64)
    } else if value >= 1 << 10 {
        format!("{:.1} KB/s", value as f64 / (1_u64 << 10) as f64)
    } else {
        format!("{value} B/s")
    }
}

fn window_text(hwnd: HWND) -> String {
    let length = unsafe { GetWindowTextLengthW(hwnd) };
    if length <= 0 {
        return String::new();
    }
    let mut buffer = vec![0_u16; length as usize + 1];
    let copied = unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32) };
    String::from_utf16_lossy(&buffer[..copied.max(0) as usize])
}

fn set_text(hwnd: HWND, text: &str) {
    unsafe { SetWindowTextW(hwnd, wide(text).as_ptr()) };
}

fn message(hwnd: HWND, text: &str, title: &str, flags: u32) -> i32 {
    unsafe { MessageBoxW(hwnd, wide(text).as_ptr(), wide(title).as_ptr(), flags) }
}

fn append_menu_item(menu: HMENU, id: usize, text: &str, disabled: bool) {
    let flags = MF_STRING | if disabled { MF_GRAYED } else { 0 };
    unsafe { AppendMenuW(menu, flags, id, wide(text).as_ptr()) };
}

fn set_clipboard_text(owner: HWND, text: &str) -> Result<(), String> {
    if unsafe { OpenClipboard(owner) } == 0 {
        return Err("The clipboard is currently busy. Try again.".to_string());
    }
    let result = (|| {
        if unsafe { EmptyClipboard() } == 0 {
            return Err("Windows could not clear the clipboard.".to_string());
        }
        let encoded = wide(text);
        let bytes = encoded.len() * size_of::<u16>();
        let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) };
        if memory.is_null() {
            return Err("Windows could not allocate clipboard memory.".to_string());
        }
        let destination = unsafe { GlobalLock(memory) }.cast::<u16>();
        if destination.is_null() {
            unsafe { GlobalFree(memory) };
            return Err("Windows could not lock clipboard memory.".to_string());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(encoded.as_ptr(), destination, encoded.len());
            GlobalUnlock(memory);
        }
        if unsafe { SetClipboardData(CF_UNICODETEXT, memory) }.is_null() {
            unsafe { GlobalFree(memory) };
            return Err("Windows could not place the text on the clipboard.".to_string());
        }
        Ok(())
    })();
    unsafe { CloseClipboard() };
    result
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn state(hwnd: HWND) -> Option<&'static mut AppState> {
    let pointer = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut AppState;
    unsafe { pointer.as_mut() }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message_id: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message_id {
        WM_CREATE => {
            let create = lparam as *const CREATESTRUCTW;
            if create.is_null() {
                return -1;
            }
            let app = unsafe { AppState::create(hwnd) };
            let pointer = Box::into_raw(app);
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, pointer as isize) };
            if let Some(app) = state(hwnd) {
                app.resize();
                unsafe {
                    SetTimer(hwnd, TIMER_SCAN, 1000, None);
                    PostMessageW(hwnd, WM_REFRESH, 0, 0);
                    SetFocus(app.search);
                }
            }
            0
        }
        WM_SIZE => {
            if let Some(app) = state(hwnd) {
                app.resize();
                app.set_minimized(wparam == SIZE_MINIMIZED as usize);
            }
            0
        }
        WM_TIMER if wparam == TIMER_SCAN => {
            if let Some(app) = state(hwnd) {
                app.refresh();
            }
            0
        }
        WM_REFRESH => {
            if let Some(app) = state(hwnd) {
                app.refresh();
            }
            0
        }
        WM_DETAILS_READY => {
            if lparam != 0 {
                let result = unsafe { *Box::from_raw(lparam as *mut details::DetailResult) };
                if let Some(app) = state(hwnd) {
                    app.detail_ready(result);
                }
            }
            0
        }
        WM_COMMAND => {
            if let Some(app) = state(hwnd) {
                let control_id = wparam & 0xffff;
                let notification = (wparam >> 16) & 0xffff;
                if control_id == ID_SEARCH && notification == EN_CHANGE as usize {
                    app.update_search();
                } else if notification == BN_CLICKED {
                    match control_id {
                        ID_REFRESH => app.refresh(),
                        ID_DETAILS => app.details(),
                        ID_RECORD_BASELINE => app.record_baseline(),
                        ID_ADD_BASELINE => app.add_selected_to_baseline(),
                        ID_REMOVE_BASELINE => app.remove_selected_from_baseline(),
                        ID_END => app.action(Action::Terminate),
                        ID_SUSPEND => app.action(Action::Suspend),
                        ID_RESUME => app.action(Action::Resume),
                        ID_FILTER_REVIEW => app.set_filter(model::Filter::Review),
                        ID_FILTER_NEW => app.set_filter(model::Filter::New),
                        ID_FILTER_HEAVY => app.set_filter(model::Filter::Heavy),
                        ID_FILTER_RESTARTING => app.set_filter(model::Filter::Restarting),
                        ID_FILTER_KNOWN => app.set_filter(model::Filter::Known),
                        ID_FILTER_ALL => app.set_filter(model::Filter::All),
                        _ => {}
                    }
                }
            }
            0
        }
        WM_NOTIFY => {
            if lparam != 0 {
                // Most WM_NOTIFY payloads are a bare NMHDR. Read the header
                // first and only widen to Nmlistview for the codes that
                // actually deliver one, because forming a reference to the
                // larger struct over a smaller allocation is undefined.
                let header =
                    unsafe { &*(lparam as *const windows_sys::Win32::UI::Controls::NMHDR) };
                let code = header.code as i32;
                if matches!(code, LVN_COLUMNCLICK | LVN_ITEMACTIVATE | NM_RCLICK) {
                    let notification = unsafe { &*(lparam as *const Nmlistview) };
                    if code == LVN_COLUMNCLICK
                        && let Some(app) = state(hwnd)
                    {
                        let column = notification.sub_item.max(0) as usize;
                        if app.sort_column == column {
                            app.sort_descending = !app.sort_descending;
                        } else {
                            app.sort_column = column;
                            app.sort_descending = matches!(column, 3..=5);
                        }
                        app.apply_filter_sort(true);
                    } else if code == LVN_ITEMACTIVATE
                        && let Some(app) = state(hwnd)
                    {
                        app.details();
                    } else if code == NM_RCLICK
                        && notification.item >= 0
                        && let Some(app) = state(hwnd)
                    {
                        app.select_index(notification.item as usize);
                        app.context_menu();
                    }
                }
            }
            0
        }
        WM_CLOSE => {
            unsafe { DestroyWindow(hwnd) };
            0
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            0
        }
        WM_NCDESTROY => {
            let pointer = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut AppState;
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
            if !pointer.is_null() {
                unsafe { drop(Box::from_raw(pointer)) };
            }
            unsafe { DefWindowProcW(hwnd, message_id, wparam, lparam) }
        }
        _ => unsafe { DefWindowProcW(hwnd, message_id, wparam, lparam) },
    }
}

fn run() -> Result<(), String> {
    if let Some(pid) = replacement_pid(std::env::args().skip(1))? {
        let old = unsafe { OpenProcess(SYNCHRONIZE_ACCESS, 0, pid) };
        if !old.is_null() {
            unsafe {
                WaitForSingleObject(old, 5_000);
                CloseHandle(old);
            }
        }
    }
    let instance_mutex =
        unsafe { CreateMutexW(null(), 0, wide("Local\\ProcDriftNative").as_ptr()) };
    if instance_mutex.is_null() {
        return Err("Could not create the single-instance guard.".to_string());
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe { CloseHandle(instance_mutex) };
        return Ok(());
    }
    unsafe { InitCommonControls() };
    let instance: HINSTANCE = unsafe { GetModuleHandleW(null()) };
    let class_name = wide("ProcDriftNativeWindow");
    let title = wide("ProcDrift");
    let class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        lpszClassName: class_name.as_ptr(),
        ..unsafe { zeroed() }
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        return Err("Could not register the native window class.".to_string());
    }
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1240,
            760,
            null_mut(),
            null_mut(),
            instance,
            null(),
        )
    };
    if hwnd.is_null() {
        return Err("Could not create the native window.".to_string());
    }
    unsafe {
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
    }
    let mut msg: MSG = unsafe { zeroed() };
    while unsafe { GetMessageW(&mut msg, null_mut(), 0, 0) } > 0 {
        if let Some(app) = state(hwnd)
            && app.handle_shortcut(&msg)
        {
            continue;
        }
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    unsafe { CloseHandle(instance_mutex) };
    Ok(())
}

fn replacement_pid(args: impl IntoIterator<Item = String>) -> Result<Option<u32>, String> {
    let mut args = args.into_iter();
    let Some(argument) = args.next() else {
        return Ok(None);
    };
    if argument != "--replace-instance" {
        return Err(format!("unknown internal argument: {argument}"));
    }
    let pid = args
        .next()
        .ok_or_else(|| "--replace-instance requires a PID".to_owned())?
        .parse::<u32>()
        .map_err(|_| "--replace-instance PID is invalid".to_owned())?;
    if args.next().is_some() {
        return Err("unexpected arguments after --replace-instance PID".to_owned());
    }
    Ok(Some(pid))
}

fn restart_elevated(owner: HWND) -> Result<(), String> {
    let executable =
        std::env::current_exe().map_err(|error| format!("locate executable: {error}"))?;
    let parameters = wide(format!("--replace-instance {}", std::process::id()));
    let result = unsafe {
        ShellExecuteW(
            owner,
            wide("runas").as_ptr(),
            wide(executable).as_ptr(),
            parameters.as_ptr(),
            null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        Err("Windows did not start the elevated replacement.".to_owned())
    } else {
        unsafe { DestroyWindow(owner) };
        Ok(())
    }
}

fn main() {
    if let Err(error) = run() {
        message(null_mut(), &error, "ProcDrift", MB_ICONERROR | MB_OK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ChildGuard(Option<std::process::Child>);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn process_row(pid: u32, ppid: u32) -> ProcessRow {
        ProcessRow {
            key: ProcKey {
                pid,
                created: u64::from(pid) * 10,
            },
            ppid,
            session_id: 1,
            thread_count: 1,
            handle_count: 1,
            trust: TrustState::Unclassified,
            findings: Findings::default(),
            name: Rc::from("test.exe"),
            cpu_tenths: 0,
            memory_bytes: 0,
            private_bytes: 0,
            io_per_second: 0,
            path: Rc::from(r"C:\test.exe"),
            paused_by_procdrift: false,
        }
    }

    #[test]
    fn elevated_replacement_argument_is_strictly_parsed() {
        assert_eq!(
            replacement_pid(["--replace-instance".into(), "42".into()]).unwrap(),
            Some(42)
        );
        assert!(replacement_pid(["--replace-instance".into()]).is_err());
        assert!(replacement_pid(["--other".into()]).is_err());
    }

    #[test]
    fn protected_action_targets_are_rejected_before_opening() {
        for pid in [0, 4, std::process::id()] {
            assert!(
                perform_action(ProcKey { pid, created: 1 }, Action::Terminate)
                    .unwrap_err()
                    .contains("protected")
            );
        }
    }

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

    #[test]
    fn path_mismatch_is_never_inherited_as_a_trusted_child() {
        let all_pids = HashSet::from([10, 20]);
        let baseline_pids = HashSet::from([10]);
        assert_eq!(
            classify_evidence(
                true,
                true,
                BaselineMatch::PathMismatch,
                10,
                &all_pids,
                &baseline_pids,
            ),
            (TrustState::Unclassified, {
                let mut findings = Findings::default();
                findings.insert(Findings::DIFFERENT_PATH | Findings::LAUNCHED_BY_KNOWN);
                findings
            })
        );
        assert_eq!(
            classify_evidence(
                true,
                true,
                BaselineMatch::None,
                10,
                &all_pids,
                &baseline_pids,
            ),
            (TrustState::Unclassified, {
                let mut findings = Findings::default();
                findings.insert(Findings::NEW | Findings::LAUNCHED_BY_KNOWN);
                findings
            })
        );
    }

    #[test]
    fn captured_tree_is_transitive_pid_safe_and_excludes_the_monitor() {
        let root = process_row(10, 1);
        let grandchild = process_row(30, 20);
        let child = process_row(20, 10);
        let excluded_monitor = process_row(40, 20);
        let unrelated = process_row(50, 1);
        let stale_parent_link = process_row(5, 10);
        let rows = [
            grandchild,
            unrelated,
            stale_parent_link,
            child,
            excluded_monitor,
            root.clone(),
        ];
        assert_eq!(
            captured_process_tree(&rows, root.key, 40),
            vec![
                root.key,
                ProcKey {
                    pid: 20,
                    created: 200
                },
                ProcKey {
                    pid: 30,
                    created: 300
                },
            ]
        );
    }

    #[test]
    fn live_native_scans_reuse_bounded_identity_state() {
        let mut scanner = Scanner::new();
        let first = scanner.scan().expect("initial native scan");
        assert!(first.iter().any(|row| row.key.pid == std::process::id()));
        let initial_buffer = scanner.query_buffer.len();
        std::thread::sleep(Duration::from_millis(20));
        let second = scanner.scan().expect("follow-up native scan");
        assert!(second.iter().any(|row| row.key.pid == std::process::id()));
        assert!(scanner.identities.len() <= second.len() + 2);
        assert_eq!(scanner.query_buffer.len(), initial_buffer);
    }

    #[test]
    fn search_matches_active_process_names_regardless_of_query_case() {
        let mut scanner = Scanner::new();
        let rows = scanner.scan().expect("native scan");
        let current = rows
            .iter()
            .find(|row| row.key.pid == std::process::id())
            .expect("current test process");
        let uppercase = current.name.to_uppercase();
        let lowercase = current.name.to_lowercase();
        assert!(row_matches_search(current, uppercase.as_bytes(), None));
        assert!(row_matches_search(current, lowercase.as_bytes(), None));
        assert!(row_matches_search(
            current,
            current.key.pid.to_string().as_bytes(),
            Some(current.key.pid),
        ));
        assert!(!row_matches_search(
            current,
            b"definitely-not-a-running-process-name",
            None,
        ));
    }

    #[test]
    fn process_action_rejects_a_stale_identity() {
        let result = perform_action(
            ProcKey {
                pid: std::process::id(),
                created: 1,
            },
            Action::Suspend,
        );
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "acts only on a disposable child process"]
    fn disposable_process_suspend_resume_and_terminate_work() {
        let child = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "timeout /t 30 /nobreak >NUL"])
            .spawn()
            .expect("spawn disposable child");
        let pid = child.id();
        let mut child = ChildGuard(Some(child));
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        assert!(!handle.is_null(), "open disposable child");
        let created = process_created(handle).expect("query disposable child identity");
        unsafe { CloseHandle(handle) };
        let key = ProcKey { pid, created };

        perform_action(key, Action::Suspend).expect("suspend disposable child");
        perform_action(key, Action::Resume).expect("resume disposable child");
        perform_action(key, Action::Terminate).expect("terminate disposable child");
        child
            .0
            .as_mut()
            .expect("child guard")
            .wait()
            .expect("reap disposable child");
        child.0 = None;
    }

    #[test]
    #[ignore = "manual live performance measurement"]
    fn benchmark_native_scanner() {
        let mut scanner = Scanner::new();
        let cold_started = Instant::now();
        let cold = scanner.scan().expect("cold native scan");
        let cold_ms = cold_started.elapsed().as_secs_f64() * 1000.0;
        let mut samples = Vec::with_capacity(200);
        for _ in 0..200 {
            let started = Instant::now();
            let rows = scanner.scan().expect("profiled native scan");
            assert!(!rows.is_empty());
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        samples.sort_by(f64::total_cmp);
        let median = samples[samples.len() / 2];
        let p95 = samples[samples.len() * 95 / 100];
        assert!(median <= 3.0, "scan median {median:.3} ms exceeds 3 ms");
        assert!(p95 <= 5.0, "scan p95 {p95:.3} ms exceeds 5 ms");
        println!(
            "processes={} cold_ms={cold_ms:.3} median_ms={median:.3} p95_ms={p95:.3} identities={} buffer_kib={}",
            cold.len(),
            scanner.identities.len(),
            scanner.query_buffer.len() / 1024,
        );
    }
}
