//! Reading the process list and turning it into rows.
//!
//! The scan is on a one-second timer, so everything here reuses its buffers:
//! the query buffer, the identity cache, and the counter maps are all owned by
//! `Scanner` and cleared rather than reallocated.

use crate::activity::{ActivityTracker, ProcessKey as ActivityKey};
use crate::autostart::AutostartIndex;
use crate::baseline::{Baseline, BaselineMatch, normalize_path};
use crate::model::{self, EvidenceRow, Findings, TrustState};
use crate::win32::{NtQuerySystemInformation, SystemProcessInformation};
use std::collections::{HashMap, HashSet};
use std::mem::{size_of, zeroed};
use std::rc::Rc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ProcKey {
    pub(crate) pid: u32,
    pub(crate) created: u64,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Counters {
    pub(crate) cpu_100ns: u64,
    pub(crate) io_bytes: u64,
}

#[derive(Clone)]
pub(crate) struct Identity {
    pub(crate) name: Rc<str>,
    pub(crate) normalized_name: Rc<str>,
    pub(crate) path: Rc<str>,
    pub(crate) normalized_path: Rc<str>,
    pub(crate) accessible: bool,
}

#[derive(Clone)]
pub(crate) struct RawProcess {
    pub(crate) key: ProcKey,
    pub(crate) ppid: u32,
    pub(crate) session_id: u32,
    pub(crate) thread_count: u32,
    pub(crate) handle_count: u32,
    pub(crate) identity: Rc<Identity>,
    pub(crate) memory_bytes: u64,
    pub(crate) private_bytes: u64,
    pub(crate) counters: Counters,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ProcessRow {
    pub(crate) key: ProcKey,
    pub(crate) ppid: u32,
    pub(crate) session_id: u32,
    pub(crate) thread_count: u32,
    pub(crate) handle_count: u32,
    pub(crate) trust: TrustState,
    pub(crate) findings: Findings,
    pub(crate) name: Rc<str>,
    pub(crate) cpu_tenths: u32,
    pub(crate) memory_bytes: u64,
    pub(crate) private_bytes: u64,
    pub(crate) io_per_second: u64,
    pub(crate) path: Rc<str>,
    pub(crate) paused_by_procdrift: bool,
}

pub(crate) struct Scanner {
    pub(crate) previous: HashMap<ProcKey, Counters>,
    pub(crate) counter_scratch: HashMap<ProcKey, Counters>,
    pub(crate) identities: HashMap<ProcKey, Rc<Identity>>,
    pub(crate) all_pids: HashSet<u32>,
    pub(crate) baseline_pids: HashSet<u32>,
    pub(crate) baseline_matches: Vec<BaselineMatch>,
    pub(crate) query_buffer: Vec<u8>,
    pub(crate) last_scan: Option<Instant>,
    pub(crate) logical_processors: u32,
    pub(crate) baseline: Baseline,
    /// Built once. Rebuilding it costs several hundred registry reads, which
    /// must not happen on the one-second refresh timer.
    pub(crate) autostart: AutostartIndex,
    pub(crate) activity: ActivityTracker,
    pub(crate) started: Instant,
    pub(crate) paused: HashSet<ProcKey>,
}

impl Scanner {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn scan(&mut self) -> Result<Vec<ProcessRow>, String> {
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

pub(crate) fn classify_evidence(
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

pub(crate) fn apply_live_findings(
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

pub(crate) fn primary_finding(row: &ProcessRow) -> &'static str {
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

pub(crate) fn legacy_category(row: &ProcessRow) -> &'static str {
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

pub(crate) fn filetime_value(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

pub(crate) fn query_process_path(handle: HANDLE) -> String {
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

pub(crate) fn query_identity(pid: u32, name: Rc<str>) -> Rc<Identity> {
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

pub(crate) fn enumerate_processes(
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

pub(crate) fn risk_rank(row: &ProcessRow) -> u8 {
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

pub(crate) fn cmp_ascii_case_insensitive(left: &str, right: &str) -> std::cmp::Ordering {
    left.bytes()
        .map(|byte| byte.to_ascii_lowercase())
        .cmp(right.bytes().map(|byte| byte.to_ascii_lowercase()))
}

pub(crate) fn contains_ascii_case_insensitive(haystack: &str, needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack.as_bytes().windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
}

pub(crate) fn row_matches_search(row: &ProcessRow, query: &[u8], query_pid: Option<u32>) -> bool {
    query.is_empty()
        || contains_ascii_case_insensitive(&row.name, query)
        || contains_ascii_case_insensitive(&row.path, query)
        || contains_ascii_case_insensitive(legacy_category(row), query)
        || query_pid == Some(row.key.pid)
}

#[cfg(test)]
mod tests {
    use super::*;

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
