//! The three things `ProcDrift` can do to a process, and the checks that run
//! before any of them.
//!
//! Every action re-verifies the creation time, so a recycled PID cannot be hit
//! by a click aimed at the process that used to hold it.

use crate::process::{ProcKey, ProcessRow, filetime_value};
use crate::win32::{IsProcessCritical, NtResumeProcess, NtSuspendProcess};
use std::collections::HashMap;
use std::mem::zeroed;
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    TerminateProcess,
};

#[derive(Clone, Copy)]
pub(crate) enum Action {
    Terminate,
    Suspend,
    Resume,
}

pub(crate) fn process_created(handle: HANDLE) -> Option<u64> {
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

pub(crate) fn perform_action(expected: ProcKey, action: Action) -> Result<(), String> {
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

pub(crate) fn captured_process_tree(
    rows: &[ProcessRow],
    root: ProcKey,
    excluded_pid: u32,
) -> Vec<ProcKey> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Findings, TrustState};
    use std::rc::Rc;

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
}
