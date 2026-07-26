//! The window: its state, the controls it owns, and the message loop's target.
//!
//! `AppState` is heap-allocated once in `WM_CREATE`, parked in `GWLP_USERDATA`,
//! and dropped in `WM_NCDESTROY`. `state` is the only way back to it, and it is
//! deliberately the only place that reconstitutes that pointer.

use crate::action::{Action, captured_process_tree, perform_action};
use crate::process::{
    ProcKey, ProcessRow, Scanner, cmp_ascii_case_insensitive, legacy_category, primary_finding,
    risk_rank, row_matches_search,
};
use crate::ui::*;
use crate::win32::*;
use crate::{activity, details, model, restart_elevated};
use model::{EvidenceRow, Findings, TrustState};
use std::collections::HashMap;
use std::mem::zeroed;
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::time::Instant;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, DEFAULT_GUI_FONT, DeleteObject, FW_NORMAL, GetStockObject, HFONT,
};
use windows_sys::Win32::UI::Controls::{
    LVCFMT_LEFT, LVCFMT_RIGHT, LVITEMW, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT,
    LVS_EX_GRIDLINES, LVS_REPORT, LVS_SHOWSELALWAYS, WC_LISTVIEWW,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetFocus, GetKeyState, SetFocus};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CREATESTRUCTW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
    DestroyWindow, EN_CHANGE, ES_AUTOHSCROLL, GWLP_USERDATA, GetClientRect, GetCursorPos,
    GetWindowLongPtrW, HMENU, IsIconic, KillTimer, MB_ICONERROR, MB_ICONWARNING, MB_OK, MB_YESNO,
    MF_SEPARATOR, MSG, MoveWindow, PostMessageW, PostQuitMessage, SIZE_MINIMIZED, SW_SHOWNORMAL,
    SendMessageW, SetTimer, SetWindowLongPtrW, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu,
    WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_KEYDOWN, WM_NCDESTROY, WM_NOTIFY, WM_SETFONT,
    WM_SIZE, WM_TIMER, WS_BORDER, WS_CHILD, WS_EX_CLIENTEDGE, WS_TABSTOP, WS_VISIBLE,
};

pub(crate) struct AppState {
    pub(crate) hwnd: HWND,
    pub(crate) search: HWND,
    pub(crate) list: HWND,
    pub(crate) status: HWND,
    pub(crate) refresh: HWND,
    pub(crate) end: HWND,
    pub(crate) suspend: HWND,
    pub(crate) resume: HWND,
    pub(crate) details: HWND,
    pub(crate) record_baseline: HWND,
    pub(crate) add_baseline: HWND,
    pub(crate) remove_baseline: HWND,
    pub(crate) filters: [HWND; 6],
    pub(crate) font: HFONT,
    pub(crate) scanner: Scanner,
    pub(crate) rows: Vec<ProcessRow>,
    pub(crate) displayed: Vec<ProcessRow>,
    pub(crate) rendered: Vec<ProcessRow>,
    pub(crate) position_scratch: HashMap<ProcKey, usize>,
    pub(crate) sort_column: usize,
    pub(crate) sort_descending: bool,
    pub(crate) search_text: String,
    pub(crate) timer_active: bool,
    pub(crate) active_filter: model::Filter,
    pub(crate) detail_worker: Option<details::DetailWorker>,
    pub(crate) onboarding_done: bool,
}

impl Drop for AppState {
    fn drop(&mut self) {
        if !self.font.is_null() {
            unsafe { DeleteObject(self.font.cast()) };
        }
    }
}

impl AppState {
    pub(crate) unsafe fn create(hwnd: HWND) -> Box<Self> {
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

    pub(crate) fn resize(&self) {
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

    pub(crate) fn refresh(&mut self) {
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

    pub(crate) fn show_onboarding_if_needed(&mut self) {
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

    pub(crate) fn apply_filter_sort(&mut self, force_resort: bool) {
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

    pub(crate) fn render(&mut self, selected_key: Option<ProcKey>) {
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

    pub(crate) fn update_search(&mut self) {
        self.search_text = window_text(self.search);
        self.apply_filter_sort(true);
    }

    pub(crate) fn set_filter(&mut self, filter: model::Filter) {
        self.active_filter = filter;
        self.apply_filter_sort(true);
    }

    pub(crate) fn set_minimized(&mut self, minimized: bool) {
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

    pub(crate) fn selected_key(&self) -> Option<ProcKey> {
        let index =
            unsafe { SendMessageW(self.list, LVM_GETNEXTITEM, usize::MAX, LVNI_SELECTED) } as isize;
        if index < 0 {
            None
        } else {
            self.rendered.get(index as usize).map(|row| row.key)
        }
    }

    pub(crate) fn selected(&self) -> Option<ProcessRow> {
        let key = self.selected_key()?;
        self.displayed.iter().find(|row| row.key == key).cloned()
    }

    pub(crate) fn select_index(&self, index: usize) {
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

    pub(crate) fn context_menu(&mut self) {
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

    pub(crate) fn dispatch_menu(&mut self, command: usize) {
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

    pub(crate) fn recent_activity(&self) {
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

    pub(crate) fn copy_selected(&self) {
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

    pub(crate) fn open_selected_location(&self) {
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

    pub(crate) fn end_selected_tree(&mut self) {
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

    pub(crate) fn details(&mut self) {
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

    pub(crate) fn detail_ready(&mut self, result: details::DetailResult) {
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

    pub(crate) fn record_baseline(&mut self) {
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

    pub(crate) fn add_selected_to_baseline(&mut self) {
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

    pub(crate) fn remove_selected_from_baseline(&mut self) {
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

    pub(crate) fn action(&mut self, kind: Action) {
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

    pub(crate) fn handle_shortcut(&mut self, message: &MSG) -> bool {
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

pub(crate) fn state(hwnd: HWND) -> Option<&'static mut AppState> {
    let pointer = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut AppState;
    unsafe { pointer.as_mut() }
}

pub(crate) unsafe extern "system" fn window_proc(
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
