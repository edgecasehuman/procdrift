//! Control identifiers and the thin wrappers over the Win32 calls the window
//! makes constantly.
//!
//! The list view is updated cell by cell rather than rebuilt, so a refresh does
//! not scroll the user's selection out from under them.

use crate::process::{ProcessRow, legacy_category};
use crate::win32::{
    CF_UNICODETEXT, CloseClipboard, EmptyClipboard, GMEM_MOVEABLE, GlobalAlloc, GlobalFree,
    GlobalLock, GlobalUnlock, LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETITEMTEXTW, OpenClipboard,
    SetClipboardData, wide,
};
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::UI::Controls::{
    LVCF_FMT, LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT, LVITEMW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateWindowExW, GetWindowTextLengthW, GetWindowTextW, HMENU, MF_GRAYED,
    MF_STRING, MessageBoxW, SendMessageW, SetWindowTextW, WM_APP, WS_CHILD, WS_TABSTOP, WS_VISIBLE,
};

pub(crate) const ID_SEARCH: usize = 101;
pub(crate) const ID_LIST: usize = 102;
pub(crate) const ID_REFRESH: usize = 103;
pub(crate) const ID_END: usize = 104;
pub(crate) const ID_SUSPEND: usize = 105;
pub(crate) const ID_RESUME: usize = 106;
pub(crate) const ID_DETAILS: usize = 107;
pub(crate) const ID_RECORD_BASELINE: usize = 108;
pub(crate) const ID_ADD_BASELINE: usize = 109;
pub(crate) const ID_REMOVE_BASELINE: usize = 110;
pub(crate) const ID_FILTER_REVIEW: usize = 120;
pub(crate) const ID_FILTER_NEW: usize = 121;
pub(crate) const ID_FILTER_HEAVY: usize = 122;
pub(crate) const ID_FILTER_RESTARTING: usize = 123;
pub(crate) const ID_FILTER_KNOWN: usize = 124;
pub(crate) const ID_FILTER_ALL: usize = 125;
pub(crate) const ID_MENU_DETAILS: usize = 201;
pub(crate) const ID_MENU_COPY: usize = 202;
pub(crate) const ID_MENU_OPEN_LOCATION: usize = 203;
pub(crate) const ID_MENU_END_TREE: usize = 204;
pub(crate) const ID_MENU_END: usize = 205;
pub(crate) const ID_MENU_SUSPEND: usize = 206;
pub(crate) const ID_MENU_RESUME: usize = 207;
pub(crate) const ID_MENU_TRUST: usize = 208;
pub(crate) const ID_MENU_UNTRUST: usize = 209;
pub(crate) const ID_MENU_ACTIVITY: usize = 210;
pub(crate) const TIMER_SCAN: usize = 1;
pub(crate) const WM_REFRESH: u32 = WM_APP + 1;
pub(crate) const WM_DETAILS_READY: u32 = WM_APP + 2;

pub(crate) fn create_control(parent: HWND, class: &str, text: &str, id: usize) -> HWND {
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

pub(crate) fn insert_column(list: HWND, index: i32, title: &str, width: i32, format: i32) {
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

pub(crate) fn insert_row(list: HWND, index: i32, row: &ProcessRow) {
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

pub(crate) fn static_cells_changed(old: &ProcessRow, new: &ProcessRow) -> bool {
    old.trust != new.trust
        || old.findings != new.findings
        || old.name != new.name
        || old.key.pid != new.key.pid
        || old.path != new.path
}

pub(crate) fn dynamic_cells_changed(old: &ProcessRow, new: &ProcessRow) -> bool {
    old.cpu_tenths != new.cpu_tenths
        || old.memory_bytes != new.memory_bytes
        || old.io_per_second != new.io_per_second
}

pub(crate) fn update_static_cells(list: HWND, index: i32, old: &ProcessRow, new: &ProcessRow) {
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

pub(crate) fn update_dynamic_cells(list: HWND, index: i32, old: &ProcessRow, new: &ProcessRow) {
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

pub(crate) fn set_cell(list: HWND, row: i32, column: i32, text: &str) {
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

pub(crate) fn format_bytes(value: u64) -> String {
    if value >= 1 << 30 {
        format!("{:.1} GB", value as f64 / (1_u64 << 30) as f64)
    } else {
        format!("{:.1} MB", value as f64 / (1_u64 << 20) as f64)
    }
}

pub(crate) fn format_rate(value: u64) -> String {
    if value >= 1 << 20 {
        format!("{:.1} MB/s", value as f64 / (1_u64 << 20) as f64)
    } else if value >= 1 << 10 {
        format!("{:.1} KB/s", value as f64 / (1_u64 << 10) as f64)
    } else {
        format!("{value} B/s")
    }
}

pub(crate) fn window_text(hwnd: HWND) -> String {
    let length = unsafe { GetWindowTextLengthW(hwnd) };
    if length <= 0 {
        return String::new();
    }
    let mut buffer = vec![0_u16; length as usize + 1];
    let copied = unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32) };
    String::from_utf16_lossy(&buffer[..copied.max(0) as usize])
}

pub(crate) fn set_text(hwnd: HWND, text: &str) {
    unsafe { SetWindowTextW(hwnd, wide(text).as_ptr()) };
}

pub(crate) fn message(hwnd: HWND, text: &str, title: &str, flags: u32) -> i32 {
    unsafe { MessageBoxW(hwnd, wide(text).as_ptr(), wide(title).as_ptr(), flags) }
}

pub(crate) fn append_menu_item(menu: HMENU, id: usize, text: &str, disabled: bool) {
    let flags = MF_STRING | if disabled { MF_GRAYED } else { 0 };
    unsafe { AppendMenuW(menu, flags, id, wide(text).as_ptr()) };
}

pub(crate) fn set_clipboard_text(owner: HWND, text: &str) -> Result<(), String> {
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
