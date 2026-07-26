//! Raw Win32 bindings and the constants `windows-sys` does not re-export.
//!
//! Nothing here makes a decision. It exists so the rest of the crate can call
//! the platform without every module carrying its own `extern` block.

use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{HANDLE, HWND, LPARAM};

pub(crate) const LVM_FIRST: u32 = 0x1000;
pub(crate) const LVM_SETEXTENDEDLISTVIEWSTYLE: u32 = LVM_FIRST + 54;
pub(crate) const LVM_INSERTCOLUMNW: u32 = LVM_FIRST + 97;
pub(crate) const LVM_INSERTITEMW: u32 = LVM_FIRST + 77;
pub(crate) const LVM_SETITEMTEXTW: u32 = LVM_FIRST + 116;
pub(crate) const LVM_DELETEALLITEMS: u32 = LVM_FIRST + 9;
pub(crate) const LVM_GETNEXTITEM: u32 = LVM_FIRST + 12;
pub(crate) const LVM_GETTOPINDEX: u32 = LVM_FIRST + 39;
pub(crate) const LVM_GETCOUNTPERPAGE: u32 = LVM_FIRST + 40;
pub(crate) const LVM_SETITEMSTATE: u32 = LVM_FIRST + 43;
pub(crate) const LVNI_SELECTED: isize = 0x0002;
pub(crate) const LVIS_FOCUSED: u32 = 0x0001;
pub(crate) const LVIS_SELECTED: u32 = 0x0002;
pub(crate) const LVN_FIRST: i32 = -100;
pub(crate) const LVN_COLUMNCLICK: i32 = LVN_FIRST - 8;
pub(crate) const LVN_ITEMACTIVATE: i32 = LVN_FIRST - 14;
pub(crate) const NM_RCLICK: i32 = -5;
pub(crate) const BN_CLICKED: usize = 0;
pub(crate) const CF_UNICODETEXT: u32 = 13;
pub(crate) const GMEM_MOVEABLE: u32 = 0x0002;
pub(crate) const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
pub(crate) const VK_CONTROL_KEY: i32 = 0x11;
pub(crate) const VK_ESCAPE_KEY: usize = 0x1B;
pub(crate) const VK_ENTER_KEY: usize = 0x0D;
pub(crate) const VK_SPACE_KEY: usize = 0x20;
pub(crate) const VK_DELETE_KEY: usize = 0x2E;
pub(crate) const VK_F2_KEY: usize = 0x71;
pub(crate) const VK_F5_KEY: usize = 0x74;

#[link(name = "ntdll")]
unsafe extern "system" {
    pub(crate) fn NtQuerySystemInformation(
        class: u32,
        buffer: *mut c_void,
        length: u32,
        return_length: *mut u32,
    ) -> i32;
    pub(crate) fn NtSuspendProcess(process: HANDLE) -> i32;
    pub(crate) fn NtResumeProcess(process: HANDLE) -> i32;
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct SystemTime {
    pub(crate) year: u16,
    pub(crate) month: u16,
    pub(crate) day_of_week: u16,
    pub(crate) day: u16,
    pub(crate) hour: u16,
    pub(crate) minute: u16,
    pub(crate) second: u16,
    pub(crate) milliseconds: u16,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    pub(crate) fn GetSystemTime(system_time: *mut SystemTime);
    pub(crate) fn IsProcessCritical(process: HANDLE, critical: *mut i32) -> i32;
    pub(crate) fn GlobalAlloc(flags: u32, bytes: usize) -> HANDLE;
    pub(crate) fn GlobalFree(memory: HANDLE) -> HANDLE;
    pub(crate) fn GlobalLock(memory: HANDLE) -> *mut c_void;
    pub(crate) fn GlobalUnlock(memory: HANDLE) -> i32;
}

#[link(name = "user32")]
unsafe extern "system" {
    pub(crate) fn CloseClipboard() -> i32;
    pub(crate) fn EmptyClipboard() -> i32;
    pub(crate) fn OpenClipboard(owner: HWND) -> i32;
    pub(crate) fn SetClipboardData(format: u32, memory: HANDLE) -> HANDLE;
}

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Clone, Copy)]
pub(crate) struct UnicodeString {
    pub(crate) Length: u16,
    pub(crate) MaximumLength: u16,
    pub(crate) Buffer: *const u16,
}

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Clone, Copy)]
pub(crate) struct SystemProcessInformation {
    pub(crate) NextEntryOffset: u32,
    pub(crate) NumberOfThreads: u32,
    pub(crate) WorkingSetPrivateSize: i64,
    pub(crate) HardFaultCount: u32,
    pub(crate) NumberOfThreadsHighWatermark: u32,
    pub(crate) CycleTime: u64,
    pub(crate) CreateTime: i64,
    pub(crate) UserTime: i64,
    pub(crate) KernelTime: i64,
    pub(crate) ImageName: UnicodeString,
    pub(crate) BasePriority: i32,
    pub(crate) UniqueProcessId: usize,
    pub(crate) InheritedFromUniqueProcessId: usize,
    pub(crate) HandleCount: u32,
    pub(crate) SessionId: u32,
    pub(crate) UniqueProcessKey: usize,
    pub(crate) PeakVirtualSize: usize,
    pub(crate) VirtualSize: usize,
    pub(crate) PageFaultCount: u32,
    pub(crate) PeakWorkingSetSize: usize,
    pub(crate) WorkingSetSize: usize,
    pub(crate) QuotaPeakPagedPoolUsage: usize,
    pub(crate) QuotaPagedPoolUsage: usize,
    pub(crate) QuotaPeakNonPagedPoolUsage: usize,
    pub(crate) QuotaNonPagedPoolUsage: usize,
    pub(crate) PagefileUsage: usize,
    pub(crate) PeakPagefileUsage: usize,
    pub(crate) PrivatePageCount: usize,
    pub(crate) ReadOperationCount: i64,
    pub(crate) WriteOperationCount: i64,
    pub(crate) OtherOperationCount: i64,
    pub(crate) ReadTransferCount: i64,
    pub(crate) WriteTransferCount: i64,
    pub(crate) OtherTransferCount: i64,
}

#[repr(C)]
pub(crate) struct Nmlistview {
    pub(crate) hdr: windows_sys::Win32::UI::Controls::NMHDR,
    pub(crate) item: i32,
    pub(crate) sub_item: i32,
    pub(crate) new_state: u32,
    pub(crate) old_state: u32,
    pub(crate) changed: u32,
    pub(crate) point: windows_sys::Win32::Foundation::POINT,
    pub(crate) lparam: LPARAM,
}

pub(crate) fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
