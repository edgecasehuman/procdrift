#![windows_subsystem = "windows"]

mod action;
mod activity;
mod app;
mod autostart;
mod baseline;
mod details;
mod knowledge;
mod model;
mod process;
mod signature;
mod state;
mod ui;
mod win32;

use app::{state, window_proc};
use std::mem::zeroed;
use std::ptr::{null, null_mut};
use ui::message;
use win32::{SYNCHRONIZE_ACCESS, wide};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HINSTANCE, HWND,
};
use windows_sys::Win32::Graphics::Gdi::UpdateWindow;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::{CreateMutexW, OpenProcess, WaitForSingleObject};
use windows_sys::Win32::UI::Controls::InitCommonControls;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateWindowExW, DestroyWindow, DispatchMessageW,
    GetMessageW, IDC_ARROW, LoadCursorW, MB_ICONERROR, MB_OK, MSG, RegisterClassW, SW_SHOW,
    SW_SHOWNORMAL, ShowWindow, TranslateMessage, WNDCLASSW, WS_CLIPCHILDREN, WS_OVERLAPPEDWINDOW,
};

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

// `replacement_pid` and `restart_elevated` are the two ends of one handoff:
// the elevated copy parses the argument the unelevated copy wrote. They stay in
// the same file so the `--replace-instance` spelling cannot drift on one side.
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

    #[test]
    fn elevated_replacement_argument_is_strictly_parsed() {
        assert_eq!(
            replacement_pid(["--replace-instance".into(), "42".into()]).unwrap(),
            Some(42)
        );
        assert!(replacement_pid(["--replace-instance".into()]).is_err());
        assert!(replacement_pid(["--other".into()]).is_err());
    }
}
