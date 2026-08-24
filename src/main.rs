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
    GetMessageW, IDC_ARROW, LoadCursorW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MSG,
    RegisterClassW, SW_SHOW, SW_SHOWNORMAL, ShowWindow, TranslateMessage, WNDCLASSW,
    WS_CLIPCHILDREN, WS_OVERLAPPEDWINDOW,
};

fn run() -> Result<(), String> {
    // Reported through a dialog rather than stdout. This is a windows-subsystem
    // binary, so it is never attached to the console that launched it and
    // anything printed would go nowhere; a dialog is the only channel that
    // reaches the person who typed the argument.
    let replaces = match invocation(std::env::args().skip(1))? {
        Invocation::Report(text) => {
            message(null_mut(), &text, "ProcDrift", MB_ICONINFORMATION | MB_OK);
            return Ok(());
        }
        Invocation::Open(pid) => pid,
    };
    if let Some(pid) = replaces {
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
    let title = wide(version_line());
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

/// What the command line asked this process to do.
#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    /// Open the window. `Some(pid)` is an elevated copy waiting on the
    /// unelevated one it replaces.
    Open(Option<u32>),
    /// Show one dialog and exit without opening a window.
    Report(String),
}

/// The name and version, in one line. This is the window title as well as the
/// answer to `--version`, so a screenshot of the running program identifies the
/// build as precisely as the command line does. The version is compiled in from
/// the manifest, which the release workflow has already checked against the tag.
fn version_line() -> String {
    format!("ProcDrift {}", env!("CARGO_PKG_VERSION"))
}

/// There are no options that change how `ProcDrift` runs -- everything happens in
/// the window -- so this exists to name the build and to make a mistyped
/// argument recoverable rather than a bare error.
fn help_text() -> String {
    let version = version_line();
    [
        version.as_str(),
        "",
        "Compares the processes running now against a reference snapshot taken",
        "when the machine was known-good, and shows what changed.",
        "",
        "Usage: ProcDrift [--version | --help]",
        "",
        "No option changes how it runs: it opens one window, and everything is",
        "done from there. The keys are listed in the README.",
        "",
        "State is kept in %LOCALAPPDATA%\\ProcDrift\\state.json, and only after",
        "you answer the first-run prompt, capture a snapshot, or change an allowance.",
    ]
    .join("\n")
}

// `invocation` and `restart_elevated` are the two ends of one handoff: the
// elevated copy parses the argument the unelevated copy wrote. They stay in the
// same file so the `--replace-instance` spelling cannot drift on one side.
//
// Parsing stays strict. `--replace-instance` makes this process wait on a PID
// another one named, so an argument list that is not exactly understood is
// refused rather than guessed at.
fn invocation(args: impl IntoIterator<Item = String>) -> Result<Invocation, String> {
    let mut args = args.into_iter();
    let Some(argument) = args.next() else {
        return Ok(Invocation::Open(None));
    };
    let report = match argument.as_str() {
        "--version" | "-v" => Some(version_line()),
        "--help" | "-h" | "/?" => Some(help_text()),
        _ => None,
    };
    if let Some(text) = report {
        if args.next().is_some() {
            return Err(format!("{argument} takes no further arguments."));
        }
        return Ok(Invocation::Report(text));
    }
    if argument != "--replace-instance" {
        return Err(format!(
            "Unrecognized argument: {argument}\n\nRun ProcDrift --help for the ones it accepts."
        ));
    }
    let pid = args
        .next()
        .ok_or_else(|| "--replace-instance requires a PID".to_owned())?
        .parse::<u32>()
        .map_err(|_| "--replace-instance PID is invalid".to_owned())?;
    if args.next().is_some() {
        return Err("unexpected arguments after --replace-instance PID".to_owned());
    }
    Ok(Invocation::Open(Some(pid)))
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
            invocation(["--replace-instance".into(), "42".into()]).unwrap(),
            Invocation::Open(Some(42))
        );
        assert!(invocation(["--replace-instance".into()]).is_err());
        assert!(invocation(["--replace-instance".into(), "x".into()]).is_err());
        assert!(
            invocation(["--replace-instance".into(), "42".into(), "43".into()]).is_err(),
            "a trailing argument must not be ignored"
        );
        assert!(invocation(["--other".into()]).is_err());
    }

    #[test]
    fn no_arguments_opens_the_window() {
        assert_eq!(
            invocation(Vec::<String>::new()).unwrap(),
            Invocation::Open(None)
        );
    }

    #[test]
    fn version_and_help_are_answered_instead_of_refused() {
        // Every one of these used to reach the unknown-argument branch and
        // produce an error dialog, which is the wrong answer to a fair question.
        assert_eq!(
            invocation(["--version".into()]).unwrap(),
            Invocation::Report(version_line())
        );
        assert_eq!(
            invocation(["-v".into()]).unwrap(),
            Invocation::Report(version_line())
        );
        for spelling in ["--help", "-h", "/?"] {
            let Ok(Invocation::Report(text)) = invocation([spelling.to_owned()]) else {
                panic!("{spelling} was not answered");
            };
            assert!(text.starts_with(&version_line()), "{spelling}: {text}");
            assert!(text.contains("--version"), "{spelling} omits --version");
        }
        // Strictness survives: these are still parsed, not merely recognized.
        assert!(invocation(["--version".into(), "extra".into()]).is_err());
        assert!(invocation(["--help".into(), "extra".into()]).is_err());
    }

    #[test]
    fn the_reported_version_is_the_compiled_in_one() {
        // The window title and --version are the same string, so a screenshot
        // and a command line cannot disagree about which build is running.
        assert!(version_line().ends_with(env!("CARGO_PKG_VERSION")));
        assert!(help_text().starts_with(&version_line()));
    }
}
