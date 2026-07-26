//! Authenticode verification for a single executable.
//!
//! Two things matter for a process list. First, most Windows system binaries
//! carry no embedded signature at all — they are covered by a security catalog,
//! so an embedded-only check reports the majority of a clean machine as
//! "Unsigned" and trains the reader to ignore the column. This module resolves
//! the catalog before falling back to the embedded signature. Second, the
//! result must distinguish "no signature" from "signature present but broken";
//! collapsing those loses the only interesting case.
//!
//! Verification is offline. Revocation checking is disabled and URL retrieval is
//! cache-only, so a selection never blocks the caller on a network round trip.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows_sys::Win32::Security::Cryptography::{
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows_sys::core::GUID;

/// `WINTRUST_ACTION_GENERIC_VERIFY_V2`.
const GENERIC_VERIFY_V2: GUID = GUID::from_u128(0x00aac56b_cd44_11d0_8cc2_00c04fc295ee);

const WTD_UI_NONE: u32 = 2;
const WTD_REVOKE_NONE: u32 = 0;
const WTD_CHOICE_FILE: u32 = 1;
const WTD_CHOICE_CATALOG: u32 = 2;
const WTD_STATEACTION_VERIFY: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;
const WTD_SAFER_FLAG: u32 = 0x100;
const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x1000;

// HRESULTs that WinVerifyTrust returns as i32.
const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B0003u32 as i32;
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B0001u32 as i32;
const TRUST_E_BAD_DIGEST: i32 = 0x80096010u32 as i32;
const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800B0111u32 as i32;
const TRUST_E_SUBJECT_NOT_TRUSTED: i32 = 0x800B0004u32 as i32;
const CERT_E_EXPIRED: i32 = 0x800B0101u32 as i32;
const CERT_E_UNTRUSTEDROOT: i32 = 0x800B0109u32 as i32;
const CERT_E_CHAINING: i32 = 0x800B010Au32 as i32;
const CERT_E_REVOKED: i32 = 0x800B010Cu32 as i32;
const CRYPT_E_SECURITY_SETTINGS: i32 = 0x80092026u32 as i32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureState {
    /// A signature verified and its certificate chain reached a root Windows
    /// trusts, as of the moment the file on disk was checked. Revocation is not
    /// checked, so a revoked certificate still lands here, and a trusted
    /// publisher is not the same thing as benign code.
    Trusted,
    /// No signature is present, embedded or catalogued.
    Unsigned,
    /// A signature is present but does not verify: tampered, expired,
    /// distrusted, or chaining to an untrusted root.
    Invalid,
    /// Verification could not be completed, so nothing is claimed either way.
    Unavailable,
}

impl SignatureState {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Trusted => "Trusted",
            Self::Unsigned => "Unsigned",
            Self::Invalid => "Invalid",
            Self::Unavailable => "Unavailable",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Verdict {
    pub state: SignatureState,
    pub signer: Option<String>,
}

impl Verdict {
    const fn unavailable() -> Self {
        Self {
            state: SignatureState::Unavailable,
            signer: None,
        }
    }
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

/// Owns a file handle so every early return closes it.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Owns the catalog administrator context.
struct CatalogAdmin(isize);

impl Drop for CatalogAdmin {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { CryptCATAdminReleaseContext(self.0, 0) };
        }
    }
}

/// Verify `path` and describe the result.
///
/// Never panics and never blocks on the network. An unreadable or missing file
/// yields `Unavailable` rather than `Unsigned`, because absence of evidence is
/// not evidence of an unsigned binary.
pub fn verify(path: &Path) -> Verdict {
    if path.as_os_str().is_empty() {
        return Verdict::unavailable();
    }
    let wide_path = wide(path);

    // FILE_SHARE_DELETE matters: a running executable may be pending deletion,
    // and omitting it turns an interesting file into an unreadable one.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Verdict::unavailable();
    }
    let handle = OwnedHandle(handle);

    if let Some(verdict) = verify_via_catalog(&wide_path, &handle) {
        return verdict;
    }
    verify_embedded(&wide_path)
}

/// Resolve the security catalog covering this file, if any, and verify against
/// it. Returns `None` when the file is not catalogued, which is the signal to
/// fall back to an embedded signature.
fn verify_via_catalog(wide_path: &[u16], file: &OwnedHandle) -> Option<Verdict> {
    let mut admin: isize = 0;
    let algorithm = wide("SHA256");
    let acquired = unsafe {
        CryptCATAdminAcquireContext2(
            &mut admin,
            std::ptr::null(),
            algorithm.as_ptr(),
            std::ptr::null(),
            0,
        )
    };
    if acquired == 0 || admin == 0 {
        return None;
    }
    let admin = CatalogAdmin(admin);

    let mut hash_length: u32 = 0;
    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin.0,
            file.0,
            &mut hash_length,
            std::ptr::null_mut(),
            0,
        )
    };
    if hash_length == 0 {
        return None;
    }
    let mut hash = vec![0u8; hash_length as usize];
    let hashed = unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin.0,
            file.0,
            &mut hash_length,
            hash.as_mut_ptr(),
            0,
        )
    };
    if hashed == 0 {
        return None;
    }

    let catalog = unsafe {
        CryptCATAdminEnumCatalogFromHash(
            admin.0,
            hash.as_ptr(),
            hash_length,
            0,
            std::ptr::null_mut(),
        )
    };
    if catalog == 0 {
        // Not catalogued. This is the common case for third-party software.
        return None;
    }

    let mut info = CATALOG_INFO {
        cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
        ..Default::default()
    };
    let described = unsafe { CryptCATCatalogInfoFromContext(catalog, &mut info, 0) };
    if described == 0 {
        unsafe { CryptCATAdminReleaseCatalogContext(admin.0, catalog, 0) };
        return None;
    }

    // The member tag is the file hash rendered as uppercase hex.
    let mut tag: Vec<u16> = hash
        .iter()
        .take(hash_length as usize)
        .flat_map(|byte| format!("{byte:02X}").encode_utf16().collect::<Vec<_>>())
        .collect();
    tag.push(0);

    let mut catalog_info = WINTRUST_CATALOG_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
        pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
        pcwszMemberTag: tag.as_ptr(),
        pcwszMemberFilePath: wide_path.as_ptr(),
        hMemberFile: file.0,
        pbCalculatedFileHash: hash.as_mut_ptr(),
        cbCalculatedFileHash: hash_length,
        hCatAdmin: admin.0,
        ..Default::default()
    };

    let verdict = run_verification(
        WTD_CHOICE_CATALOG,
        WINTRUST_DATA_0 {
            pCatalog: &mut catalog_info,
        },
    );

    unsafe { CryptCATAdminReleaseCatalogContext(admin.0, catalog, 0) };
    Some(verdict)
}

fn verify_embedded(wide_path: &[u16]) -> Verdict {
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide_path.as_ptr(),
        ..Default::default()
    };
    run_verification(
        WTD_CHOICE_FILE,
        WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
    )
}

/// Drive `WinVerifyTrust` once, read the signer out of the retained state, then
/// release that state. The verify/close pair must always be balanced or
/// wintrust leaks the provider chain.
fn run_verification(union_choice: u32, subject: WINTRUST_DATA_0) -> Verdict {
    let mut action = GENERIC_VERIFY_V2;
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: union_choice,
        Anonymous: subject,
        dwStateAction: WTD_STATEACTION_VERIFY,
        // The UI is suppressed by dwUIChoice above, not by these flags.
        // SAFER_FLAG is the legacy Software Restriction Policy flag that
        // wintrust callers conventionally set; cache-only retrieval is what
        // keeps this off the network.
        dwProvFlags: WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };

    let status = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (&raw mut data).cast::<std::ffi::c_void>(),
        )
    };

    let signer = if status == 0 {
        signer_name(data.hWVTStateData)
    } else {
        None
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (&raw mut data).cast::<std::ffi::c_void>(),
        )
    };

    Verdict {
        state: classify(status),
        signer,
    }
}

const fn classify(status: i32) -> SignatureState {
    match status {
        0 => SignatureState::Trusted,
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
            SignatureState::Unsigned
        }
        TRUST_E_BAD_DIGEST
        | TRUST_E_EXPLICIT_DISTRUST
        | TRUST_E_SUBJECT_NOT_TRUSTED
        | CERT_E_EXPIRED
        | CERT_E_UNTRUSTEDROOT
        | CERT_E_CHAINING
        | CERT_E_REVOKED
        | CRYPT_E_SECURITY_SETTINGS => SignatureState::Invalid,
        _ => SignatureState::Unavailable,
    }
}

/// Read the leaf certificate's display name out of a successful verification.
fn signer_name(state: HANDLE) -> Option<String> {
    if state.is_null() {
        return None;
    }
    unsafe {
        let provider = WTHelperProvDataFromStateData(state);
        if provider.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
        if signer.is_null() {
            return None;
        }
        let certificate = WTHelperGetProvCertFromChain(signer, 0);
        if certificate.is_null() || (*certificate).pCert.is_null() {
            return None;
        }

        let length = CertGetNameStringW(
            (*certificate).pCert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
        );
        // A return of 1 is just the terminating NUL, meaning no name.
        if length <= 1 {
            return None;
        }
        let mut buffer = vec![0u16; length as usize];
        let written = CertGetNameStringW(
            (*certificate).pCert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            buffer.as_mut_ptr(),
            length,
        );
        if written <= 1 {
            return None;
        }
        let name = String::from_utf16_lossy(&buffer[..(written - 1) as usize]);
        (!name.trim().is_empty()).then_some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_and_empty_paths_are_unavailable_not_unsigned() {
        assert_eq!(verify(Path::new("")).state, SignatureState::Unavailable);
        assert_eq!(
            verify(Path::new(r"C:\does\not\exist\nowhere.exe")).state,
            SignatureState::Unavailable
        );
    }

    #[test]
    fn status_codes_separate_missing_signatures_from_broken_ones() {
        assert_eq!(classify(0), SignatureState::Trusted);
        assert_eq!(classify(TRUST_E_NOSIGNATURE), SignatureState::Unsigned);
        assert_eq!(classify(TRUST_E_BAD_DIGEST), SignatureState::Invalid);
        assert_eq!(classify(CERT_E_UNTRUSTEDROOT), SignatureState::Invalid);
        // An unmapped failure must not be reported as either extreme.
        assert_eq!(classify(0x7FFF_FFFF), SignatureState::Unavailable);
    }

    #[test]
    fn a_catalog_signed_system_binary_verifies() {
        // Every supported Windows install has a signed kernel32. If this fails,
        // catalog resolution is broken and the whole column is untrustworthy.
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let verdict = verify(
            Path::new(&system)
                .join("System32")
                .join("kernel32.dll")
                .as_path(),
        );
        assert_eq!(verdict.state, SignatureState::Trusted);
        assert!(
            verdict
                .signer
                .as_deref()
                .is_some_and(|signer| signer.contains("Microsoft")),
            "expected a Microsoft signer, got {:?}",
            verdict.signer
        );
    }
}
