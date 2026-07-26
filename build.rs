fn main() {
    println!("cargo:rerun-if-changed=ProcDrift.manifest");
    let mut resource = winresource::WindowsResource::new();
    resource
        .set_manifest_file("ProcDrift.manifest")
        .set("FileDescription", "ProcDrift")
        .set("ProductName", "ProcDrift")
        .set("CompanyName", "ProcDrift")
        // Matches LICENSE. The "contributors" wording is deliberate, so the
        // binary's file properties should not quietly drop it.
        .set("LegalCopyright", "Copyright © 2026 ProcDrift contributors")
        .set("OriginalFilename", "ProcDrift.exe");
    resource
        .compile()
        .expect("compile ProcDrift Windows resources");
}
