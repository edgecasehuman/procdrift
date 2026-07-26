fn main() {
    println!("cargo:rerun-if-changed=ProcDrift.manifest");
    let mut resource = winresource::WindowsResource::new();
    resource
        .set_manifest_file("ProcDrift.manifest")
        .set("FileDescription", "ProcDrift")
        .set("ProductName", "ProcDrift")
        .set("CompanyName", "ProcDrift")
        .set("LegalCopyright", "Copyright © 2026 ProcDrift")
        .set("OriginalFilename", "ProcDrift.exe");
    resource
        .compile()
        .expect("compile ProcDrift Windows resources");
}
