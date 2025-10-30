use winresource::WindowsResource;

fn main() {
    if cfg!(target_os = "windows") {
        WindowsResource::new()
            .set_icon("CompilerFwCtl.ico")
            .set_version_info(winresource::VersionInfo::PRODUCTVERSION, 0x01000200)
            .set_version_info(winresource::VersionInfo::FILEVERSION, 0x01000200)
            .set("ProductName", "CompilerFwCtl")
            .set("FileDescription", "Portable Firewall Control")
            .set("CompanyName", "How Dumb, LLC")
            .set("LegalCopyright", "Copyleft (C) daemon.devin")
            .compile()
            .unwrap();
    }
}