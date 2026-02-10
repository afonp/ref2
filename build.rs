fn main() {
    // Ensure Homebrew's pkg-config path is visible to CMake on macOS.
    let homebrew_pkgconfig = "/opt/homebrew/lib/pkgconfig";
    let old_path = std::env::var("PKG_CONFIG_PATH").unwrap_or_default();
    let new_path = if old_path.is_empty() {
        homebrew_pkgconfig.to_string()
    } else {
        format!("{}:{}", homebrew_pkgconfig, old_path)
    };
    std::env::set_var("PKG_CONFIG_PATH", &new_path);

    let dst = cmake::Config::new(".")
        .env("PKG_CONFIG_PATH", &new_path)
        .define("CMAKE_PREFIX_PATH", "/opt/homebrew")
        .build_target("ref2")
        .build();

    println!("cargo:rustc-link-search=native={}/build", dst.display());
    println!("cargo:rustc-link-lib=static=ref2");
    println!("cargo:rustc-link-lib=pcap");

    // Re-run if any C source changes
    println!("cargo:rerun-if-changed=c/");
    println!("cargo:rerun-if-changed=CMakeLists.txt");
}
