fn main() {
    println!("cargo:rerun-if-env-changed=OS_LOG_LEVEL");
    println!("cargo:rerun-if-env-changed=RUST_BACKTRACE");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=x86_64.json");

    let metadata = rustc_version::version_meta().unwrap();
    let output_path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), "meta");
    let output_data = format!(
        "Rust Compiler version: {}\nLLVM version: {}",
        metadata.short_version_string,
        metadata.llvm_version.unwrap()
    );

    std::fs::write(output_path, output_data).unwrap();
}
