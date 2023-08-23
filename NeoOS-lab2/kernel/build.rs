fn main() {
    println!("cargo:rerun-if-env-changed=OS_LOG_LEVEL");
    println!("cargo:rerun-if-env-changed=RUST_BACKTRACE");
    println!("cargo:rerun-if-changed=build.rs");

    if cfg!(target_arch = "x86_64") {
        // Compile trampoline for APs.
        println!("cargo:rerun-if-changed=src/arch/x86_64/boot/ap_trampoline.S");

        let ret = std::process::Command::new("nasm")
            .arg("-f")
            .arg("bin")
            .arg("-o")
            .arg(format!("{}/ap_trampoline", env!("CARGO_MANIFEST_DIR")))
            .arg("src/arch/x86_64/boot/ap_trampoline.S")
            .status()
            .expect("build.rs: fatal error when building nasm!");

        if !ret.success() {
            panic!("build.rs: nasm returned {}", ret.code().unwrap());
        }
    }

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
