fn main() {
    println!("cargo:rerun-if-env-changed=OS_LOG_LEVEL");
    println!("cargo:rerun-if-env-changed=RUST_BACKTRACE");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=x86_64.json");

    // Compile the assembly file
    let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap_or(".".to_string());
    let trap = format!("{}{}", base_path, "/src/arch/x86_64/interrupt/trap.S");
    let idt = format!(
        "{}{}",
        base_path, "/src/arch/x86_64/interrupt/idt_vectors.S"
    );
    println!("cargo:rerun-if-changed={}", trap);
    println!("cargo:rerun-if-changed={}", idt);
    cc::Build::new().file(trap).compile("trap");
    cc::Build::new().file(idt).compile("idt_vectors");

    // Tell Cargo to link the object file into the final executable
    println!("cargo:rustc-link-lib=static=trap");
    println!("cargo:rustc-link-lib=static=idt_vectors");
}
