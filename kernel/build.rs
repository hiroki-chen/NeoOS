fn main() {
    println!("cargo:rerun-if-env-changed=OS_LOG_LEVEL");
    println!("cargo:rerun-if-env-changed=RUST_BACKTRACE");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=x86_64.json");
}
