fn main() {
    println!("cargo:rerun-if-env-changed=LOG");
    println!("cargo:rerun-if-changed=build.rs");
}
