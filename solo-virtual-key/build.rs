use std::env;
use std::fs::copy;
use std::path::Path;
use std::process::Command;

pub fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");

    let output = Command::new("make")
        .current_dir("src/ext")
        .output()
        .expect("failed to execute 'make'");

    if !output.status.success() {
        panic!("make failed: {:?}", output);
    }

    let cwd = env::current_dir().unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let src = Path::new(&cwd).join("src/ext/main");
    let dst = Path::new(&out_dir).join("solokey");
    copy(&src, &dst).unwrap();
}
