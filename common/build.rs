use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/profile.bpf.c";

fn main() -> Result<(), Box<dyn std::error::Error>> {

    tonic_build::configure()
        .build_server(false)
        .out_dir("src/api/push")
        .compile(
            &["proto/push/v1/push.proto"], &["proto/push/v1"]
        ).unwrap();
    tonic_build::compile_protos("proto/push/v1/push.proto").unwrap();


    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("profile.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            Path::new("../vmlinux").join(arch).as_os_str(),
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    Ok(())
}