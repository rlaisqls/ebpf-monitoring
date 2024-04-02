use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/profile.bpf.c";

fn main() -> Result<(), Box<dyn std::error::Error>> {

    ["profile", "pyperf"]
        .iter()
        .for_each(|name| {
            SkeletonBuilder::new()
                .source(format!("src/bpf/{}.bpf.c", name))
                .clang_args("-I src/ebpf/bpf/vmlinux/aarch")
                .build_and_generate(format!("src/ebpf/bpf/.out/{}.skel.rs", name))
                .unwrap();
    });

    Ok(())
}