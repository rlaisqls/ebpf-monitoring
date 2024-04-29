use libbpf_cargo::SkeletonBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    ["profile", "pyperf"]
        .iter()
        .for_each(|name| {
            SkeletonBuilder::new()
                .source(format!("src/ebpf/bpf/{}.bpf.c", name))
                .clang_args("-I src/ebpf/bpf/vmlinux/aarch64 -I src/ebpf/bpf/libbpf -I src/ebpf/bpf")
                .build_and_generate(format!("src/ebpf/bpf/{}.skel.rs", name))
                .unwrap();
    });

    ["profile"]
        .iter()
        .for_each(|name| {
            tonic_build::configure()
                .build_server(false)
                .out_dir(format!("src/gen/{}", name))
                .compile(
                    &[format!("proto/{}/v1/{}.proto", name, name)],
                    &[format!("proto/{}/v1", name)],
                ).unwrap();
            tonic_build::compile_protos(format!("proto/{}/v1/{}.proto", name, name)).unwrap();
        });

    Ok(())
}