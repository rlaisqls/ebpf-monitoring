use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/profile.bpf.c";

fn main() -> Result<(), Box<dyn std::error::Error>> {

    ["push"]
        .iter()
        .for_each(|name| {
            tonic_build::configure()
                .build_server(false)
                .out_dir(format!("src/api/{}", name))
                .compile(
                    &[format!("proto/{}/v1/{}.proto", name, name)],
                    &[format!("proto/{}/v1", name)],
                ).unwrap();
            tonic_build::compile_protos(format!("proto/{}/v1/{}.proto", name, name)).unwrap();
        });

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