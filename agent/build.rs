
fn main() -> Result<(), Box<dyn std::error::Error>> {

    ["push", "profile"]
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

    Ok(())
}