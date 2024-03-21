fn main() -> Result<(), Box<dyn std::error::Error>> {

    tonic_build::configure()
        .build_server(false)
        .out_dir("../src/api/push")
        .compile(
            &["../proto/push/v1/push.proto"], &["../proto/push/v1"]
        ).unwrap();
    tonic_build::compile_protos("../proto/push/v1/push.proto").unwrap();

    Ok(())
}