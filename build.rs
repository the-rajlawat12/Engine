fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tonic_build::compile_protos("proto/v1/model.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos: {:?}", e));
    Ok(())
}
