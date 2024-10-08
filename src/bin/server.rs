use engine::analyzer::{analyzer::analyzer_server::AnalyzerServer, AnalyzerService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse().unwrap();
    let analyzer = AnalyzerService::default();
    println!("AnalyzerServer listening on {}", addr);

    tonic::transport::Server::builder()
        .add_service(AnalyzerServer::new(analyzer))
        .serve(addr)
        .await
        .unwrap();

    Ok(())
}
