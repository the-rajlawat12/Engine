use tonic::{transport::Server, Request, Response, Status};

// use analyzer::analyzer_server::{Analyzer, AnalyzerServer};
use analyzer::{analyzer_server::Analyzer, AnalyzeRequest, AnalyzeResponse, Status as CAStatus};

use crate::try_analyze;

// #[derive(Default)]
// pub struct Analyzer {}

pub mod analyzer {
    tonic::include_proto!("engine");
}

#[derive(Default, Debug)]
pub struct AnalyzerService {}

#[tonic::async_trait]
impl Analyzer for AnalyzerService {
    async fn do_analyze(
        &self,
        request: Request<analyzer::AnalyzeRequest>,
    ) -> Result<Response<analyzer::AnalyzeResponse>, Status> {
        println!("Got a request: {:?}", request);

        let code = request.get_ref().code.clone();
        let fname = request.get_ref().name.clone();

        let r = try_analyze(code, fname);

        match r {
            Ok(x) => {
                let report_string = serde_json::to_string(&x);

                let response = analyzer::AnalyzeResponse {
                    status: i32::from(CAStatus::Ok),
                    report: report_string.unwrap_or_default(),
                    ir: "".to_string(), //result: "Hello, World!".into(),
                };
                return Ok(Response::new(response));
            }
            Err(x) => {
                let response = analyzer::AnalyzeResponse {
                    status: i32::from(CAStatus::Err),
                    report: x.to_string(),
                    ir: "".to_string(),
                };
                return Ok(Response::new(response));
            }
        }
        unreachable!("We never ever reach here!");
    }
}
