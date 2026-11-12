//! OTLP/HTTP endpoints intentionally do not use browser authentication hoops.
//! Invalid exporter credentials must never fall through to a public IP rule.
use super::social_login::pg_pool;
use crate::{
    error::AppResult,
    hoops::authz::Principal,
    services::telemetry_service::{self as service, IngestError, MAX_BODY, ReceiverInput, Signal},
};
use prost::Message;
use salvo::prelude::*;
use serde_json::Value;

#[handler]
pub async fn list_receivers(depot: &mut Depot) -> AppResult<Json<Value>> {
    Ok(Json(
        service::list(&pg_pool(depot)?, &Principal::from_depot(depot)?).await?,
    ))
}
#[handler]
pub async fn save_receiver(req: &mut Request, depot: &mut Depot) -> AppResult<Json<Value>> {
    let input = req
        .parse_json::<ReceiverInput>()
        .await
        .map_err(|_| crate::error::AppError::Validation("Invalid receiver configuration".into()))?;
    Ok(Json(
        service::save(&pg_pool(depot)?, &Principal::from_depot(depot)?, input).await?,
    ))
}
#[handler]
pub async fn delete_receiver(req: &mut Request, depot: &mut Depot) -> AppResult<Json<Value>> {
    let id = req
        .param::<String>("id")
        .ok_or_else(|| crate::error::AppError::Validation("Receiver ID required".into()))?;
    Ok(Json(
        service::disable(&pg_pool(depot)?, &Principal::from_depot(depot)?, &id).await?,
    ))
}
// google.rpc.Status wire schema (details omitted). OTLP errors are protobuf,
// including authentication, parse and persistence failures.
#[derive(Clone, PartialEq, prost::Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
}
fn reply(res: &mut Response, result: Result<(), IngestError>) {
    res.headers_mut()
        .insert("content-type", "application/x-protobuf".parse().unwrap());
    match result {
        Ok(()) => {
            res.status_code(StatusCode::OK);
            res.body(Vec::<u8>::new());
        }
        Err(error) => {
            res.status_code(
                StatusCode::from_u16(error.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            );
            if error.status == 429 || error.status == 503 {
                res.headers_mut()
                    .insert("retry-after", "60".parse().unwrap());
            }
            let code = match error.status {
                400 | 413 | 415 => 3,
                401 => 16,
                403 => 7,
                429 => 8,
                _ => 14,
            };
            res.body(
                RpcStatus {
                    code,
                    message: error.message.into(),
                }
                .encode_to_vec(),
            );
        }
    }
}
async fn export(req: &mut Request, depot: &mut Depot, res: &mut Response, signal: Signal) {
    let result = async {
        let pool =
            pg_pool(depot).map_err(|_| IngestError::new(503, "Telemetry storage unavailable"))?;
        let content = req.header::<String>("content-type").unwrap_or_default();
        if !content
            .split(';')
            .next()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/x-protobuf"))
        {
            return Err(IngestError::new(415, "OTLP protobuf content type required"));
        }
        // Header ambiguity is never resolved by silently picking a credential.
        if req.headers().get_all("authorization").iter().count() > 1
            || req.headers().get_all("content-encoding").iter().count() > 1
        {
            return Err(IngestError::new(400, "Ambiguous OTLP headers"));
        }
        let authorization = match req.headers().get("authorization") {
            Some(v) => Some(
                v.to_str()
                    .map_err(|_| IngestError::new(401, "Exporter authentication required"))?
                    .to_owned(),
            ),
            None => None,
        };
        let encoding = match req.headers().get("content-encoding") {
            Some(v) => Some(
                v.to_str()
                    .map_err(|_| IngestError::new(415, "Unsupported OTLP content encoding"))?
                    .to_owned(),
            ),
            None => None,
        };
        let agent = req.header::<String>("user-agent").unwrap_or_default();
        let peer = req.remote_addr().ip(); // Never trust client supplied Forwarded/XFF.
        let body = req
            .payload_with_max_size(MAX_BODY)
            .await
            .map_err(|_| IngestError::new(413, "OTLP body unavailable or too large"))?;
        service::ingest(
            &pool,
            signal,
            authorization.as_deref(),
            peer,
            &agent,
            body,
            encoding.as_deref(),
        )
        .await
    }
    .await;
    reply(res, result);
}
#[handler]
pub async fn traces(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    export(req, depot, res, Signal::Traces).await
}
#[handler]
pub async fn metrics(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    export(req, depot, res, Signal::Metrics).await
}
#[handler]
pub async fn logs(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    export(req, depot, res, Signal::Logs).await
}
