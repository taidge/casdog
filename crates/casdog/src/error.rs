use salvo::oapi::{self, ToSchema};
use salvo::prelude::*;
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Authorization failed: {0}")]
    Authorization(String),

    #[error("Invalid input: {0}")]
    Validation(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Resource already exists: {0}")]
    Conflict(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Casbin error: {0}")]
    Casbin(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    pub code: u16,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ErrorResponse {
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

#[async_trait]
impl Writer for AppError {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        let (status, error_response) = match &self {
            AppError::Database(e) => {
                tracing::error!("Database error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new(500, "Database error"),
                )
            }
            AppError::Authentication(msg) => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new(401, "Authentication failed").with_details(msg.clone()),
            ),
            AppError::Authorization(msg) => (
                StatusCode::FORBIDDEN,
                ErrorResponse::new(403, "Authorization failed").with_details(msg.clone()),
            ),
            AppError::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new(400, "Validation error").with_details(msg.clone()),
            ),
            AppError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                ErrorResponse::new(404, "Not found").with_details(msg.clone()),
            ),
            AppError::Conflict(msg) => (
                StatusCode::CONFLICT,
                ErrorResponse::new(409, "Conflict").with_details(msg.clone()),
            ),
            AppError::Jwt(e) => {
                tracing::error!("JWT error: {:?}", e);
                (
                    StatusCode::UNAUTHORIZED,
                    ErrorResponse::new(401, "Invalid token"),
                )
            }
            AppError::Config(msg) => {
                tracing::error!("Config error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new(500, "Configuration error"),
                )
            }
            AppError::Casbin(msg) => {
                tracing::error!("Casbin error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new(500, "Authorization system error"),
                )
            }
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new(500, "Internal server error"),
                )
            }
        };

        res.status_code(status);
        res.render(Json(error_response));
    }
}

impl oapi::EndpointOutRegister for AppError {
    fn register(components: &mut oapi::Components, operation: &mut oapi::Operation) {
        operation.responses.insert(
            "400".to_string(),
            oapi::Response::new("Bad Request")
                .add_content("application/json", ErrorResponse::to_schema(components)),
        );
        operation.responses.insert(
            "401".to_string(),
            oapi::Response::new("Unauthorized")
                .add_content("application/json", ErrorResponse::to_schema(components)),
        );
        operation.responses.insert(
            "403".to_string(),
            oapi::Response::new("Forbidden")
                .add_content("application/json", ErrorResponse::to_schema(components)),
        );
        operation.responses.insert(
            "404".to_string(),
            oapi::Response::new("Not Found")
                .add_content("application/json", ErrorResponse::to_schema(components)),
        );
        operation.responses.insert(
            "500".to_string(),
            oapi::Response::new("Internal Server Error")
                .add_content("application/json", ErrorResponse::to_schema(components)),
        );
    }
}

pub type AppResult<T> = Result<T, AppError>;
